#!/usr/bin/env python3
"""PreToolUse hook: deterministic guard rails for the AgentSec workbench.

Hooks run as code, not as instructions, so these constraints hold regardless of
what the model has read — including a poisoned document it just retrieved as part
of a test. That property is the entire reason this file exists rather than another
paragraph in the skill.

Refuses:

* any Bash command mentioning a production-looking host
* `agentsec run` from Bash (use the MCP tool, so the run is audited under an actor)
* writes to policy/ or the fixture corpus (allowlist and recorded evidence are
  code-review artefacts, not agent output)
* AgentSec MCP calls carrying a URL, SQL, shell or credential argument — belt and
  braces behind the closed tool schemas

Reads a PreToolUse payload on stdin, writes a hook JSON response on stdout.
Exit 0 always: a crashed hook must not become a silent bypass.
"""

from __future__ import annotations

import json
import re
import sys

# Substrings that suggest a production system, matched against *host-shaped tokens*
# rather than the raw command. Deliberately broad — a false refusal costs one
# clarifying message, a false allow costs an incident — but scanning the whole
# command string made it broad in the wrong direction: `grep "Live Artifact" docs/`
# and a `Co-Authored-By: … <noreply@anthropic.com>` commit trailer both tripped it,
# while `curl https://prod.customer.com --proxy localhost` passed, because one
# `localhost` anywhere exempted every marker in the line.
PRODUCTION_MARKERS = (
    "prod", "production", "prd", "live", ".com", ".net", ".org", ".io",
    "customer", "payments", "billing",
)

# Hosts that are fine despite matching a marker above. Matched per token, so an
# exempt host no longer launders a production host sharing the same command.
PRODUCTION_EXEMPT = (
    "localhost", "127.0.0.1", "::1", ".local", ".svc", ".internal", ".test",
    "example.com", "example.org", "example.net", "vendor-collect.example",
    "partner-billing.example",
)

# A URL, or a bare host:port / dotted hostname. Anchored on characters that cannot
# appear mid-word, so prose and file paths are not mistaken for endpoints.
HOST_TOKEN = re.compile(
    r"""(?:
        [a-z][a-z0-9+.-]*://(?P<url_host>[^/\s:@'"]+(?::\d+)?)   # scheme://host
      | (?:^|[\s'"=@,(])(?P<bare>
            (?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}      # dotted hostname
            (?::\d+)?
        )(?=$|[\s'"/,;)])
    )""",
    re.VERBOSE,
)

# Redundant with the closed tool schemas and `tests/test_mcp_contract.py`, and kept
# as a third layer because the cost is one set intersection. It only makes sense
# against AgentSec's own surface: `query`, `headers` and `code` are ordinary
# arguments on other servers' tools, and the refusal text below tells the caller to
# pass a `target_id`, which only AgentSec has.
FORBIDDEN_MCP_ARGS = {
    "url", "endpoint", "base_url", "host", "command", "cmd", "shell", "sql",
    "query", "script", "code", "token", "password", "secret", "api_key",
    "credential", "headers",
}

PROTECTED_PATHS = (
    "/policy/targets.yaml",
    "/policy/approvals.yaml",
    "/fixtures/",
)


def deny(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def allow() -> None:
    sys.exit(0)


def check_bash(command: str) -> None:
    lowered = command.lower()

    # `agentsec run` via Bash bypasses the gateway's audit actor and approval
    # check. The MCP tool exists precisely so runs are attributable.
    if re.search(r"\bagentsec\s+run\b", lowered):
        deny(
            "Start runs through the agentsec_start_run MCP tool, not Bash, so the "
            "run is recorded against an actor and the approval check applies. "
            "`agentsec preview` and the read-only subcommands are fine."
        )

    for host in _hosts(lowered):
        # Scoped to this host, not the whole line: an exempt host elsewhere in the
        # command must not vouch for this one.
        if _is_exempt(host):
            continue
        for marker in PRODUCTION_MARKERS:
            if marker in host:
                deny(
                    f"This command contacts {host!r}, which contains {marker!r} and "
                    f"looks like a production system. AgentSec targets staging only — "
                    f"`production` is not a valid environment in the allowlist. If "
                    f"this host is genuinely a test system, rename it or ask the user "
                    f"to confirm."
                )

    allow()


def _is_exempt(host: str) -> bool:
    """Exact host, or a subdomain of an exempt domain — never a substring.

    Substring matching would exempt `example.com.evil.net`, which is the same
    laundering trick the per-token scoping above exists to stop.
    """
    for entry in PRODUCTION_EXEMPT:
        if entry.startswith("."):
            if host == entry.lstrip(".") or host.endswith(entry):
                return True
        elif host == entry or host.endswith("." + entry):
            return True
    return False


def _hosts(command: str) -> list[str]:
    """Host-shaped tokens in a command, without their port."""
    found = []
    for match in HOST_TOKEN.finditer(command):
        host = match.group("url_host") or match.group("bare")
        if host:
            found.append(host.rsplit(":", 1)[0] if ":" in host else host)
    return found


def check_write(path: str) -> None:
    normalised = path.replace("\\", "/")
    for protected in PROTECTED_PATHS:
        if protected in normalised:
            deny(
                f"{protected} is operator-owned. The target allowlist, the approval "
                f"ledger and the recorded fixture corpus are reviewed like firewall "
                f"rules — propose the change to the user instead of writing it."
            )
    allow()


def is_agentsec_tool(tool_name: str) -> bool:
    """Is ``mcp__<server>__<tool>`` AgentSec's own gateway?

    Matched on either half. The server name is whatever the operator called the
    entry in `.mcp.json`, so it can be renamed; the tool name is fixed by
    `mcp.contract.TOOLS` and is always `agentsec_*`. Requiring both would let a
    rename silently drop the layer.

    Requiring *neither* is what this replaces. `settings.json` matches the hook on
    `mcp__.*`, so every MCP server in the session reached the argument check —
    and `query`, `headers`, `code` and `url` are ordinary arguments elsewhere. A
    browser navigation was refused with a message telling it to pass a
    `target_id`, which is not a thing outside this repo. The check was written as
    a third layer behind AgentSec's closed schemas; it defends nothing on a
    server whose schemas it has never seen, and the false refusals are not free.

    `__` is the delimiter *and* a legal character in a server name, so the split
    is ambiguous: `mcp__purple__team__agentsec_start_run` is a server called
    `purple__team` under one reading and a tool called `team__agentsec_start_run`
    under another. Rather than guess which, every segment is tested. The
    ambiguity can only add matches, and a false positive here costs one refusal
    on a tool named after AgentSec, while a false negative silently removes the
    layer from the gateway it was written for.
    """
    segments = tool_name.split("__")
    if len(segments) < 3 or segments[0] != "mcp":
        return False
    return any(s == "agentsec" or s.startswith("agentsec_") for s in segments[1:])


def check_mcp(tool_name: str, tool_input: dict) -> None:
    offenders = sorted(set(tool_input) & FORBIDDEN_MCP_ARGS)
    if offenders:
        deny(
            f"{tool_name} was called with {offenders}, which AgentSec tools never "
            f"accept. Endpoints and credentials are resolved server-side from the "
            f"target allowlist; pass a target_id instead."
        )
    allow()


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        allow()
        return

    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        allow()
        return

    if tool == "Bash":
        check_bash(str(tool_input.get("command", "")))
    elif tool in {"Write", "Edit", "NotebookEdit"}:
        check_write(str(tool_input.get("file_path", "")))
    elif is_agentsec_tool(tool):
        check_mcp(tool, tool_input)

    allow()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never let a hook bug turn into an unnoticed bypass or a wedged session.
        allow()
