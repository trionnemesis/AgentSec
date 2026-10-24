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
Malformed or indeterminate requests, and unexpected validation errors, receive a
fixed deny response rather than becoming a silent bypass.
"""

from __future__ import annotations

import json
import os
import posixpath
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

WINDOWS_SHORT_POLICY_ALIASES = (
    (re.compile(r"/policy/target~[1-9][0-9]*\.yam$"), "/policy/targets.yaml"),
    (re.compile(r"/policy/approv~[1-9][0-9]*\.yam$"), "/policy/approvals.yaml"),
)

INDETERMINATE_INPUT_REASON = (
    "AgentSec denied this request because its hook could not validate the "
    "PreToolUse input."
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


def _is_absolute_path(path: str) -> bool:
    normalised = path.replace("\\", "/")
    return normalised.startswith("/") or bool(re.match(r"^[A-Za-z]:/", normalised))


def _is_drive_relative_path(path: str) -> bool:
    """A Win32 ``C:foo`` path whose per-drive base the hook cannot know."""
    return bool(re.match(r"^[A-Za-z]:(?:$|[^/])", path.replace("\\", "/")))


def _uses_windows_paths(path: str, base: str | None) -> bool:
    """Whether the target is interpreted with Windows filename semantics."""
    return sys.platform == "win32" or any(
        candidate is not None
        and (
            "\\" in candidate
            or candidate.startswith("//")
            or bool(re.match(r"^[A-Za-z]:/", candidate))
        )
        for candidate in (path, base)
    )


def _windows_alias_key(path: str) -> str:
    """Collapse Win32 aliases relevant to protected-path matching.

    The ordinary Win32 namespace ignores trailing spaces and dots in components.
    A colon after a component selects an NTFS stream; even a named stream remains
    attached to the operator-owned file, while ``::$DATA`` names its default data
    stream. Drive-letter colons are structural and are therefore retained.
    """
    components = []
    for index, component in enumerate(path.split("/")):
        is_drive = index == 0 and bool(re.fullmatch(r"[A-Za-z]:", component))
        if not is_drive:
            original = component
            component = component.split(":", 1)[0].rstrip(" .")
            if original and not component:
                deny(INDETERMINATE_INPUT_REASON)
        components.append(component)
    return "/".join(components)


def _normalise_path(path: str, cwd: str | None) -> tuple[str, bool, bool]:
    """Lexically resolve a tool path without touching the filesystem.

    Claude Code declares the current working directory in the hook envelope. The
    project-root environment variable is a fallback for older/direct invocations.
    POSIX normalisation after separator conversion gives Windows spellings and dot
    segments the same component boundaries without following symlinks.
    """
    normalised = path.replace("\\", "/")
    if _is_drive_relative_path(normalised):
        deny(INDETERMINATE_INPUT_REASON)
    base = cwd or os.environ.get("CLAUDE_PROJECT_DIR")
    windows_paths = _uses_windows_paths(path, base)
    case_insensitive = windows_paths or sys.platform == "darwin"
    if not _is_absolute_path(normalised):
        if not base or not _is_absolute_path(base):
            deny(INDETERMINATE_INPUT_REASON)
        normalised = posixpath.join(base.replace("\\", "/"), normalised)
    return posixpath.normpath(normalised), case_insensitive, windows_paths


def check_write(path: str, cwd: str | None) -> None:
    normalised, case_insensitive, windows_paths = _normalise_path(path, cwd)
    if windows_paths:
        # Alias collapse can turn `. ` and `.. ` into live dot segments, so run
        # lexical traversal normalisation again after applying Win32 semantics.
        normalised = posixpath.normpath(_windows_alias_key(normalised))
    match_path = normalised.casefold() if case_insensitive else normalised
    for protected in PROTECTED_PATHS:
        is_match = (
            protected in match_path
            if protected.endswith("/")
            else match_path.endswith(protected)
        )
        if is_match:
            deny(
                f"{protected} is operator-owned. The target allowlist, the approval "
                f"ledger and the recorded fixture corpus are reviewed like firewall "
                f"rules — propose the change to the user instead of writing it."
            )
    if windows_paths:
        for alias, protected in WINDOWS_SHORT_POLICY_ALIASES:
            if alias.search(match_path):
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


def _required_text(tool_input: dict, field: str) -> str:
    value = tool_input.get(field)
    if not isinstance(value, str) or not value.strip():
        deny(INDETERMINATE_INPUT_REASON)
    return value


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        deny(INDETERMINATE_INPUT_REASON)

    if not isinstance(payload, dict):
        deny(INDETERMINATE_INPUT_REASON)

    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    cwd = payload.get("cwd")
    if (
        not isinstance(tool, str)
        or not tool
        or not isinstance(tool_input, dict)
        or (
            cwd is not None
            and (
                not isinstance(cwd, str)
                or not cwd.strip()
                or not _is_absolute_path(cwd)
            )
        )
    ):
        deny(INDETERMINATE_INPUT_REASON)

    if tool == "Bash":
        check_bash(_required_text(tool_input, "command"))
    elif tool in {"Write", "Edit"}:
        check_write(_required_text(tool_input, "file_path"), cwd)
    elif tool == "NotebookEdit":
        check_write(_required_text(tool_input, "notebook_path"), cwd)
    elif is_agentsec_tool(tool):
        check_mcp(tool, tool_input)

    allow()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Do not expose exception text or let a hook bug become a silent bypass.
        deny(INDETERMINATE_INPUT_REASON)
