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
* MCP calls carrying a URL, SQL, shell or credential argument — belt and braces
  behind the closed tool schemas

Reads a PreToolUse payload on stdin, writes a hook JSON response on stdout.
Exit 0 always: a crashed hook must not become a silent bypass.
"""

from __future__ import annotations

import json
import re
import sys

# Substrings that suggest a production system. Deliberately broad — a false
# refusal costs one clarifying message, a false allow costs an incident.
PRODUCTION_MARKERS = (
    "prod", "production", "prd", "live", ".com", ".net", ".org", ".io",
    "customer", "payments", "billing",
)

# Hosts that are fine despite matching a marker above.
PRODUCTION_EXEMPT = (
    "localhost", "127.0.0.1", "::1", ".local", ".svc", ".internal", ".test",
    "example.com", "example.org", "vendor-collect.example", "partner-billing.example",
)

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

    for marker in PRODUCTION_MARKERS:
        if marker not in lowered:
            continue
        if any(ok in lowered for ok in PRODUCTION_EXEMPT):
            continue
        deny(
            f"This command mentions {marker!r}, which looks like a production "
            f"system. AgentSec targets staging only — `production` is not a valid "
            f"environment in the allowlist. If this host is genuinely a test "
            f"system, rename it or ask the user to confirm."
        )

    allow()


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
    elif tool.startswith("mcp__"):
        check_mcp(tool, tool_input)

    allow()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never let a hook bug turn into an unnoticed bypass or a wedged session.
        allow()
