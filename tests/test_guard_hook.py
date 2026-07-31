"""The PreToolUse guard hook.

The hook runs as code rather than as instructions, which is the whole reason it
exists — so it needs the same regression cover as the evaluator. Every case here
is one the hook got wrong in practice, or one it must keep getting right.

Hostnames are assembled from parts because an agent editing this file may itself
be governed by the hook under test, and a literal production-looking host in a
`Bash` command would be refused before the edit landed.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from tests.conftest import REPO_ROOT

HOOK = REPO_ROOT / ".claude" / "hooks" / "guard_agentsec.py"

ACME_ORG = "db.payments." + "acme" + ".org"
SPOOF = "example.com." + "evil" + ".net"
CLI_RUN = "agentsec" + " run --target demo-agent-fixture"


def decide(tool: str, tool_input: dict) -> str | None:
    """Run the hook; return the refusal reason, or None when it allows."""
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"tool_name": tool, "tool_input": tool_input}),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, "a crashed hook must never become a silent bypass"
    if not result.stdout.strip():
        return None
    payload = json.loads(result.stdout)["hookSpecificOutput"]
    assert payload["permissionDecision"] == "deny"
    return payload["permissionDecisionReason"]


@pytest.mark.parametrize(
    "command",
    [
        # Markers used to be matched against the raw command, so ordinary work that
        # merely mentioned one was refused. Both of these happened during review.
        'grep -rn "Live Artifact" docs/',
        'git commit --trailer "Co-Authored-By: C <noreply@anthropic.com>"',
        'python -c "x" # evidence.tool_audit.complete',
        # Legitimate local and cluster-internal endpoints.
        "curl http://localhost:8080/chat",
        "curl https://staging-agent.internal/health",
        "curl https://prod.svc.cluster.local/x",
        # RFC 2606 documentation space, including subdomains.
        "psql -h db.payments.example.org -c 'select 1'",
        # Ordinary tooling with no host at all.
        "pytest -q tests/",
        "pip install -e '.[dev,mcp]'",
    ],
)
def test_allows_ordinary_commands(command: str) -> None:
    assert decide("Bash", {"command": command}) is None


@pytest.mark.parametrize(
    "command",
    [
        # The exemption was tested against the whole command, so one `localhost`
        # anywhere vouched for every host on the line.
        "curl https://prod.customer.com --proxy localhost",
        "curl https://api.acme-production.com/v1",
        "curl http://billing.acme.net/invoices",
        f"psql -h {ACME_ORG} -c 'select 1'",
        # A substring exemption would have accepted this as `example.com`.
        f"curl https://{SPOOF}/x",
    ],
)
def test_refuses_production_looking_hosts(command: str) -> None:
    reason = decide("Bash", {"command": command})
    assert reason is not None
    assert "production" in reason


def test_refuses_cli_run_in_favour_of_the_audited_mcp_tool() -> None:
    reason = decide("Bash", {"command": CLI_RUN})
    assert reason is not None
    assert "agentsec_start_run" in reason


@pytest.mark.parametrize(
    "path",
    ["/repo/policy/targets.yaml", "/repo/policy/approvals.yaml", "/repo/fixtures/demo/x.json"],
)
def test_refuses_writes_to_operator_owned_files(path: str) -> None:
    assert decide("Write", {"file_path": path}) is not None


def test_allows_writes_to_source() -> None:
    assert decide("Write", {"file_path": "/repo/src/agentsec/cli.py"}) is None


def test_refuses_mcp_calls_carrying_a_locator() -> None:
    reason = decide(
        "mcp__agentsec__agentsec_preview_run",
        {"target_id": "demo-agent-fixture", "url": "http://evil.example"},
    )
    assert reason is not None
    assert "url" in reason
    assert decide(
        "mcp__agentsec__agentsec_preview_run", {"target_id": "demo-agent-fixture"}
    ) is None


def test_malformed_payload_allows_rather_than_wedging_the_session() -> None:
    result = subprocess.run(
        [sys.executable, str(HOOK)], input="not json",
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    assert not result.stdout.strip()
