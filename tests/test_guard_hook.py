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
DEFAULT_CWD = "/repo"
INDETERMINATE_INPUT_REASON = (
    "AgentSec denied this request because its hook could not validate the "
    "PreToolUse input."
)


def run_hook(payload: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload),
        capture_output=True, text=True, check=False,
    )


def deny_payload(result: subprocess.CompletedProcess[str]) -> dict:
    assert result.returncode == 0
    assert result.stderr == ""
    output = json.loads(result.stdout)
    assert set(output) == {"hookSpecificOutput"}
    decision = output["hookSpecificOutput"]
    assert set(decision) == {
        "hookEventName", "permissionDecision", "permissionDecisionReason",
    }
    assert decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "deny"
    assert isinstance(decision["permissionDecisionReason"], str)
    return decision


def decide(tool: str, tool_input: dict, *, cwd: str | None = DEFAULT_CWD) -> str | None:
    """Run the hook; return the refusal reason, or None when it allows."""
    payload = {"tool_name": tool, "tool_input": tool_input}
    if cwd is not None:
        payload["cwd"] = cwd
    result = run_hook(payload)
    assert result.returncode == 0, "a crashed hook must never become a silent bypass"
    if not result.stdout.strip():
        return None
    return deny_payload(result)["permissionDecisionReason"]


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
    ("path", "cwd"),
    [
        ("/repo/policy/targets.yaml", DEFAULT_CWD),
        ("/repo/policy/approvals.yaml", DEFAULT_CWD),
        ("/repo/fixtures/demo/x.json", DEFAULT_CWD),
        ("policy/targets.yaml", DEFAULT_CWD),
        ("./policy/approvals.yaml", DEFAULT_CWD),
        ("src/../fixtures/demo/x.json", DEFAULT_CWD),
        ("../policy/targets.yaml", "/repo/src"),
        (r"policy\approvals.yaml", DEFAULT_CWD),
        (r"C:\repo\fixtures\demo\x.json", DEFAULT_CWD),
    ],
)
def test_refuses_writes_to_operator_owned_files(path: str, cwd: str) -> None:
    assert decide("Write", {"file_path": path}, cwd=cwd) is not None


def test_refuses_notebook_edits_using_the_documented_path_field() -> None:
    assert decide("NotebookEdit", {"notebook_path": "fixtures/demo/run.ipynb"}) is not None


def test_allows_notebook_edits_outside_the_protected_set() -> None:
    assert decide("NotebookEdit", {"notebook_path": "notebooks/report.ipynb"}) is None


def test_refuses_edit_of_a_protected_relative_path() -> None:
    assert decide("Edit", {"file_path": "policy/targets.yaml"}) is not None


@pytest.mark.parametrize(
    "path",
    [
        "/repo/src/agentsec/cli.py",
        "src/agentsec/cli.py",
        "policy/targets.yaml.bak",
        "test_fixtures/demo/x.json",
    ],
)
def test_allows_writes_outside_the_protected_set(path: str) -> None:
    assert decide("Write", {"file_path": path}) is None


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


@pytest.mark.parametrize(
    "tool",
    [
        "mcp__purple__agentsec_start_run",
        # `__` delimits the name and is legal inside a server name, so this is
        # either the server `purple__team` or the tool `team__agentsec_start_run`
        # depending on where the split falls. Under either reading it is the
        # AgentSec gateway, and the hook must not lose it to the ambiguity.
        "mcp__purple__team__agentsec_start_run",
        "mcp__agentsec__purple__agentsec_start_run",
    ],
)
def test_refuses_agentsec_tools_under_a_renamed_server(tool: str) -> None:
    """The `.mcp.json` key is the operator's to choose; the tool names are not."""
    assert decide(tool, {"target_id": "demo-agent-fixture", "sql": "select 1"}) is not None


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        # `settings.json` matches the hook on `mcp__.*`, so every server in the
        # session used to reach the AgentSec argument check. Each of these was
        # refused with a message telling it to pass a `target_id`.
        ("mcp__browser__navigate", {"url": "http://localhost:3000"}),
        ("mcp__notion__search", {"query": "purple run"}),
        ("mcp__fetch__get", {"url": "http://localhost:8080", "headers": {}}),
        ("mcp__sqlite_docs__lookup", {"sql": "select 1"}),
        # Testing every segment is what keeps the renamed-server case above from
        # slipping through; it must not turn into matching everything.
        ("mcp__notion__data__search", {"query": "purple run"}),
    ],
)
def test_leaves_other_mcp_servers_alone(tool: str, tool_input: dict) -> None:
    assert decide(tool, tool_input) is None


@pytest.mark.parametrize(
    "raw_input",
    [
        "not json",
        "null",
        "[]",
        # json.load raises RecursionError here, exercising the fail-closed outer
        # exception path in a subprocess rather than a same-process mock.
        "[" * 2000,
    ],
)
def test_malformed_json_or_envelope_is_denied_with_a_stable_schema(raw_input: str) -> None:
    result = subprocess.run(
        [sys.executable, str(HOOK)], input=raw_input,
        capture_output=True, text=True, check=False,
    )
    decision = deny_payload(result)
    assert decision["permissionDecisionReason"] == INDETERMINATE_INPUT_REASON


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"tool_name": 1, "tool_input": {}},
        {"tool_name": "Bash", "tool_input": None},
        {"tool_name": "Bash", "tool_input": []},
        {"tool_name": "Bash", "tool_input": {}, "cwd": DEFAULT_CWD},
        {"tool_name": "Bash", "tool_input": {"command": 1}, "cwd": DEFAULT_CWD},
        {"tool_name": "Write", "tool_input": {}, "cwd": DEFAULT_CWD},
        {"tool_name": "Edit", "tool_input": {"file_path": []}, "cwd": DEFAULT_CWD},
        {
            "tool_name": "NotebookEdit",
            "tool_input": {"file_path": "fixtures/x.ipynb"},
            "cwd": DEFAULT_CWD,
        },
        {"tool_name": "Write", "tool_input": {"file_path": "relative.py"}, "cwd": 3},
        {"tool_name": "Write", "tool_input": {"file_path": "relative.py"}, "cwd": "."},
    ],
)
def test_malformed_types_and_guarded_fields_are_denied(payload: object) -> None:
    decision = deny_payload(run_hook(payload))
    assert decision["permissionDecisionReason"] == INDETERMINATE_INPUT_REASON


def test_relative_write_without_a_declared_base_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    reason = decide("Write", {"file_path": "src/agentsec/cli.py"}, cwd=None)
    assert reason is not None
    assert "could not validate" in reason


def test_relative_write_with_a_relative_project_root_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", ".")
    reason = decide("Write", {"file_path": "src/agentsec/cli.py"}, cwd=None)
    assert reason is not None
    assert "could not validate" in reason
