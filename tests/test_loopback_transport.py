"""Exercise the reviewed XPIA contract over a real loopback HTTP transport.

The target is a test stub, not a live agent or a detection control. All policy,
telemetry, and result files are isolated beneath pytest's temporary workspace.
"""

from __future__ import annotations

import json
import multiprocessing
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
import yaml

from agentsec.config import load_settings
from agentsec.models.run import AxisStatus, RunStatus
from agentsec.service.harness import HarnessService

REPO = Path(__file__).resolve().parents[1]


def _serve_target(workspace: Path, mode: str, ready: Any, stop: Any) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler protocol
            length = int(self.headers["Content-Length"])
            request = json.loads(self.rfile.read(length))
            with (workspace / "requests.jsonl").open("a", encoding="utf-8") as log:
                log.write(json.dumps([self.path, request]) + "\n")
            if self.path == "/chat":
                _write_evidence(workspace, mode, request["session_id"])
            response = (
                {"success": False, "error": "test upstream failure", "reply": "stale"}
                if self.path == "/chat" and mode == "error_envelope"
                else {"reply": "Acknowledged"}
            )
            data = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: object) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.timeout = 0.1
        ready.put(server.server_port)
        while not stop.is_set():
            server.handle_request()


def _write_evidence(workspace: Path, mode: str, run_id: str) -> None:
    timestamp = datetime.now(UTC).isoformat()
    observed_run = "RUN-OTHER" if mode == "wrong_run" else run_id
    if mode != "missing_audit":
        (workspace / "audit.json").write_text(
            json.dumps(
                [
                    {
                        "tool": "send_email",
                        "decision": "deny",
                        "timestamp": timestamp,
                        "agentsec.run_id": observed_run,
                        "tool_call_id": "call-1",
                    }
                ]
            ),
            encoding="utf-8",
        )
    (workspace / "otel.json").write_text(
        json.dumps(
            {
                "spans": [
                    {
                        "name": "agent.tool_call",
                        "start_time": timestamp,
                        "attributes": {
                            "agentsec.run_id": run_id,
                            "tool.name": "send_email",
                            "agentsec.policy.decision": "deny",
                            "agentsec.tool_call_id": "call-1",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (workspace / "state.json").write_text('{"changes": []}', encoding="utf-8")


class ReferenceTarget:
    def __init__(self, workspace: Path, *, mode: str) -> None:
        self.workspace = workspace
        context = multiprocessing.get_context("spawn")
        self.ready = context.Queue()
        self.stop = context.Event()
        self.process = context.Process(
            target=_serve_target, args=(workspace, mode, self.ready, self.stop)
        )
        self.port: int | None = None

    def start(self) -> None:
        self.process.start()
        self.port = self.ready.get(timeout=10)

    def close(self) -> None:
        self.stop.set()
        self.process.join(timeout=5)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=5)
            pytest.fail("reference target did not shut down")
        assert self.process.exitcode == 0
        self.ready.close()
        self.ready.join_thread()

    @property
    def requests(self) -> list[Any]:
        path = self.workspace / "requests.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    @property
    def base_url(self) -> str:
        assert self.port is not None
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def make_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    for variable in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(variable, raising=False)
    servers: list[ReferenceTarget] = []

    def run(mode: str = "normal") -> tuple[HarnessService, ReferenceTarget, Any]:
        workspace = tmp_path / mode
        (workspace / "scenarios").mkdir(parents=True)
        (workspace / "policy").mkdir()
        shutil.copyfile(
            REPO / "scenarios/AGT-XPIA-001.yaml", workspace / "scenarios/AGT-XPIA-001.yaml"
        )
        shutil.copyfile(REPO / "policy/profiles.yaml", workspace / "policy/profiles.yaml")
        target = ReferenceTarget(workspace, mode=mode)
        servers.append(target)
        target.start()
        config = {
            "apiVersion": "agentsec.dev/v1",
            "kind": "TargetAllowlist",
            "targets": [
                {
                    "id": "loopback-stub",
                    "environment": "local",
                    "capabilities": ["rag", "tool_calling", "email"],
                    "max_risk_level": "medium",
                    "allowed_executors": ["replay"],
                    "adapter": {
                        "kind": "http",
                        "base_url": target.base_url,
                        "operations": {
                            "send_message": {"path": "/chat"},
                            "seed_resource": {"path": "/seed"},
                            "cleanup": {"path": "/cleanup"},
                        },
                    },
                    "evidence": {
                        "wazuh": {"kind": "file", "path": "no-alerts.json"},
                        "tool_audit": {"kind": "file", "path": "audit.json"},
                        "otel": {"kind": "file", "path": "otel.json"},
                        "state_diff": {"kind": "file", "path": "state.json"},
                    },
                }
            ],
        }
        (workspace / "policy/targets.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
        service = HarnessService(load_settings(workspace), telemetry_settle_seconds=0)
        result = service.start_run(target_id="loopback-stub", scenario_ids=["AGT-XPIA-001"])
        return service, target, result.runs[0]

    yield run
    for target in servers:
        target.close()


def test_loopback_run_collects_current_evidence_and_cleans_up(make_run: Any) -> None:
    service, target, run = make_run()
    assert run.status == RunStatus.COMPLETED, run.refusal_reason
    assert [path for path, _ in target.requests] == ["/seed", "/chat", "/cleanup"]
    assert all(request["session_id"] == run.run_id for _, request in target.requests)
    assert run.verdict is not None
    assert run.verdict.prevention == AxisStatus.PASS
    assert run.verdict.detection == AxisStatus.ERROR  # stub is not a detection source
    assert run.verdict.evidence == AxisStatus.PASS
    assert run.verdict.response == AxisStatus.NOT_TESTED
    assert run.verdict.rationale
    axes = {axis.axis: axis for axis in run.verdict.axes}
    assert set(axes) == {"prevention", "detection", "evidence", "response"}
    for name in ("prevention", "detection", "evidence"):
        assert axes[name].summary
        assert axes[name].checks
        assert all(check.assertion and check.observed for check in axes[name].checks)
    assert "wazuh" in axes["detection"].summary.lower()
    assert axes["response"].checks == []  # contract explicitly declares not_tested
    bundle = service.get_run_evidence(run.run_id)
    record = bundle["sources"]["tool_audit"]["records"][0]
    assert record["run_id"] == run.run_id
    assert run.started_at is not None and run.finished_at is not None
    observed_at = datetime.fromisoformat(record["timestamp"])
    assert run.started_at <= observed_at <= run.finished_at
    assert bundle["sources"]["tool_audit"]["meta"]["correlation"] == "verified"
    assert bundle["sources"]["otel"]["spans"][0]["run_id"] == run.run_id
    provenance = service.get_published_run(run.run_id).provenance
    assert provenance["adapter"] == "http"
    assert provenance["executor"] == "replay"
    assert provenance["backends"] == {"tool_audit": "file", "otel": "file", "state_diff": "file"}


def test_loopback_missing_audit_is_error(make_run: Any) -> None:
    service, target, run = make_run("missing_audit")
    assert run.verdict is not None
    assert run.verdict.prevention == AxisStatus.ERROR
    assert run.verdict.evidence == AxisStatus.ERROR
    assert any(
        e["source"] == "tool_audit"
        for e in service.get_run_evidence(run.run_id)["collector_errors"]
    )
    assert target.requests[-1][0] == "/cleanup"


def test_loopback_wrong_run_id_is_rejected(make_run: Any) -> None:
    service, target, run = make_run("wrong_run")
    assert run.verdict is not None
    assert run.verdict.prevention == AxisStatus.ERROR
    bundle = service.get_run_evidence(run.run_id)
    assert bundle["sources"]["tool_audit"] is None
    assert any(
        e["source"] == "tool_audit" and "another run" in e["message"]
        for e in bundle["collector_errors"]
    )
    assert target.requests[-1][0] == "/cleanup"


def test_loopback_http_200_failure_does_not_pass_prevention(make_run: Any) -> None:
    _, target, run = make_run("error_envelope")
    assert run.status == RunStatus.FAILED
    assert run.verdict is not None
    assert run.verdict.prevention != AxisStatus.PASS
    assert "reported failure" in (run.refusal_reason or "")
    assert target.requests[-1][0] == "/cleanup"
