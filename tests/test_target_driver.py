"""Issue #48 target-driver capability and lifecycle boundaries."""

from __future__ import annotations

import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier, Lock

import pytest
import yaml
from jsonschema import Draft202012Validator

from agentsec.config import package_schema_dir
from agentsec.errors import ConfigError, ExecutionFailed
from agentsec.execution.adapters import FixtureAdapter, HttpAdapter
from agentsec.execution.base import ExecutionContext
from agentsec.execution.replay import ReplayExecutor
from agentsec.models.evidence import TranscriptTurn
from agentsec.models.run import RunStatus
from agentsec.models.scenario import Scenario
from agentsec.models.target import Adapter, Target, TargetAllowlist
from agentsec.policy.allowlist import load_allowlist
from agentsec.policy.approvals import ApprovalStore
from agentsec.scenario.validator import validate_scenario
from agentsec.service.harness import HarnessService


def _scenario(*steps: dict[str, object]) -> Scenario:
    return Scenario.model_validate(
        {
            "apiVersion": "agentsec.dev/v1",
            "kind": "Scenario",
            "metadata": {
                "id": "AGT-DRIVER-001",
                "title": "Target driver operation dispatch",
                "severity": "low",
            },
            "spec": {
                "target": {"environments": ["local"]},
                "risk": {"level": "low"},
                "attack": {"executor": "replay", "steps": list(steps)},
                "contract": {
                    "prevention": {
                        "must_not": [{"kind": "output_contains", "value": "blocked"}]
                    }
                },
            },
        }
    )


def _fixture_target(tmp_path: Path) -> Target:
    return Target.model_validate(
        {
            "id": "driver-fixture",
            "environment": "local",
            "capabilities": ["rag", "tool_calling", "memory"],
            "adapter": {"kind": "fixture", "fixture_dir": str(tmp_path)},
        }
    )


def _http_target(
    *,
    operations: dict[str, dict[str, str]],
    principals: dict[str, str] | None = None,
) -> Target:
    return Target.model_validate(
        {
            "id": "driver-http",
            "environment": "staging",
            "capabilities": ["rag", "tool_calling", "memory"],
            "adapter": {
                "kind": "http",
                "base_url": "http://127.0.0.1:8080",
                "operations": operations,
            },
            "principals": principals or {},
        }
    )


def _context(tmp_path: Path, scenario: Scenario, target: Target) -> ExecutionContext:
    return ExecutionContext(
        run_id="RUN-20260820-001",
        scenario=scenario,
        scenario_path=None,
        target=target,
        raw_dir=tmp_path / "raw",
        timeout_seconds=10,
    )


def test_fixture_dispatches_non_message_operations_without_reply_keys(tmp_path: Path) -> None:
    (tmp_path / "AGT-DRIVER-001.transcript.json").write_text(
        '{"replies": {"message": "fixture reply"}}', encoding="utf-8"
    )
    adapter = FixtureAdapter(_fixture_target(tmp_path), "AGT-DRIVER-001", tmp_path)

    seeded = adapter.send(
        operation="seed_memory",
        step_id="seed-with-no-reply",
        principal=None,
        session="RUN-1",
        payload="remember this",
    )
    replied = adapter.send(
        operation="send_message",
        step_id="message",
        principal=None,
        session="RUN-1",
        payload="hello",
    )

    assert seeded.role == "system"
    assert seeded.content == "seed_memory completed"
    assert replied.role == "assistant"
    assert replied.content == "fixture reply"
    assert adapter.supported_operations()[-1] == "cleanup"


def test_http_operation_map_is_fixed_and_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _http_target(
        operations={
            "send_message": {"path": "/v1/chat"},
            "seed_memory": {"path": "/_agentsec/seed/memory"},
            "cleanup": {"path": "/_agentsec/cleanup"},
        },
        principals={"tenant-a": "DRIVER_TOKEN"},
    )
    requests: list[tuple[str, dict[str, object]]] = []

    class Response:
        text = ""

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"reply": "ok"}

    class Client:
        def __init__(self, **_: object) -> None:
            pass

        def post(self, url: str, *, json: dict[str, object]) -> Response:
            requests.append((url, json))
            return Response()

        def close(self) -> None:
            return None

    import httpx

    monkeypatch.setattr(httpx, "Client", Client)
    adapter = HttpAdapter(target)
    adapter.send(
        operation="seed_memory",
        step_id="seed",
        principal=None,
        session="RUN-1",
        payload="remember",
    )
    adapter.send(
        operation="send_message",
        step_id="message",
        principal=None,
        session="RUN-1",
        payload="hello",
    )
    monkeypatch.setenv("DRIVER_TOKEN", "secret-token")
    adapter.send(
        operation="send_message",
        step_id="message-as-tenant",
        principal="tenant-a",
        session="RUN-1",
        payload="hello as tenant",
    )
    adapter.cleanup(target_id=target.id, session="RUN-1")

    assert [url for url, _ in requests] == [
        "http://127.0.0.1:8080/_agentsec/seed/memory",
        "http://127.0.0.1:8080/v1/chat",
        "http://127.0.0.1:8080/v1/chat",
        "http://127.0.0.1:8080/_agentsec/cleanup",
    ]
    assert requests[1][1] == {"message": "hello", "session_id": "RUN-1"}
    assert requests[2][1] == {
        "message": "hello as tenant",
        "session_id": "RUN-1",
        "principal_token": "secret-token",
    }
    assert requests[0][1] == {
        "operation": "seed_memory",
        "session_id": "RUN-1",
        "step_id": "seed",
        "payload": "remember",
    }
    assert target.redacted()["supported_operations"] == [
        "cleanup",
        "seed_memory",
        "send_message",
    ]
    assert "8080" not in str(target.redacted())


def test_http_send_message_200_error_envelope_is_an_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _http_target(operations={"send_message": {"path": "/v1/chat"}})

    class Response:
        text = ""
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"error": "upstream model timeout", "reply": None, "request_id": "abc"}

    class Client:
        def __init__(self, **_: object) -> None:
            pass

        def post(self, url: str, *, json: dict[str, object]) -> Response:
            return Response()

        def close(self) -> None:
            return None

    import httpx

    monkeypatch.setattr(httpx, "Client", Client)
    adapter = HttpAdapter(target)

    with pytest.raises(ExecutionFailed) as exc_info:
        adapter.send(
            operation="send_message",
            step_id="message",
            principal=None,
            session="RUN-1",
            payload="hello",
        )

    message = str(exc_info.value)
    assert "message" in message
    for key in ("error", "reply", "request_id"):
        assert key in message
    assert "upstream model timeout" not in message


def _http_adapter_with_response(
    monkeypatch: pytest.MonkeyPatch,
    target: Target,
    *,
    json_result: object = None,
    json_raises: bool = False,
    text: str = "",
    status_code: int = 200,
) -> HttpAdapter:
    """Build an HttpAdapter whose mocked client always returns one fixed body."""

    class Response:
        def __init__(self) -> None:
            self.text = text
            self.status_code = status_code

        def raise_for_status(self) -> None:
            return None

        def json(self) -> object:
            if json_raises:
                raise ValueError("not json")
            return json_result

    class Client:
        def __init__(self, **_: object) -> None:
            pass

        def post(self, url: str, *, json: dict[str, object]) -> Response:
            return Response()

        def close(self) -> None:
            return None

    import httpx

    monkeypatch.setattr(httpx, "Client", Client)
    return HttpAdapter(target)


def test_http_send_message_200_empty_object_is_an_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _http_target(operations={"send_message": {"path": "/v1/chat"}})
    adapter = _http_adapter_with_response(monkeypatch, target, json_result={})

    with pytest.raises(ExecutionFailed):
        adapter.send(
            operation="send_message",
            step_id="message",
            principal=None,
            session="RUN-1",
            payload="hello",
        )


def test_http_send_message_blank_reply_is_an_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _http_target(operations={"send_message": {"path": "/v1/chat"}})
    adapter = _http_adapter_with_response(monkeypatch, target, json_result={"reply": "   "})

    with pytest.raises(ExecutionFailed):
        adapter.send(
            operation="send_message",
            step_id="message",
            principal=None,
            session="RUN-1",
            payload="hello",
        )


def test_http_send_message_real_reply_is_an_assistant_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _http_target(operations={"send_message": {"path": "/v1/chat"}})
    adapter = _http_adapter_with_response(
        monkeypatch, target, json_result={"reply": "I can't help with that."}
    )

    turn = adapter.send(
        operation="send_message",
        step_id="message",
        principal=None,
        session="RUN-1",
        payload="hello",
    )

    assert turn.role == "assistant"
    assert turn.content == "I can't help with that."


def test_http_send_message_plain_text_body_is_an_assistant_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _http_target(operations={"send_message": {"path": "/v1/chat"}})
    adapter = _http_adapter_with_response(monkeypatch, target, json_raises=True, text="refused")

    turn = adapter.send(
        operation="send_message",
        step_id="message",
        principal=None,
        session="RUN-1",
        payload="hello",
    )

    assert turn.role == "assistant"
    assert turn.content == "refused"


def test_http_send_message_blank_plain_text_body_is_an_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _http_target(operations={"send_message": {"path": "/v1/chat"}})
    adapter = _http_adapter_with_response(monkeypatch, target, json_raises=True, text="   ")

    with pytest.raises(ExecutionFailed) as exc_info:
        adapter.send(
            operation="send_message",
            step_id="message",
            principal=None,
            session="RUN-1",
            payload="hello",
        )

    assert "non-JSON body, blank" in str(exc_info.value)


def test_http_non_message_operation_without_content_key_still_yields_a_system_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _http_target(operations={"seed_memory": {"path": "/_agentsec/seed/memory"}})
    adapter = _http_adapter_with_response(monkeypatch, target, json_result={"ok": True})

    turn = adapter.send(
        operation="seed_memory",
        step_id="seed",
        principal=None,
        session="RUN-1",
        payload="remember",
    )

    assert turn.role == "system"


@pytest.mark.parametrize(
    ("json_result", "type_name", "leak"),
    [
        (["marker-xyz"], "list", "marker-xyz"),
        (424242, "int", "424242"),
        ("refused-secret", "str", "refused-secret"),
    ],
)
def test_http_send_message_non_object_json_body_is_an_execution_failure(
    monkeypatch: pytest.MonkeyPatch, json_result: object, type_name: str, leak: str
) -> None:
    target = _http_target(operations={"send_message": {"path": "/v1/chat"}})
    adapter = _http_adapter_with_response(monkeypatch, target, json_result=json_result)

    with pytest.raises(ExecutionFailed) as exc_info:
        adapter.send(
            operation="send_message",
            step_id="message",
            principal=None,
            session="RUN-1",
            payload="hello",
        )

    message = str(exc_info.value)
    assert type_name in message
    assert leak not in message


@pytest.mark.parametrize(
    "json_result",
    [
        {"output": []},
        {"output": {}},
        {"output": 0},
        {"error": "upstream model timeout", "output": []},
    ],
)
def test_http_send_message_falsy_output_value_is_an_execution_failure(
    monkeypatch: pytest.MonkeyPatch, json_result: dict[str, object]
) -> None:
    """A falsy but non-None ``output`` is still no model output: the ``or``
    chain must not hand its last operand through as an assistant turn."""
    target = _http_target(operations={"send_message": {"path": "/v1/chat"}})
    adapter = _http_adapter_with_response(monkeypatch, target, json_result=json_result)

    with pytest.raises(ExecutionFailed) as exc_info:
        adapter.send(
            operation="send_message",
            step_id="message",
            principal=None,
            session="RUN-1",
            payload="hello",
        )

    message = str(exc_info.value)
    assert "JSON object keys:" in message
    assert "upstream model timeout" not in message


def test_http_error_status_does_not_echo_payload_or_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _http_target(
        operations={"send_message": {"path": "/v1/chat"}},
        principals={"tenant-a": "DRIVER_TOKEN"},
    )
    monkeypatch.setenv("DRIVER_TOKEN", "super-secret-token")

    import httpx

    class Response:
        def raise_for_status(self) -> None:
            request = httpx.Request("POST", "http://127.0.0.1:8080/v1/chat")
            response = httpx.Response(
                500, request=request, text="upstream leaked payload: super-secret-token"
            )
            response.raise_for_status()

        def json(self) -> dict[str, str]:
            raise AssertionError("json() must not be called when raise_for_status raises")

    class Client:
        def __init__(self, **_: object) -> None:
            pass

        def post(self, url: str, *, json: dict[str, object]) -> Response:
            return Response()

        def close(self) -> None:
            return None

    monkeypatch.setattr(httpx, "Client", Client)
    adapter = HttpAdapter(target)

    with pytest.raises(ExecutionFailed) as exc_info:
        adapter.send(
            operation="send_message",
            step_id="message",
            principal="tenant-a",
            session="RUN-1",
            payload="attack payload with secret marker",
        )

    message = str(exc_info.value)
    assert "message" in message
    assert "HTTPStatusError" in message
    assert "super-secret-token" not in message
    assert "attack payload with secret marker" not in message


@pytest.mark.parametrize(
    "path",
    [
        "https://other.example/x",
        "//other.example/x",
        "/v1/chat?next=x",
        "/v1/chat#fragment",
        "/v1/../x",
        "v1/../../x",
        "/v1\\chat",
        "/v1/\x00chat",
        "/white space",
        "/測試",
        "/v1/%2e%2e/x",
        "/v1/%252e%252e/x",
    ],
)
@pytest.mark.parametrize("field", ["operation", "chat"])
def test_http_paths_reject_locator_shapes_and_encodings(path: str, field: str) -> None:
    with pytest.raises(ValueError, match="safe relative path"):
        if field == "operation":
            _http_target(operations={"seed_memory": {"path": path}})
        else:
            Target.model_validate(
                {
                    "id": "driver-http",
                    "environment": "staging",
                    "adapter": {
                        "kind": "http",
                        "base_url": "http://127.0.0.1:8080",
                        "chat_path": path,
                    },
                }
            )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/safe", True),
        ("/safe/", True),
        ("safe/path", True),
        ("https://other.example/x", False),
        ("//other.example/x", False),
        ("/v1/chat?next=x", False),
        ("/v1/chat#fragment", False),
        ("/v1\\chat", False),
        ("/v1/%2e%2e/x", False),
        ("/v1/%252e%252e/x", False),
        ("/white space", False),
        ("/測試", False),
        ("/safe\n", False),
        ("/safe\r", False),
        ("/safe\x00", False),
        ("a//b", False),
        ("/./x", False),
        ("/", False),
        ("scheme:value", False),
        ("https:/evil", False),
        ("http:evil", False),
        ("/x//y", False),
        ("/x//", False),
    ],
)
def test_model_and_schema_safe_path_corpus_is_identical(path: str, expected: bool) -> None:
    schema = json.loads(
        (package_schema_dir() / "target.schema.json").read_text(encoding="utf-8")
    )
    schema_accepts = Draft202012Validator(schema["$defs"]["safeRelativePath"]).is_valid(path)
    try:
        Adapter.model_validate(
            {
                "kind": "http",
                "base_url": "http://127.0.0.1:8080",
                "chat_path": path,
            }
        )
    except ValueError:
        model_accepts = False
    else:
        model_accepts = True

    assert schema_accepts is expected
    assert model_accepts is expected


def test_non_message_http_operation_requires_a_fixed_endpoint() -> None:
    with pytest.raises(ValueError):
        _http_target(operations={"seed_memory": {}})


def test_target_validation_requires_live_cleanup_capability() -> None:
    scenario = _scenario({"id": "message", "kind": "agent_message", "payload": "hello"})
    target = _http_target(operations={"send_message": {"path": "/v1/chat"}}).model_copy(
        update={"environment": "local"}
    )

    report = validate_scenario(scenario, target=target)

    assert any(
        issue.code == "unsupported_driver_operation" and "cleanup" in issue.message
        for issue in report.errors
    )


def test_allowlist_path_errors_do_not_echo_endpoint_or_query_secret(tmp_path: Path) -> None:
    secret_path = "https://secret.example/api?token=TOPSECRET"
    path = tmp_path / "targets.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "agentsec.dev/v1",
                "kind": "TargetAllowlist",
                "targets": [
                    {
                        "id": "secret-path",
                        "environment": "local",
                        "adapter": {
                            "kind": "http",
                            "base_url": "http://127.0.0.1:8080",
                            "chat_path": secret_path,
                            "operations": {
                                "cleanup": {"path": secret_path},
                            },
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError) as exc:
        load_allowlist(path, check_network=False)

    assert secret_path not in exc.value.message
    assert "TOPSECRET" not in str(exc.value.details)
    assert "invalid fixed adapter path" in exc.value.message


def test_allowlist_yaml_error_does_not_echo_source_secret(tmp_path: Path) -> None:
    secret = "https://secret.example/api?token=TOPSECRET"
    path = tmp_path / "targets.yaml"
    path.write_text(
        "apiVersion: agentsec.dev/v1\n"
        "kind: TargetAllowlist\n"
        "targets:\n"
        "  - id: secret-path\n"
        "    environment: local\n"
        "    adapter:\n"
        "      kind: http\n"
        "      base_url: http://127.0.0.1:8080\n"
        "      chat_path: [https://secret.example/api?token=TOPSECRET\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError) as exc:
        load_allowlist(path, check_network=False)

    rendered = f"{exc.value.message} {exc.value.details} {exc.value}"
    assert secret not in rendered
    assert "TOPSECRET" not in rendered
    assert "invalid YAML" in exc.value.message
    assert "line" in exc.value.message and "column" in exc.value.message


def test_approval_lock_does_not_pollute_policy_directory(tmp_path: Path) -> None:
    policy_dir = tmp_path / "policy"
    ledger_path = policy_dir / "approvals.yaml"
    store = ApprovalStore(ledger_path)

    store.grant(scenario_id="*", target_id="*", approved_by="pytest")

    assert store._lock_path.parent != policy_dir  # noqa: SLF001
    assert not (policy_dir / ".approvals.yaml.lock").exists()


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership semantics")
def test_approval_lock_namespace_is_per_effective_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    store = ApprovalStore(tmp_path / "approvals.yaml")

    monkeypatch.setattr(os, "geteuid", lambda: 1001)
    first = store._lock_path  # noqa: SLF001
    monkeypatch.setattr(os, "geteuid", lambda: 1002)
    second = store._lock_path  # noqa: SLF001

    assert first.parent != second.parent
    assert first.parent.name.endswith("-1001")
    assert second.parent.name.endswith("-1002")


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership semantics")
def test_approval_lock_rejects_symlink_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    store = ApprovalStore(tmp_path / "approvals.yaml")
    root = store._lock_path.parent  # noqa: SLF001
    real_root = tmp_path / "real-lock-root"
    real_root.mkdir()
    root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(ConfigError, match="approval lock root"):
        store.grant(scenario_id="*", target_id="*", approved_by="pytest")


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership semantics")
def test_approval_lock_rejects_unsafe_root_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    store = ApprovalStore(tmp_path / "approvals.yaml")
    root = store._lock_path.parent  # noqa: SLF001
    root.mkdir(mode=0o700)
    root.chmod(0o755)

    with pytest.raises(ConfigError, match="ownership or permissions"):
        store.grant(scenario_id="*", target_id="*", approved_by="pytest")


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership semantics")
def test_approval_lock_rejects_wrong_root_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    actual_uid = os.geteuid()
    fake_uid = actual_uid + 1
    monkeypatch.setattr(os, "geteuid", lambda: fake_uid)
    store = ApprovalStore(tmp_path / "approvals.yaml")
    root = store._lock_path.parent  # noqa: SLF001
    root.mkdir(mode=0o700)

    with pytest.raises(ConfigError, match="ownership or permissions"):
        store.grant(scenario_id="*", target_id="*", approved_by="pytest")


class _RecordingAdapter:
    def __init__(
        self,
        *,
        fail: str | None = None,
        cleanup_error: bool = False,
        close_error: bool = False,
    ) -> None:
        self.calls: list[str] = []
        self.fail = fail
        self.cleanup_error = cleanup_error
        self.close_error = close_error
        self.cleaned = False
        self.closed = False

    def supported_operations(self) -> list[str]:
        return [
            "seed_resource",
            "seed_memory",
            "inject_tool_response",
            "assume_identity",
            "send_message",
            "snapshot_state",
            "cleanup",
        ]

    def send(self, *, operation: str, step_id: str, principal: str | None,
             session: str, payload: str) -> TranscriptTurn:
        self.calls.append(operation)
        if operation == self.fail:
            raise ExecutionFailed(f"primary {operation} failure")
        return TranscriptTurn(role="assistant", content="ok", step_id=step_id)

    def cleanup(self, *, target_id: str, session: str) -> None:
        self.cleaned = True
        if self.cleanup_error:
            raise ExecutionFailed("cleanup endpoint failed")

    def close(self) -> None:
        self.closed = True
        if self.close_error:
            raise ExecutionFailed("client close endpoint failed")


def test_replay_dispatches_every_driver_operation_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _RecordingAdapter()
    monkeypatch.setattr("agentsec.execution.replay.build_adapter", lambda *args: adapter)
    scenario = _scenario(
        {"id": "resource", "kind": "seed_resource", "payload": "doc"},
        {"id": "memory", "kind": "seed_memory", "payload": "memory"},
        {"id": "tool", "kind": "tool_response_injection", "payload": "result"},
        {"id": "identity", "kind": "assume_identity", "as_principal": "tenant-a"},
        {"id": "message", "kind": "agent_message", "payload": "hello"},
        {"id": "snapshot", "kind": "snapshot_state"},
        {"id": "wait", "kind": "wait", "seconds": 0},
    )
    target = _fixture_target(tmp_path)

    result, _ = ReplayExecutor(tmp_path).execute(_context(tmp_path, scenario, target))

    assert result.ok
    assert adapter.calls == [
        "seed_resource",
        "seed_memory",
        "inject_tool_response",
        "assume_identity",
        "send_message",
        "snapshot_state",
    ]
    assert result.steps_completed == [
        "resource", "memory", "tool", "identity", "message", "snapshot", "wait"
    ]
    assert adapter.cleaned and adapter.closed


def test_replay_preserves_primary_error_and_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _RecordingAdapter(fail="send_message", cleanup_error=True)
    monkeypatch.setattr("agentsec.execution.replay.build_adapter", lambda *args: adapter)
    scenario = _scenario({"id": "message", "kind": "agent_message", "payload": "hello"})

    result, _ = ReplayExecutor(tmp_path).execute(
        _context(tmp_path, scenario, _fixture_target(tmp_path))
    )

    assert not result.ok
    assert result.error is not None
    assert "primary send_message failure" in result.error
    assert "cleanup endpoint failed" in result.error
    assert adapter.cleaned and adapter.closed


def test_replay_marks_only_successfully_dispatched_steps_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _RecordingAdapter(fail="send_message")
    monkeypatch.setattr("agentsec.execution.replay.build_adapter", lambda *args: adapter)
    scenario = _scenario(
        {"id": "resource", "kind": "seed_resource", "payload": "doc"},
        {"id": "message", "kind": "agent_message", "payload": "hello"},
    )

    result, _ = ReplayExecutor(tmp_path).execute(
        _context(tmp_path, scenario, _fixture_target(tmp_path))
    )

    assert not result.ok
    assert result.steps_completed == ["resource"]
    assert "message" not in result.steps_completed
    assert adapter.cleaned and adapter.closed


def test_replay_success_becomes_failure_when_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _RecordingAdapter(cleanup_error=True)
    monkeypatch.setattr("agentsec.execution.replay.build_adapter", lambda *args: adapter)
    scenario = _scenario({"id": "message", "kind": "agent_message", "payload": "hello"})

    result, _ = ReplayExecutor(tmp_path).execute(
        _context(tmp_path, scenario, _fixture_target(tmp_path))
    )

    assert not result.ok
    assert result.error is not None and "cleanup endpoint failed" in result.error
    assert result.steps_completed == ["message"]
    assert adapter.cleaned and adapter.closed


def test_replay_close_failure_fails_closed_after_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _RecordingAdapter(close_error=True)
    monkeypatch.setattr("agentsec.execution.replay.build_adapter", lambda *args: adapter)
    scenario = _scenario({"id": "message", "kind": "agent_message", "payload": "hello"})

    result, _ = ReplayExecutor(tmp_path).execute(
        _context(tmp_path, scenario, _fixture_target(tmp_path))
    )

    assert not result.ok
    assert result.error is not None and "client close endpoint failed" in result.error
    assert adapter.cleaned and adapter.closed


def test_start_run_refuses_whole_batch_before_adapter_when_operation_is_unsupported(
    service: HarnessService, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = service.get_target("demo-agent-fixture")
    target = base.model_copy(
        update={
            "id": "http-preflight",
            "adapter": Adapter(
                kind="http",
                base_url="http://127.0.0.1:9",
                operations={
                    "send_message": {"path": "/chat"},
                    "cleanup": {"path": "/_agentsec/cleanup"},
                },
            ),
        }
    )
    service._allowlist = TargetAllowlist(targets=[target])
    adapter_calls: list[object] = []
    approval_calls: list[object] = []
    executor_calls: list[object] = []
    monkeypatch.setattr(
        "agentsec.execution.replay.build_adapter",
        lambda *args: adapter_calls.append(args) or None,
    )
    monkeypatch.setattr(
        service.approvals,
        "consume",
        lambda *args: approval_calls.append(args),
    )
    monkeypatch.setattr(
        "agentsec.service.harness.get_executor",
        lambda *args, **kwargs: executor_calls.append((args, kwargs)) or None,
    )

    scenario = service.catalog.get("AGT-MEMPOIS-001")
    validation = validate_scenario(scenario, target=target)
    assert not validation.ok
    assert any(issue.code == "unsupported_driver_operation" for issue in validation.errors)

    preview = service.preview_run(
        target_id="http-preflight", scenario_ids=["AGT-MEMPOIS-001"], profile="nightly"
    )
    result = service.start_run(
        target_id="http-preflight",
        scenario_ids=["AGT-TOOLLOOP-001", "AGT-MEMPOIS-001"],
        profile="nightly",
    )

    assert preview["runnable_count"] == 0
    assert preview["blocked_count"] == 1
    assert any(
        "unsupported_driver_operation" in error
        for error in preview["plan"][0]["validation"]["errors"]
    )
    assert [run.status for run in result.runs] == [RunStatus.REFUSED, RunStatus.REFUSED]
    assert adapter_calls == []
    assert approval_calls == []
    assert executor_calls == []
    assert result.exit_code != 0
    assert result.report["blocking_count"] >= 1


def test_batch_rechecks_single_use_wildcard_approval_before_each_execution(
    service: HarnessService, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = service.catalog.get("AGT-TOOLLOOP-001")
    second = service.catalog.get("AGT-XPIA-001")

    def requires_approval(scenario: Scenario) -> Scenario:
        risk = scenario.spec.risk.model_copy(update={"requires_approval": True})
        spec = scenario.spec.model_copy(update={"risk": risk})
        return scenario.model_copy(update={"spec": spec})

    first = requires_approval(first)
    second = requires_approval(second)
    monkeypatch.setattr(service.catalog, "select", lambda **_: [first, second])

    approval = service.approvals.grant(
        scenario_id="*",
        target_id="demo-agent-fixture",
        approved_by="pytest",
    )
    consumed: list[tuple[str, str]] = []
    original_consume = service.approvals.consume

    def record_consume(approval_id: str, run_id: str) -> bool:
        consumed.append((approval_id, run_id))
        return original_consume(approval_id, run_id)

    monkeypatch.setattr(service.approvals, "consume", record_consume)

    result = service.start_run(
        target_id="demo-agent-fixture",
        scenario_ids=[first.id, second.id],
        profile="nightly",
        approval_id=approval.approval_id,
    )

    assert [run.status for run in result.runs] == [RunStatus.COMPLETED, RunStatus.REFUSED]
    assert result.runs[0].execution is not None
    assert result.runs[1].execution is None
    assert consumed == [(approval.approval_id, result.runs[0].run_id)]
    ledger = service.approvals.get(approval.approval_id)
    assert ledger is not None
    assert ledger.consumed_by_run == result.runs[0].run_id


def test_concurrent_callers_claim_once_and_only_winner_executes(
    service: HarnessService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def requires_approval(scenario: Scenario) -> Scenario:
        risk = scenario.spec.risk.model_copy(update={"requires_approval": True})
        spec = scenario.spec.model_copy(update={"risk": risk})
        return scenario.model_copy(update={"spec": spec})

    first = requires_approval(service.catalog.get("AGT-XPIA-001"))
    second = requires_approval(service.catalog.get("AGT-TOOLLOOP-001"))
    settings_a = replace(
        service.settings,
        results_dir=tmp_path / "results-a",
        db_path=tmp_path / "results-a" / "agentsec.db",
    )
    settings_b = replace(
        service.settings,
        results_dir=tmp_path / "results-b",
        db_path=tmp_path / "results-b" / "agentsec.db",
    )
    caller_a = HarnessService(settings_a, actor="caller-a")
    caller_b = HarnessService(settings_b, actor="caller-b")
    monkeypatch.setattr(caller_a, "_next_run_id", lambda: "RUN-CALLER-A")
    monkeypatch.setattr(caller_b, "_next_run_id", lambda: "RUN-CALLER-B")
    monkeypatch.setattr(caller_a.catalog, "select", lambda **_: [first])
    monkeypatch.setattr(caller_b.catalog, "select", lambda **_: [second])

    approval = caller_a.approvals.grant(
        scenario_id="*",
        target_id="demo-agent-fixture",
        approved_by="pytest",
    )
    both_valid = Barrier(2)
    valid_decisions: list[bool] = []
    valid_lock = Lock()

    def gate_check(original):  # noqa: ANN001
        def check(**kwargs):  # noqa: ANN003
            decision = original(**kwargs)
            with valid_lock:
                valid_decisions.append(decision.allowed)
            both_valid.wait(timeout=10)
            return decision

        return check

    monkeypatch.setattr(caller_a.guard, "check", gate_check(caller_a.guard.check))
    monkeypatch.setattr(caller_b.guard, "check", gate_check(caller_b.guard.check))
    execute_calls: list[str] = []
    original_execute = ReplayExecutor.execute

    def record_execute(executor, ctx):  # noqa: ANN001
        execute_calls.append(ctx.run_id)
        return original_execute(executor, ctx)

    monkeypatch.setattr(
        "agentsec.execution.replay.ReplayExecutor.execute", record_execute
    )

    def run(caller: HarnessService, scenario_id: str):
        return caller.start_run(
            target_id="demo-agent-fixture",
            scenario_ids=[scenario_id],
            profile="nightly",
            approval_id=approval.approval_id,
        ).runs[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(run, caller_a, first.id),
            pool.submit(run, caller_b, second.id),
        ]
        runs = [future.result(timeout=30) for future in futures]

    assert valid_decisions == [True, True]
    assert sorted(str(run.status) for run in runs) == sorted(
        [str(RunStatus.COMPLETED), str(RunStatus.REFUSED)]
    )
    assert len(execute_calls) == 1
    completed = next(run for run in runs if run.status is RunStatus.COMPLETED)
    ledger = caller_a.approvals.get(approval.approval_id)
    assert ledger is not None
    assert ledger.consumed_by_run == completed.run_id
