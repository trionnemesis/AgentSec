"""Policy guard, allowlist and approvals."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
import yaml

from agentsec.errors import ConfigError, EvidenceUnavailable
from agentsec.models.scenario import Scenario
from agentsec.models.target import Target, TargetAllowlist
from agentsec.policy.allowlist import (
    ENV_EXTERNAL_ALLOW,
    assert_private_url,
    load_allowlist,
)
from agentsec.policy.approvals import ApprovalStore
from agentsec.policy.guard import PolicyGuard
from agentsec.policy.profiles import default_profiles, load_profiles
from agentsec.scenario.loader import load_scenario_file
from tests.conftest import REPO_ROOT


def _scenario(name: str) -> Scenario:
    return load_scenario_file(REPO_ROOT / "scenarios" / f"{name}.yaml")


def _target(**overrides) -> Target:  # noqa: ANN003
    base = {
        "id": "test-agent",
        "environment": "staging",
        "capabilities": ["rag", "tool_calling", "memory", "multi_tenant", "email"],
        "max_risk_level": "medium",
        "allowed_executors": ["replay"],
        "adapter": {"kind": "fixture", "fixture_dir": "fixtures/x"},
        "evidence": {
            "otel": {"kind": "file", "path": "a.json"},
            "wazuh": {"kind": "file", "path": "b.json"},
            "tool_audit": {"kind": "file", "path": "c.json"},
            "state_diff": {"kind": "file", "path": "d.json"},
        },
    }
    return Target.model_validate({**base, **overrides})


# ------------------------------------------------------------------- allowlist


def test_production_environment_is_not_expressible() -> None:
    """The refusal is structural: there is no runtime flag to override.

    A boolean like `allow_production=False` is one code review away from being
    flipped. An absent enum member is not.
    """
    with pytest.raises(Exception) as exc:
        _target(environment="production")
    assert "production" in str(exc.value) or "environment" in str(exc.value)


def test_public_http_endpoint_is_refused(tmp_path) -> None:  # noqa: ANN001
    doc = {
        "apiVersion": "agentsec.dev/v1",
        "kind": "TargetAllowlist",
        "targets": [
            {
                "id": "leaky-agent",
                "environment": "staging",
                "adapter": {"kind": "http", "base_url": "https://8.8.8.8/chat"},
            }
        ],
    }
    path = tmp_path / "targets.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    with pytest.raises(ConfigError) as exc:
        load_allowlist(path)
    assert "not a private or loopback address" in exc.value.message


def test_public_endpoint_allowed_when_operator_opts_in(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    doc = {
        "apiVersion": "agentsec.dev/v1",
        "kind": "TargetAllowlist",
        "targets": [
            {
                "id": "sanctioned-agent",
                "environment": "staging",
                "adapter": {"kind": "http", "base_url": "https://agent.example.com/chat"},
            }
        ],
    }
    path = tmp_path / "targets.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    monkeypatch.setenv(ENV_EXTERNAL_ALLOW, "agent.example.com")
    allowlist = load_allowlist(path)
    assert allowlist.get("sanctioned-agent") is not None


def test_loopback_endpoint_is_accepted(tmp_path) -> None:  # noqa: ANN001
    doc = {
        "apiVersion": "agentsec.dev/v1",
        "kind": "TargetAllowlist",
        "targets": [
            {
                "id": "local-agent",
                "environment": "local",
                "adapter": {"kind": "http", "base_url": "http://127.0.0.1:8080"},
            }
        ],
    }
    path = tmp_path / "targets.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    assert load_allowlist(path).get("local-agent") is not None


def test_evidence_backend_url_is_checked_too(tmp_path) -> None:  # noqa: ANN001
    """The adapter is not the only thing the harness dials.

    The Wazuh collector sends `WAZUH_INDEXER_USER`/`_PASSWORD` over basic auth, so
    a public URL there leaks the SIEM credentials rather than merely reaching the
    wrong host.
    """
    doc = {
        "apiVersion": "agentsec.dev/v1",
        "kind": "TargetAllowlist",
        "targets": [
            {
                "id": "leaky-evidence",
                "environment": "staging",
                "adapter": {"kind": "fixture", "fixture_dir": "fixtures/demo-agent"},
                "evidence": {
                    "wazuh": {
                        "kind": "opensearch",
                        "url": "https://8.8.8.8:9200",
                        "username_env": "WAZUH_INDEXER_USER",
                        "password_env": "WAZUH_INDEXER_PASSWORD",
                    }
                },
            }
        ],
    }
    path = tmp_path / "targets.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    with pytest.raises(ConfigError) as exc:
        load_allowlist(path)
    assert "not a private or loopback address" in exc.value.message
    assert exc.value.details["field"] == "evidence.wazuh.url"


def test_private_url_is_reasserted_at_collection_time() -> None:
    """Load-time leniency is only safe if something checks again later.

    `_is_private_host` treats an unresolvable name as private, because compose
    service names legitimately do not resolve when the allowlist loads. A name that
    resolves publicly by the time a collector dials it must still be refused.
    """
    assert_private_url("http://10.1.2.3:9200", what="the Wazuh Indexer")  # does not raise
    with pytest.raises(EvidenceUnavailable) as exc:
        assert_private_url("https://8.8.8.8:9200", what="the Wazuh Indexer")
    assert "outside private address space" in exc.value.message


def test_quarantine_with_an_explicit_offset_is_converted_not_overwritten() -> None:
    """`.replace(tzinfo=UTC)` on an aware value moved the instant.

    A quarantine written as `+08:00` used to be reinterpreted as UTC and ran eight
    hours long. Expressed here as an instant that has already passed in its own
    zone, so a wrong reading leaves it in force.
    """
    expired = (datetime.now(UTC) - timedelta(minutes=30)).astimezone(
        timezone(timedelta(hours=8))
    )
    base = _scenario("AGT-XPIA-001").model_dump(mode="json")
    base["spec"]["regression"]["quarantined_until"] = expired.isoformat()
    scenario = Scenario.model_validate(base)

    decision = PolicyGuard().check(
        scenario=scenario, target=_target(), profile=default_profiles().get("pr")
    )
    assert decision.allowed, decision.reasons


def test_redacted_target_withholds_endpoint_and_credential_names() -> None:
    """What we hand a model must not include the shape of the secret.

    Knowing a target reads ORDER_AGENT_TOKEN is a useful hint to an attacker and
    of no use to a scenario author.
    """
    target = Target.model_validate(
        {
            "id": "secret-agent",
            "environment": "staging",
            "adapter": {
                "kind": "http",
                "base_url": "http://10.0.0.5:8080",
                "headers_from_env": {"authorization": "AGENT_BEARER"},
            },
            "principals": {"tenant-a": "TENANT_A_TOKEN"},
        }
    )
    redacted = target.redacted()
    blob = str(redacted)
    assert "10.0.0.5" not in blob
    assert "TENANT_A_TOKEN" not in blob
    assert "AGENT_BEARER" not in blob
    # The logical principal name is safe and necessary for authoring.
    assert redacted["principals"] == ["tenant-a"]


def test_duplicate_target_ids_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate target ids"):
        TargetAllowlist.model_validate(
            {
                "targets": [
                    {"id": "dup", "environment": "local",
                     "adapter": {"kind": "fixture", "fixture_dir": "a"}},
                    {"id": "dup", "environment": "local",
                     "adapter": {"kind": "fixture", "fixture_dir": "b"}},
                ]
            }
        )


def test_shipped_allowlist_loads() -> None:
    allowlist = load_allowlist(REPO_ROOT / "policy" / "targets.yaml")
    assert allowlist.get("demo-agent-fixture") is not None


# ------------------------------------------------------------------- guard


def test_guard_allows_a_fitting_scenario() -> None:
    guard = PolicyGuard()
    decision = guard.check(
        scenario=_scenario("AGT-XPIA-001"),
        target=_target(),
        profile=default_profiles().get("pr"),
    )
    assert decision.allowed, decision.reasons


def test_guard_refuses_on_missing_capability() -> None:
    decision = PolicyGuard().check(
        scenario=_scenario("AGT-MEMPOIS-001"),  # needs memory
        target=_target(capabilities=["tool_calling"]),
        profile=default_profiles().get("nightly"),
    )
    assert not decision.allowed
    assert any("capabilities" in r for r in decision.reasons)


def test_guard_refuses_when_executor_not_permitted() -> None:
    decision = PolicyGuard().check(
        scenario=_scenario("AGT-XPIA-001"),
        target=_target(allowed_executors=["promptfoo"]),
        profile=default_profiles().get("pr"),
    )
    assert not decision.allowed
    assert any("executor" in r for r in decision.reasons)


def test_risk_ceiling_uses_the_stricter_of_target_and_profile() -> None:
    """A permissive target must not widen a strict profile, or vice versa."""
    scenario = _scenario("AGT-TENANT-001")  # risk: medium
    strict_profile = default_profiles().get("pr").model_copy(
        update={"max_risk_level": "low"}
    )
    decision = PolicyGuard().check(
        scenario=scenario, target=_target(max_risk_level="high"), profile=strict_profile
    )
    assert not decision.allowed
    assert any("ceiling" in r for r in decision.reasons)


def test_destructive_scenario_requires_approval_automatically() -> None:
    """Authors forget. Upgrading is safer than trusting the flag."""
    scenario = Scenario.model_validate(
        {
            "metadata": {
                "id": "AGT-TEST-001",
                "title": "Destructive test case",
                "severity": "high",
            },
            "spec": {
                "target": {"environments": ["staging"]},
                "risk": {"level": "medium", "destructive": True},
                "attack": {
                    "executor": "replay",
                    "steps": [{"id": "go", "kind": "agent_message", "payload": "hi"}],
                },
                "contract": {
                    "prevention": {"must_not": [{"kind": "output_contains", "value": "x"}]}
                },
            },
        }
    )
    assert scenario.spec.risk.requires_approval is True

    decision = PolicyGuard().check(
        scenario=scenario,
        target=_target(allow_destructive=True),
        profile=default_profiles().get("release"),
    )
    assert not decision.allowed
    assert any("approval" in r for r in decision.reasons)


def test_quarantined_scenario_is_refused_until_expiry() -> None:
    future = (datetime.now(UTC) + timedelta(days=7)).date().isoformat()
    base = _scenario("AGT-XPIA-001").model_dump(mode="json")
    base["spec"]["regression"]["quarantined_until"] = future
    scenario = Scenario.model_validate(base)

    decision = PolicyGuard().check(
        scenario=scenario, target=_target(), profile=default_profiles().get("pr")
    )
    assert not decision.allowed
    assert any("quarantined" in r for r in decision.reasons)


def test_expired_quarantine_no_longer_blocks() -> None:
    past = (datetime.now(UTC) - timedelta(days=1)).date().isoformat()
    base = _scenario("AGT-XPIA-001").model_dump(mode="json")
    base["spec"]["regression"]["quarantined_until"] = past
    scenario = Scenario.model_validate(base)

    decision = PolicyGuard().check(
        scenario=scenario, target=_target(), profile=default_profiles().get("pr")
    )
    assert decision.allowed, decision.reasons


# ------------------------------------------------------------------ approvals


def test_approval_is_single_use(tmp_path) -> None:  # noqa: ANN001
    store = ApprovalStore(tmp_path / "approvals.yaml")
    approval = store.grant(
        scenario_id="AGT-XPIA-001", target_id="test-agent", approved_by="alice"
    )
    assert approval.is_valid_for("AGT-XPIA-001", "test-agent")

    store.consume(approval.approval_id, "RUN-20260728-001")
    reloaded = store.get(approval.approval_id)
    assert reloaded is not None
    assert not reloaded.is_valid_for("AGT-XPIA-001", "test-agent")
    assert "already consumed" in reloaded.invalid_reason("AGT-XPIA-001", "test-agent")


def test_approval_is_scoped_to_scenario_and_target(tmp_path) -> None:  # noqa: ANN001
    store = ApprovalStore(tmp_path / "approvals.yaml")
    approval = store.grant(
        scenario_id="AGT-XPIA-001", target_id="test-agent", approved_by="alice"
    )
    assert not approval.is_valid_for("AGT-TENANT-001", "test-agent")
    assert not approval.is_valid_for("AGT-XPIA-001", "other-agent")


def test_approval_expires(tmp_path) -> None:  # noqa: ANN001
    store = ApprovalStore(tmp_path / "approvals.yaml")
    approval = store.grant(
        scenario_id="*", target_id="*", approved_by="alice", ttl_minutes=1
    )
    later = datetime.now(UTC) + timedelta(minutes=2)
    assert not approval.is_valid_for("AGT-XPIA-001", "test-agent", now=later)
    assert "expired" in approval.invalid_reason("AGT-XPIA-001", "test-agent", now=later)


# ------------------------------------------------------------------- profiles


def test_shipped_profiles_load_and_gate_sensibly() -> None:
    profiles = load_profiles(REPO_ROOT / "policy" / "profiles.yaml")
    from agentsec.models.run import PurpleVerdict

    pr = profiles.get("pr")
    assert pr.blocks(PurpleVerdict.DETECTION_GAP)
    assert pr.blocks(PurpleVerdict.PREVENTION_GAP)
    assert pr.blocks(PurpleVerdict.ERROR)
    # A pull request is deliberately not blocked on these; release is.
    assert not pr.blocks(PurpleVerdict.EVIDENCE_GAP)
    assert profiles.get("release").blocks(PurpleVerdict.EVIDENCE_GAP)
    assert not pr.blocks(PurpleVerdict.SECURE)


def test_missing_profiles_file_falls_back_to_defaults(tmp_path) -> None:  # noqa: ANN001
    profiles = load_profiles(tmp_path / "nope.yaml")
    assert profiles.names() == ["nightly", "pr", "release"]
