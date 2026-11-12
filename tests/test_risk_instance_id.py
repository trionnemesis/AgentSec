"""Contract tests for stable, additive repository risk instance identities."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.inspect import inspect_project
from agentsec.models.risk import RepoRisk
from agentsec.project import discover
from agentsec.reporting.publish import _dashboard_validator, publish
from agentsec.service.harness import HarnessService
from tests.test_inspect import MANIFEST, write


def scan(root: Path, service: HarnessService):
    return inspect_project(root=root, discovery=discover(root), catalog=service.catalog)


def test_mcp_instances_are_unique_stable_and_independent_of_secret_values(
    workspace: Path, service: HarnessService
) -> None:
    write(workspace / ".agentsec/project.yaml", MANIFEST)
    path = workspace / ".mcp.json"
    names = ["FOO", "Foo", "foo", "x" * 120 + "A", "x" * 120 + "B"]

    def set_servers(names: list[str], secret: str) -> None:
        write(
            path,
            json.dumps(
                {
                    "mcpServers": {
                        name: {"url": "https://example.invalid", "env": {"API_TOKEN": secret}}
                        for name in names
                    }
                }
            ),
        )

    set_servers(names, "secret-one")
    report = scan(workspace, service)
    risks = [r for r in report.risks if r.rule_id == "ASI-MCP-CREDENTIAL-ENV"]
    ids = {r.instance_id for r in risks}
    assert len(ids) == len(names)
    assert all(r.id == "ASI-MCP-CREDENTIAL-ENV:.mcp.json" for r in risks)
    assert all(x and x.startswith("rinst-v1:") for x in ids)
    before_queue = report.verify_queue

    set_servers(["A-new", *reversed(names)], "different-secret")
    new_report = scan(workspace, service)
    new_ids = {r.instance_id for r in new_report.risks if r.rule_id == "ASI-MCP-CREDENTIAL-ENV"}
    assert ids < new_ids
    assert new_report.verify_queue == before_queue
    assert "secret-one" not in json.dumps(report.to_dict())


def test_grant_instance_ids_distinguish_duplicate_findings_without_using_grant_text(
    workspace: Path, service: HarnessService
) -> None:
    write(workspace / ".agentsec/project.yaml", MANIFEST)
    path = workspace / ".claude/settings.json"

    def set_grants(values: list[str]) -> None:
        write(path, json.dumps({"permissions": {"allow": values}}))

    def ids() -> list[str]:
        return [
            r.instance_id
            for r in scan(workspace, service).risks
            if r.rule_id == "ASI-TOOL-BROAD-GRANT"
        ]

    set_grants(["Bash(*)", "Bash(*)"])
    first = ids()
    assert len(first) == len(set(first)) == 2
    set_grants(["Read(*)", "Bash(*)", "Bash(*)"])
    assert ids() == first
    set_grants(["Bash(:*)", "Bash(*)"])
    assert ids() == first


def test_same_resolved_file_from_symlink_gets_distinct_instance_ids(
    workspace: Path, service: HarnessService
) -> None:
    write(workspace / ".agentsec/project.yaml", MANIFEST)
    hook = write(
        workspace / ".claude/hooks/a.py",
        'import requests\nrequests.get("https://example.invalid")\n',
    )
    (hook.parent / "b.py").symlink_to(hook.name)
    found = [r for r in scan(workspace, service).risks if r.rule_id == "ASI-HOOK-NETWORK-EGRESS"]
    assert len(found) == 2
    assert len({r.instance_id for r in found}) == 2


def test_memory_store_identity_survives_adding_an_earlier_entry(
    workspace: Path, service: HarnessService
) -> None:
    write(workspace / ".agentsec/project.yaml", MANIFEST)
    write(workspace / ".claude/memory/z.md", "some context")
    before = next(
        r for r in scan(workspace, service).risks if r.rule_id == "ASI-MEMORY-UNREVIEWED-STORE"
    )
    write(workspace / ".claude/memory/a.md", "different context")
    after = next(
        r for r in scan(workspace, service).risks if r.rule_id == "ASI-MEMORY-UNREVIEWED-STORE"
    )
    assert before.id != after.id  # legacy ID still follows the first file
    assert before.instance_id == after.instance_id


def test_instance_source_encoding_does_not_confuse_delimiters() -> None:
    common = dict(
        rule_id="ASI-TEST-EXAMPLE",
        severity="low",
        surface_kind="mcp_server",
        surface_id="same",
        file=".mcp.json",
        title="test",
    )
    left = RepoRisk(**common, identity_source=("a:b", "c"))
    right = RepoRisk(**common, identity_source=("a", "b:c"))
    assert left.instance_id != right.instance_id
    assert "identity_source" not in left.model_dump()


def test_publisher_exposes_new_identity_and_preserves_old_records(
    workspace: Path, service: HarnessService
) -> None:
    write(workspace / ".agentsec/project.yaml", MANIFEST)
    write(workspace / ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(*)"]}}))
    report = scan(workspace, service).to_dict()
    plane = publish("repo_risk", report)
    assert all(r["instance_id"].startswith("rinst-v1:") for r in plane["risks"])
    legacy = RepoRisk(
        rule_id="ASI-TEST-EXAMPLE",
        severity="low",
        surface_kind="hook",
        surface_id="h",
        file="a",
        title="old",
    ).to_dict()
    assert "instance_id" not in legacy
    old_plane = publish("repo_risk", {"status": "inspected", "risks": [legacy]})
    assert "instance_id" not in old_plane["risks"][0]


def test_dashboard_schema_accepts_current_and_old_snapshots(
    workspace: Path, service: HarnessService
) -> None:
    write(workspace / ".agentsec/project.yaml", MANIFEST)
    write(workspace / ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(*)"]}}))
    dashboard = publish("dashboard", service.dashboard())
    assert dashboard["repo_risk"]["risks"]
    validator = _dashboard_validator()
    validator.validate(dashboard)
    for risk in dashboard["repo_risk"]["risks"]:
        del risk["instance_id"]
    validator.validate(dashboard)
