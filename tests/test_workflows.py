"""Supply-chain invariants for GitHub Actions workflows."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))

EXPECTED_ACTIONS = {
    "actions/checkout": (
        "11d5960a326750d5838078e36cf38b85af677262",
        "v4.4.0",
    ),
    "actions/configure-pages": (
        "983d7736d9b0ae728b81ab479565c72886d7745b",
        "v5.0.0",
    ),
    "actions/deploy-pages": (
        "d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
        "v4.0.5",
    ),
    "actions/setup-python": (
        "a26af69be951a213d495a4c3e4e4022e16d87065",
        "v5.6.0",
    ),
    "actions/upload-artifact": (
        "ea165f8d65b6e75b540449e92b4886f43607fa02",
        "v4.6.2",
    ),
    "actions/upload-pages-artifact": (
        "56afc609e74202658d3ffba0e8f6dda462b719fa",
        "v3.0.1",
    ),
    "pypa/gh-action-pip-audit": (
        "1220774d901786e6f652ae159f7b6bc8fea6d266",
        "v1.1.0",
    ),
}

USES_LINE = re.compile(
    r"^\s*(?:-\s+)?uses:\s+([^@\s]+)@([0-9a-f]{40})\s+#\s+(v\d+\.\d+\.\d+)\s*$"
)


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_workflow_yaml_is_parseable(workflow: Path) -> None:
    assert yaml.safe_load(workflow.read_text(encoding="utf-8")) is not None


def test_external_actions_are_allowlisted_and_pinned_to_full_commit_shas() -> None:
    observed: set[str] = set()
    for workflow in WORKFLOWS:
        for line_number, line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not re.match(r"^\s*(?:-\s+)?uses:", line):
                continue
            match = USES_LINE.match(line)
            assert match is not None, (
                f"{workflow.relative_to(ROOT)}:{line_number}: external actions require a "
                "40-character commit SHA and an exact semver comment"
            )
            action, sha, version = match.groups()
            assert action in EXPECTED_ACTIONS, (
                f"{workflow.relative_to(ROOT)}:{line_number}: review and allowlist {action}"
            )
            assert (sha, version) == EXPECTED_ACTIONS[action], (
                f"{workflow.relative_to(ROOT)}:{line_number}: {action} pin/comment drifted"
            )
            observed.add(action)

    assert observed == set(EXPECTED_ACTIONS), (
        "the audit action or a pinned workflow action vanished"
    )
