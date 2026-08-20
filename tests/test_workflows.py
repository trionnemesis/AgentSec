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
        "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "v7.0.1",
    ),
    "actions/configure-pages": (
        "45bfe0192ca1faeb007ade9deae92b16b8254a0d",
        "v6.0.0",
    ),
    "actions/deploy-pages": (
        "cd2ce8fcbc39b97be8ca5fce6e763baed58fa128",
        "v5.0.0",
    ),
    "actions/setup-python": (
        "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "v7.0.0",
    ),
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "v7.0.1",
    ),
    "actions/upload-pages-artifact": (
        "fc324d3547104276b827a68afc52ff2a11cc49c9",
        "v5.0.0",
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
