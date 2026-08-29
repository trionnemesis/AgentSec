"""Drift prevention between the docs/skill prose and the MCP contract.

`agentsec.mcp.contract` (``TOOLS`` / ``RESOURCES``) is the source of truth for
the tool and resource surface. A hand-copied list or a tool name mentioned in
prose drifts the moment the contract changes underneath it, and nothing short
of a failing build reliably catches that — see the module docstring on
``agentsec.mcp.contract`` for the same argument applied to the surface itself.
"""

from __future__ import annotations

import re
from pathlib import Path

from agentsec.mcp.contract import RESOURCES, TOOLS, contract_summary
from tests.conftest import REPO_ROOT

DOC_FILES: tuple[Path, ...] = (
    REPO_ROOT / ".claude" / "skills" / "agentsec" / "SKILL.md",
    REPO_ROOT / ".claude" / "skills" / "agentsec" / "references" / "red-execution.md",
    REPO_ROOT / ".claude" / "skills" / "agentsec" / "references" / "blue-evidence.md",
    REPO_ROOT / "README.md",
    REPO_ROOT / "README.zh-TW.md",
)

# Scoped to the `agentsec_` prefix (tool names are `agentsec_[a-z_]+`) so CLI
# command words never enter the match: `mcp-contract` and `agentsec-mcp` are
# hyphenated, and `AGENTSEC_WORKSPACE` is upper-case, so none of them follow
# a literal lower-case "agentsec_".
TOOL_TOKEN_RE = re.compile(r"\bagentsec_[a-z]+(?:_[a-z]+)*\b")

# A trailing `.`/`` ` ``/`,` from prose punctuation is never part of the URI.
RESOURCE_URI_RE = re.compile(r"agentsec://[A-Za-z0-9_/{}.-]*[A-Za-z0-9_/{}]")

_PLACEHOLDER_RE = re.compile(r"\{[a-zA-Z_]+\}")


def _normalise_placeholders(uri: str) -> str:
    """Collapse any ``{name}`` segment so ``{id}`` and ``{run_id}`` compare equal.

    Docs are prose, not code: the exact placeholder spelling is not a promise
    they make, only that a templated resource is the one being referenced.
    """
    return _PLACEHOLDER_RE.sub("{*}", uri)


def _read(path: Path) -> str:
    assert path.is_file(), f"expected doc file is missing: {path}"
    return path.read_text(encoding="utf-8")


def test_every_agentsec_tool_token_in_docs_names_a_real_tool() -> None:
    """A tool renamed or removed in the contract must fail doc-referencing tests.

    Extracted from the skill and both READMEs, not just one, because a stale
    tool name in a translated doc is exactly as misleading as in the English one.
    """
    real_names = {t.name for t in TOOLS}
    for path in DOC_FILES:
        mentioned = set(TOOL_TOKEN_RE.findall(_read(path)))
        unknown = mentioned - real_names
        assert not unknown, f"{path.name} mentions unknown tool name(s): {sorted(unknown)}"


def test_every_agentsec_resource_uri_in_docs_matches_the_contract() -> None:
    """A resource URI in prose must resolve to a real ``RESOURCES`` template."""
    templates = {_normalise_placeholders(r.uri_template) for r in RESOURCES}
    for path in DOC_FILES:
        referenced = set(RESOURCE_URI_RE.findall(_read(path)))
        unknown = {u for u in referenced if _normalise_placeholders(u) not in templates}
        assert not unknown, f"{path.name} references unknown resource URI(s): {sorted(unknown)}"


def test_exactly_one_tool_executes_and_it_is_start_run() -> None:
    """The one tool allowed to act on the target, pinned by name, not just by count."""
    execute_tools = [t.name for t in TOOLS if t.risk == "execute"]
    assert execute_tools == ["agentsec_start_run"]
    assert len(execute_tools) == contract_summary()["counts"]["execute_tools"]


def test_non_read_only_tools_are_exactly_the_three_local_actors() -> None:
    """Everything not read-only either executes against a target or writes
    local state (SQLite / report files) — never a fourth, undocumented actor."""
    non_read_only = {t.name for t in TOOLS if not t.read_only}
    assert non_read_only == {
        "agentsec_start_run",
        "agentsec_promote_finding",
        "agentsec_generate_report",
    }
    counts = contract_summary()["counts"]
    assert len(non_read_only) == counts["tools"] - counts["read_only_tools"]


def test_skill_points_at_project_risks_and_dashboard_resources() -> None:
    """SKILL.md names these two by URI instead of reproducing the full
    resource list (Deliverable 1); make sure the pointer stays in place."""
    skill_text = _read(REPO_ROOT / ".claude" / "skills" / "agentsec" / "SKILL.md")
    for uri in ("agentsec://project/risks", "agentsec://dashboard/latest"):
        assert uri in skill_text, f"SKILL.md no longer mentions {uri}"
