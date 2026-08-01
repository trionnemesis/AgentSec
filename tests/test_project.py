"""Selected-project resolution and discovery.

The cases here are the acceptance matrix from issue #20 PR B, plus the two
properties everything downstream depends on: an id that does not encode one
machine's directory layout, and an inventory that never reports "nothing found"
when it means "could not look".

Assertions are made against the serialised JSON as often as against fields,
because a leak that moves a value to a different key passes a field-by-field
test.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from agentsec.config import load_settings
from agentsec.errors import ConfigError, ProjectError, ProjectNotInitialised, UnsafePath
from agentsec.project import (
    MANIFEST_PATH,
    check_location,
    default_manifest_text,
    discover,
    load_manifest,
    resolve_root,
    safe_child,
    suggest_project_id,
)

MANIFEST = """\
apiVersion: agentsec.dev/v1alpha1
kind: Project
project_id: demo-project
name: Demo
surfaces:
  skills: .claude/skills
  agents: .claude/agents
  hooks: .claude/hooks
  settings: .claude/settings.json
  instructions: CLAUDE.md
  mcp_config: .mcp.json
"""

SKILL = """\
---
name: deploy
description: Ship the thing.
---

# Deploy

Steps.
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A small but complete Claude project."""
    root = tmp_path / "repo"
    _write(root / ".agentsec" / "project.yaml", MANIFEST)
    _write(root / ".claude" / "skills" / "deploy" / "SKILL.md", SKILL)
    _write(root / ".claude" / "agents" / "reviewer.md", "---\nname: reviewer\n---\nreview\n")
    _write(root / ".claude" / "hooks" / "guard.py", "print('hi')\n")
    _write(
        root / ".claude" / "settings.json",
        json.dumps({"hooks": {"PreToolUse": []}, "permissions": {"deny": ["Bash(rm:*)"]}}),
    )
    _write(root / "CLAUDE.md", "# Demo\n")
    _write(
        root / ".mcp.json",
        json.dumps({"mcpServers": {"agentsec": {"command": "agentsec-mcp", "env": {"K": "v"}}}}),
    )
    return root


# -- the root ----------------------------------------------------------------


def test_a_missing_root_is_refused_before_anything_is_read(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as exc:
        resolve_root(tmp_path / "nope")
    assert "does not exist" in exc.value.message


def test_a_file_is_not_a_root(tmp_path: Path) -> None:
    target = _write(tmp_path / "a-file", "x")
    with pytest.raises(ConfigError):
        resolve_root(target)


def test_load_settings_shares_the_resolver(tmp_path: Path) -> None:
    """One canonicalisation for execution and discovery alike."""
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "nope")
    assert load_settings(tmp_path).workspace == tmp_path.resolve()


# -- declared locations ------------------------------------------------------


@pytest.mark.parametrize(
    "location",
    [
        "../../secret",
        "a/../../b",
        "/etc/passwd",
        "~/secrets",
        "C:/Windows",
        "https://attacker.example/skills",
        "skills; curl http://x",
        "skills`whoami`",
        "skills$(id)",
        "skills\\other",
        " .claude/skills",
        "",
    ],
)
def test_unsafe_locations_are_refused(location: str) -> None:
    with pytest.raises(UnsafePath):
        check_location(location, field="surfaces.skills")


def test_a_manifest_naming_a_traversal_is_refused_and_the_target_is_never_read(
    project: Path, tmp_path: Path
) -> None:
    """The acceptance rule is refusal *before* the read, not refusal of the result."""
    secret = _write(tmp_path / "outside" / "SKILL.md", "---\nname: leaked\n---\n")
    _write(
        project / ".agentsec" / "project.yaml",
        MANIFEST.replace("skills: .claude/skills", "skills: ../outside"),
    )
    with pytest.raises(UnsafePath) as exc:
        discover(project)
    assert "escapes the project" in exc.value.message
    assert "surfaces.skills" in exc.value.message
    assert secret.exists(), "the fixture is only meaningful while the file is there to read"


def test_safe_child_refuses_a_symlink_that_leaves_the_project(
    project: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    link = project / ".claude" / "escape"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafePath) as exc:
        safe_child(resolve_root(project), ".claude/escape", field="surfaces.skills")
    assert "outside the project root" in exc.value.message


# -- discovery ---------------------------------------------------------------


def test_discovers_every_declared_surface(project: Path) -> None:
    result = discover(project).to_dict()

    assert result["project"]["project_id"] == "demo-project"
    assert [s["id"] for s in result["surfaces"]["skills"]] == ["deploy"]
    assert result["surfaces"]["skills"][0]["name"] == "deploy"
    assert [s["id"] for s in result["surfaces"]["agents"]] == ["reviewer"]
    assert [s["id"] for s in result["surfaces"]["hooks"]] == ["guard"]
    assert result["surfaces"]["settings"]["detail"]["hook_events"] == ["PreToolUse"]
    assert result["surfaces"]["settings"]["detail"]["permission_rules"] == {"deny": 1}
    assert result["surfaces"]["instructions"]["detail"]["lines"] == 1
    assert [s["name"] for s in result["surfaces"]["mcp_servers"]] == ["agentsec"]
    assert result["problems"] == []


def test_nothing_absolute_leaves_discovery(project: Path) -> None:
    """An id or a path that encodes the checkout is an id that changes per machine."""
    body = json.dumps(discover(project).to_dict())
    assert str(project.resolve()) not in body
    assert str(project.parent.resolve()) not in body
    for surface in discover(project).to_dict()["surfaces"]["skills"]:
        assert not surface["path"].startswith("/")


def test_mcp_env_values_are_not_read(project: Path) -> None:
    """`.mcp.json` env blocks are where someone else's token ends up."""
    _write(
        project / ".mcp.json",
        json.dumps(
            {"mcpServers": {"x": {"command": "x", "env": {"API_TOKEN": "sk-live-must-not-appear"}}}}
        ),
    )
    body = json.dumps(discover(project).to_dict())
    assert "sk-live-must-not-appear" not in body
    assert "API_TOKEN" in body, "the key names are the inventory; only the values are withheld"


def test_equivalent_paths_to_one_checkout_give_one_result(project: Path, tmp_path: Path) -> None:
    link = tmp_path / "via-symlink"
    link.symlink_to(project, target_is_directory=True)
    spellings = [
        project,
        Path(str(project) + os.sep),
        project / "." / ".claude" / "..",
        link,
    ]
    results = [discover(where).to_dict() for where in spellings]
    assert all(r == results[0] for r in results)


def test_a_moved_checkout_keeps_its_ids(project: Path, tmp_path: Path) -> None:
    """Content-relative ids, so a CI runner's hashed path changes nothing."""
    elsewhere = tmp_path / "somewhere" / "else" / "repo"
    elsewhere.parent.mkdir(parents=True)
    shutil.copytree(project, elsewhere, symlinks=True)
    assert discover(elsewhere).to_dict() == discover(project).to_dict()


def test_the_environment_selects_the_project(project: Path, monkeypatch) -> None:  # noqa: ANN001
    """Selection is a process-boundary concern; no caller passes a path."""
    monkeypatch.setenv("AGENTSEC_WORKSPACE", str(project))
    assert discover().to_dict()["project"]["project_id"] == "demo-project"


# -- absence and malformation are stated, never implied -----------------------


def test_a_project_with_no_skill_surface_is_not_tested_rather_than_clean(project: Path) -> None:
    shutil.rmtree(project / ".claude" / "skills")
    result = discover(project).to_dict()
    assert result["surfaces"]["skills"] == []
    assert result["counts"]["supported_skills"] == 0
    assert result["skill_assurance"] == {
        "status": "not_tested",
        "reason": "no_skill_surface",
        "detail": "no readable SKILL.md was found under the declared skills location",
    }


def test_skills_present_but_unevaluated_say_so_differently(project: Path) -> None:
    """"Nothing to test" and "nothing to test with" are different answers."""
    assurance = discover(project).to_dict()["skill_assurance"]
    assert assurance["status"] == "not_tested"
    assert assurance["reason"] == "no_evaluator"
    assert "#14" in assurance["detail"]


def test_a_malformed_skill_is_reported_not_dropped(project: Path) -> None:
    _write(project / ".claude" / "skills" / "broken" / "SKILL.md", "---\nname: [unclosed\n---\n")
    result = discover(project).to_dict()

    ids = {s["id"]: s["status"] for s in result["surfaces"]["skills"]}
    assert ids == {"deploy": "supported", "broken": "malformed"}
    assert result["counts"]["supported_skills"] == 1
    assert any(p["kind"] == "malformed" for p in result["problems"])


def test_a_directory_that_is_not_a_skill_is_reported_as_unsupported(project: Path) -> None:
    (project / ".claude" / "skills" / "notes").mkdir()
    problems = discover(project).to_dict()["problems"]
    assert [p["path"] for p in problems if p["kind"] == "unsupported"] == [".claude/skills/notes"]


def test_malformed_settings_is_a_problem_rather_than_an_empty_inventory(project: Path) -> None:
    _write(project / ".claude" / "settings.json", "{not json")
    result = discover(project).to_dict()
    assert result["surfaces"]["settings"]["status"] == "malformed"
    assert any(p["kind"] == "malformed" for p in result["problems"])


def test_a_symlinked_skill_pointing_outside_is_reported_and_not_read(
    project: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    _write(outside / "SKILL.md", "---\nname: leaked\ndescription: tenant-b-secret\n---\n")
    (project / ".claude" / "skills" / "borrowed").symlink_to(outside, target_is_directory=True)

    result = discover(project).to_dict()
    body = json.dumps(result)
    assert "tenant-b-secret" not in body
    assert "leaked" not in body
    assert any(p["kind"] == "escapes_project" for p in result["problems"])


# -- the manifest ------------------------------------------------------------


def test_an_uninitialised_repository_says_which_command_to_run(tmp_path: Path) -> None:
    with pytest.raises(ProjectNotInitialised) as exc:
        discover(tmp_path)
    assert "agentsec init" in exc.value.message
    assert MANIFEST_PATH in exc.value.message


@pytest.mark.parametrize(
    "body",
    [
        "apiVersion: wrong/v1\nkind: Project\nproject_id: demo-project\nname: Demo\n",
        "apiVersion: agentsec.dev/v1alpha1\nkind: Scenario\nproject_id: demo\nname: Demo\n",
        "apiVersion: agentsec.dev/v1alpha1\nkind: Project\nproject_id: NO\nname: Demo\n",
        "apiVersion: agentsec.dev/v1alpha1\nkind: Project\nname: Demo\n",
        (
            "apiVersion: agentsec.dev/v1alpha1\nkind: Project\nproject_id: demo-project\n"
            "name: Demo\napi_key: sk-live-1234\n"
        ),
        "[]\n",
        "apiVersion: agentsec.dev/v1alpha1\nkind: Project\nproject_id: demo\nname: Demo\n:\n:\n",
    ],
)
def test_a_manifest_that_is_not_a_manifest_is_refused(tmp_path: Path, body: str) -> None:
    _write(tmp_path / ".agentsec" / "project.yaml", body)
    with pytest.raises(ProjectError):
        load_manifest(tmp_path)


def test_the_scaffold_agentsec_init_writes_is_itself_valid(tmp_path: Path) -> None:
    """A starting file that does not load is worse than no starting file."""
    _write(
        tmp_path / ".agentsec" / "project.yaml",
        default_manifest_text(project_id=suggest_project_id(tmp_path), name=tmp_path.name),
    )
    manifest = load_manifest(tmp_path)
    assert manifest.project_id == suggest_project_id(tmp_path)
    assert manifest.surfaces.skills == ".claude/skills"


@pytest.mark.parametrize(
    ("directory", "expected"),
    [("My Repo", "my-repo"), ("agentsec", "agentsec"), ("x", "agentsec-project")],
)
def test_suggested_ids_fit_the_pattern(tmp_path: Path, directory: str, expected: str) -> None:
    root = tmp_path / directory
    root.mkdir()
    assert suggest_project_id(root) == expected


# -- the CLI entry points ----------------------------------------------------


def test_init_writes_a_manifest_that_show_can_read(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from agentsec.cli import app

    _write(tmp_path / ".claude" / "skills" / "greet" / "SKILL.md", SKILL)
    runner = CliRunner()

    written = runner.invoke(app, ["init", "--workspace", str(tmp_path)])
    assert written.exit_code == 0, written.output
    assert (tmp_path / ".agentsec" / "project.yaml").is_file()

    shown = runner.invoke(app, ["project", "show", "--workspace", str(tmp_path)])
    assert shown.exit_code == 0, shown.output
    assert json.loads(shown.stdout)["counts"]["supported_skills"] == 1


def test_init_refuses_to_overwrite_without_force(project: Path) -> None:
    """The manifest is reviewed and committed; replacing it is a decision."""
    from typer.testing import CliRunner

    from agentsec.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["init", "--workspace", str(project)])
    assert result.exit_code == 2
    assert load_manifest(project).project_id == "demo-project"

    forced = runner.invoke(
        app, ["init", "--workspace", str(project), "--force", "--project-id", "renamed"]
    )
    assert forced.exit_code == 0
    assert load_manifest(project).project_id == "renamed"


def test_this_repository_describes_itself(tmp_path: Path) -> None:
    """The manifest that ships is the first case the discovery runs against."""
    from tests.conftest import REPO_ROOT

    result = discover(REPO_ROOT).to_dict()
    assert result["project"]["project_id"] == "agentsec"
    assert "agentsec" in {s["id"] for s in result["surfaces"]["skills"]}
    assert "guard_agentsec" in {s["id"] for s in result["surfaces"]["hooks"]}
    assert result["skill_assurance"]["status"] == "not_tested"
    assert str(REPO_ROOT) not in json.dumps(result)
