"""ADR 0008 Phase 0: deterministic, read-only static Skill Assurance."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import get_args

import pytest
import yaml
from typer.testing import CliRunner

from agentsec.cli import app
from agentsec.mcp.contract import RESOURCES, TOOLS
from agentsec.mcp.prompts import PROMPTS
from agentsec.models.run import VERDICT_PRECEDENCE, AxisStatus, PurpleVerdict
from agentsec.models.scenario import ExecutorName
from agentsec.skill_eval.manifest import ManifestProblem, parse_suite
from agentsec.skill_eval.static import _read_regular, validate_static
from tests.conftest import REPO_ROOT

PROJECT = """\
apiVersion: agentsec.dev/v1alpha1
kind: Project
project_id: demo-project
name: Demo
surfaces:
  skills: .claude/skills
"""

SKILL = """\
---
name: deploy
description: >
  Review a deployment without acquiring execution capability.
---

# Deploy

Read the [red lane](references/red.md) and [blue lane](references/blue.md).
Use the [local check](scripts/check.py) when reviewing the bundle.
"""

REFERENCES = {
    ".claude/skills/deploy/references/red.md": "# Red\n\nRed guidance.\n",
    ".claude/skills/deploy/references/blue.md": "# Blue\n\nBlue guidance.\n",
}

SCRIPT = """\
from pathlib import Path

Path("executed-marker").write_text("this must never run")
"""


def _write(path: Path, body: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(body, bytes):
        path.write_bytes(body)
    else:
        path.write_text(body, encoding="utf-8")
    return path


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _suite_document(root: Path) -> dict[str, object]:
    entry = ".claude/skills/deploy/SKILL.md"
    script = ".claude/skills/deploy/scripts/check.py"
    return {
        "apiVersion": "agentsec.dev/v1alpha1",
        "kind": "SkillEvalSuite",
        "suite_id": "deploy-static",
        "profile": "static",
        "skill_id": "deploy",
        "entrypoint": {"path": entry, "digest": _digest(root / entry)},
        "references": [
            {"path": path, "digest": _digest(root / path)} for path in sorted(REFERENCES)
        ],
        "scripts": [{"path": script, "digest": _digest(root / script)}],
    }


def _install_project(tmp_path: Path, *, suite: bool = True) -> Path:
    root = tmp_path / "repo"
    _write(root / ".agentsec/project.yaml", PROJECT)
    _write(root / ".claude/skills/deploy/SKILL.md", SKILL)
    for path, body in REFERENCES.items():
        _write(root / path, body)
    _write(root / ".claude/skills/deploy/scripts/check.py", SCRIPT)
    if suite:
        _write(
            root / ".agentsec/skill_eval/deploy-static.yaml",
            yaml.safe_dump(_suite_document(root), sort_keys=False),
        )
    return root


def _rewrite_suite(root: Path, document: dict[str, object]) -> None:
    _write(
        root / ".agentsec/skill_eval/deploy-static.yaml",
        yaml.safe_dump(document, sort_keys=False),
    )


def _codes(report: object) -> set[str]:
    data = report.to_dict()  # type: ignore[attr-defined]
    codes = {item["code"] for item in data["issues"]}
    for skill in data["skills"]:
        codes.update(item["code"] for item in skill["issues"])
    return codes


def test_valid_bundle_is_deterministic_read_only_and_never_runs_scripts(tmp_path: Path) -> None:
    root = _install_project(tmp_path)

    first = validate_static(root)
    second = validate_static(root)

    assert first.status == "valid"
    assert first.exit_code == 0
    assert first.to_dict() == second.to_dict()
    assert not (root / "executed-marker").exists()
    assert not (root / "results").exists()
    assert "verdict" not in json.dumps(first.to_dict()).lower()


def test_cli_emits_only_machine_readable_json_and_preserves_exit_meaning(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    result = CliRunner().invoke(
        app, ["skill", "validate", "--profile", "static", "--workspace", str(root)]
    )

    assert result.exit_code == 0, result.output
    body = json.loads(result.stdout)
    assert body["kind"] == "SkillEvalStaticReport"
    assert body["status"] == "valid"
    assert body["counts"] == {"valid": 1, "invalid": 0, "not_tested": 0, "error": 0}

    unsupported = CliRunner().invoke(
        app, ["skill", "validate", "--profile", "nightly", "--workspace", str(root)]
    )
    assert unsupported.exit_code == 2
    assert json.loads(unsupported.stdout)["issues"] == [
        {"code": "skill_eval_profile_unsupported", "path": ".agentsec/skill_eval"}
    ]


def test_digest_drift_is_a_blocking_invalid_result(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    _write(root / ".claude/skills/deploy/references/red.md", "changed after review\n")

    report = validate_static(root)

    assert report.status == "invalid"
    assert report.exit_code == 1
    assert "digest_mismatch" in _codes(report)


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("missing", "asset_missing"),
        ("extra", "asset_unpinned"),
    ],
)
def test_pin_set_is_exact_in_both_directions(
    tmp_path: Path, change: str, expected: str
) -> None:
    root = _install_project(tmp_path)
    if change == "missing":
        (root / ".claude/skills/deploy/references/blue.md").unlink()
    else:
        _write(root / ".claude/skills/deploy/references/.hidden.md", "not pinned\n")

    report = validate_static(root)

    assert report.status == "invalid"
    assert expected in _codes(report)


def test_all_symlinks_are_refused_without_reading_the_target(
    tmp_path: Path,
) -> None:
    root = _install_project(tmp_path)
    outside = _write(tmp_path / "outside.md", "TENANT-B-SECRET\n")
    target = root / ".claude/skills/deploy/references/red.md"
    target.unlink()
    target.symlink_to(outside)

    report = validate_static(root)
    serialised = json.dumps(report.to_dict())

    assert report.status == "error"
    assert "symlink_forbidden" in _codes(report)
    assert "TENANT-B-SECRET" not in serialised
    assert str(tmp_path) not in serialised

    # An in-repository link is still an alias reviewers did not pin as bytes.
    target.unlink()
    target.symlink_to(root / ".claude/skills/deploy/references/blue.md")
    assert "symlink_forbidden" in _codes(validate_static(root))


@pytest.mark.parametrize(
    "unsafe",
    [
        "../../secret",
        "/etc/passwd",
        "~/secret",
        "C:/Windows/System32",
        "https://attacker.example/ref.md",
        ".claude\\skills\\deploy\\references\\red.md",
        ".claude/skills/deploy/references/%2e%2e/secret",
        ".claude/skills/deploy/references/\u202eevil.md",
    ],
)
def test_manifest_rejects_dangerous_paths_before_any_target_read(
    tmp_path: Path, unsafe: str
) -> None:
    root = _install_project(tmp_path)
    document = _suite_document(root)
    references = document["references"]
    assert isinstance(references, list)
    references[0]["path"] = unsafe
    _rewrite_suite(root, document)

    report = validate_static(root)

    assert report.status == "error"
    assert "manifest_schema_invalid" in _codes(report)
    assert unsafe not in json.dumps(report.to_dict())


@pytest.mark.parametrize(
    ("destination", "syntax"),
    [
        ("https://attacker.example/prompt", "[bad]({value})"),
        ("file:///etc/passwd", "[bad]({value})"),
        ("/etc/passwd", "[bad]({value})"),
        ("../outside.md", "[bad]({value})"),
        ("https://attacker.example/prompt", "<a href=\"{value}\">bad</a>"),
        ("file:///etc/passwd", "<a href={value}>bad</a>"),
        ("file:///etc/passwd", "[b\\]ad]({value})"),
        ("file:///etc/passwd", "[outer [inner]]({value})"),
    ],
)
def test_markdown_destinations_cannot_escape_the_pinned_local_bundle(
    tmp_path: Path, destination: str, syntax: str
) -> None:
    root = _install_project(tmp_path)
    skill_path = root / ".claude/skills/deploy/SKILL.md"
    _write(skill_path, SKILL + "\n" + syntax.format(value=destination) + "\n")
    document = _suite_document(root)
    _rewrite_suite(root, document)

    report = validate_static(root)

    assert report.status == "invalid"
    assert "dangerous_reference" in _codes(report)


def test_router_asset_mentions_must_be_real_links_and_equal_the_manifest(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    skill_path = root / ".claude/skills/deploy/SKILL.md"
    broken = SKILL.replace(
        "[red lane](references/red.md)", "`references/red.md`"
    )
    _write(skill_path, broken)
    _rewrite_suite(root, _suite_document(root))

    report = validate_static(root)

    assert report.status == "invalid"
    assert {"router_asset_not_linked", "router_references_mismatch"} <= _codes(report)


def test_asset_tokens_in_reference_files_must_also_be_pinned(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    blue = root / ".claude/skills/deploy/references/blue.md"
    _write(blue, "# Blue\n\nDo not load `scripts/undeclared.py`.\n")
    _rewrite_suite(root, _suite_document(root))

    report = validate_static(root)

    assert report.status == "invalid"
    assert "asset_token_unpinned" in _codes(report)


def test_empty_unpinned_directories_are_not_silently_ignored(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    (root / ".claude/skills/deploy/hidden-empty").mkdir()

    report = validate_static(root)

    assert report.status == "invalid"
    assert "asset_directory_unpinned" in _codes(report)


def test_entrypoint_must_be_the_discovered_skill_md_and_name_must_match(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    alternate = ".claude/skills/deploy/OTHER.md"
    _write(root / alternate, SKILL)
    document = _suite_document(root)
    document["entrypoint"] = {"path": alternate, "digest": _digest(root / alternate)}
    _rewrite_suite(root, document)

    report = validate_static(root)

    assert report.status == "invalid"
    assert {"entrypoint_invalid", "entrypoint_not_discovered"} <= _codes(report)


def test_nested_skill_uses_discovery_id_while_frontmatter_uses_leaf_name(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    document = _suite_document(root)
    old = root / ".claude/skills/deploy"
    nested = root / ".claude/skills/team/deploy"
    nested.parent.mkdir(parents=True)
    old.rename(nested)

    document["skill_id"] = "team.deploy"
    for field in ("entrypoint",):
        pin = document[field]
        assert isinstance(pin, dict)
        pin["path"] = str(pin["path"]).replace("/deploy/", "/team/deploy/")
        pin["digest"] = _digest(root / str(pin["path"]))
    for field in ("references", "scripts"):
        pins = document[field]
        assert isinstance(pins, list)
        for pin in pins:
            pin["path"] = str(pin["path"]).replace("/deploy/", "/team/deploy/")
            pin["digest"] = _digest(root / str(pin["path"]))
    _rewrite_suite(root, document)

    report = validate_static(root)

    assert report.status == "valid"
    assert report.skills[0].skill_id == "team.deploy"


def test_frontmatter_is_strict_but_allows_a_block_scalar_description(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    assert validate_static(root).status == "valid"

    skill_path = root / ".claude/skills/deploy/SKILL.md"
    duplicate = SKILL.replace("name: deploy", "name: deploy\nname: second")
    _write(skill_path, duplicate)
    _rewrite_suite(root, _suite_document(root))

    report = validate_static(root)
    assert "frontmatter_yaml_invalid" in _codes(report)


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"\xef\xbb\xbf" + SKILL.encode(), "frontmatter_bom_forbidden"),
        (
            SKILL.replace("name: deploy", "name: &skill deploy").encode(),
            "frontmatter_yaml_invalid",
        ),
        (
            SKILL.replace("name: deploy", "name: !!str deploy").encode(),
            "frontmatter_yaml_invalid",
        ),
    ],
)
def test_frontmatter_rejects_bom_and_yaml_indirection(
    tmp_path: Path, body: bytes, code: str
) -> None:
    root = _install_project(tmp_path)
    _write(root / ".claude/skills/deploy/SKILL.md", body)
    _rewrite_suite(root, _suite_document(root))

    report = validate_static(root)

    assert report.status == "invalid"
    assert code in _codes(report)


@pytest.mark.parametrize("invisible", ["\u200b", "\u2028", "\U000e0001"])
def test_invisible_and_alternate_line_characters_cannot_hide_links(
    tmp_path: Path, invisible: str
) -> None:
    root = _install_project(tmp_path)
    skill_path = root / ".claude/skills/deploy/SKILL.md"
    _write(skill_path, SKILL + invisible + "[bad](file:///etc/passwd)\n")
    _rewrite_suite(root, _suite_document(root))

    report = validate_static(root)

    assert report.status == "invalid"
    assert {"frontmatter_control_character", "markdown_control_character"} & _codes(report)


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (
            b"apiVersion: agentsec.dev/v1alpha1\nkind: SkillEvalSuite\n"
            b"suite_id: x-static\nsuite_id: y-static\n",
            "yaml_invalid",
        ),
        (b"a: &x value\nb: *x\n", "yaml_indirection_forbidden"),
        (b"!!map {a: b}\n", "yaml_indirection_forbidden"),
        (b"\xef\xbb\xbfapiVersion: agentsec.dev/v1alpha1\n", "yaml_bom_forbidden"),
    ],
)
def test_suite_yaml_has_no_ambiguous_review_forms(body: bytes, code: str) -> None:
    with pytest.raises(ManifestProblem) as exc:
        parse_suite(body)
    assert exc.value.code == code


def test_suite_yaml_depth_is_bounded_before_construction() -> None:
    body = ("a: " + "[" * 18 + "x" + "]" * 18 + "\n").encode()
    with pytest.raises(ManifestProblem) as exc:
        parse_suite(body)
    assert exc.value.code == "yaml_too_deep"


@pytest.mark.parametrize("bad_digest", ["sha256:abc", "0" * 64])
def test_malformed_or_unlabelled_digest_is_rejected_by_the_suite_schema(
    tmp_path: Path, bad_digest: str
) -> None:
    root = _install_project(tmp_path)
    document = _suite_document(root)
    entrypoint = document["entrypoint"]
    assert isinstance(entrypoint, dict)
    entrypoint["digest"] = bad_digest
    _rewrite_suite(root, document)

    report = validate_static(root)

    assert report.status == "error"
    assert "manifest_schema_invalid" in _codes(report)


def test_suite_manifest_cannot_be_pinned_as_a_circular_asset(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    document = _suite_document(root)
    references = document["references"]
    assert isinstance(references, list)
    references[0] = {
        "path": ".agentsec/skill_eval/deploy-static.yaml",
        "digest": "sha256:" + "0" * 64,
    }
    _rewrite_suite(root, document)

    report = validate_static(root)

    assert report.status == "invalid"
    assert "reference_location_invalid" in _codes(report)


def test_parent_directory_symlink_is_refused_by_inventory_and_secure_open(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    references = root / ".claude/skills/deploy/references"
    outside = tmp_path / "outside-references"
    references.rename(outside)
    references.symlink_to(outside, target_is_directory=True)

    report = validate_static(root)

    assert report.status == "error"
    assert {"symlink_forbidden", "path_component_invalid"} & _codes(report)


def test_sibling_directory_alias_to_pinned_skill_fails_before_discovery(
    tmp_path: Path,
) -> None:
    root = _install_project(tmp_path)
    (root / ".claude/skills/alias").symlink_to("deploy", target_is_directory=True)

    report = validate_static(root)

    assert report.status == "error"
    assert report.skills == []
    assert report.to_dict()["issues"] == [
        {"code": "symlink_forbidden", "path": ".claude/skills/alias"}
    ]


def test_sibling_directory_alias_to_hidden_in_repo_skill_fails_closed(
    tmp_path: Path,
) -> None:
    root = _install_project(tmp_path)
    _write(
        root / "hidden-skill/SKILL.md",
        SKILL.replace("name: deploy", "name: hidden-skill"),
    )
    (root / ".claude/skills/alias").symlink_to(
        "../../hidden-skill", target_is_directory=True
    )

    report = validate_static(root)

    assert report.status == "error"
    assert report.skills == []
    assert report.to_dict()["issues"] == [
        {"code": "symlink_forbidden", "path": ".claude/skills/alias"}
    ]


def test_sibling_skill_file_alias_fails_before_discovery_can_resolve_it(
    tmp_path: Path,
) -> None:
    root = _install_project(tmp_path)
    hidden = _write(
        root / "hidden-skill/SKILL.md",
        SKILL.replace("name: deploy", "name: hidden-skill"),
    )
    alias = root / ".claude/skills/alias/SKILL.md"
    alias.parent.mkdir()
    alias.symlink_to(hidden)

    report = validate_static(root)

    assert report.status == "error"
    assert report.skills == []
    assert report.to_dict()["issues"] == [
        {"code": "symlink_forbidden", "path": ".claude/skills/alias/SKILL.md"}
    ]


def test_skill_root_audit_overflow_discards_filesystem_order_subset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec.skill_eval import static as static_module

    monkeypatch.setattr(static_module, "MAX_SKILL_ROOT_ENTRIES", 4)
    reports = []
    names = [f"extra-{index}.txt" for index in range(5)]
    for parent, creation_order in (
        (tmp_path / "forward", names),
        (tmp_path / "reverse", list(reversed(names))),
    ):
        root = _install_project(parent)
        for name in creation_order:
            _write(root / ".claude/skills" / name, "x")
        reports.append(validate_static(root))

    assert reports[0].to_dict() == reports[1].to_dict()
    for report in reports:
        assert report.status == "error"
        assert report.skills == []
        assert report.to_dict()["issues"] == [
            {
                "code": "skill_root_too_many_entries",
                "path": ".claude/skills",
            }
        ]


def test_skill_root_audit_depth_is_bounded_before_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec.skill_eval import static as static_module

    root = _install_project(tmp_path)
    (root / ".claude/skills/z/deep/too").mkdir(parents=True)
    monkeypatch.setattr(static_module, "MAX_SKILL_ROOT_DEPTH", 2)

    report = validate_static(root)

    assert report.status == "error"
    assert report.skills == []
    assert report.to_dict()["issues"] == [
        {"code": "skill_root_too_deep", "path": ".claude/skills/z/deep/too"}
    ]


def test_canonical_equivalent_declared_skill_root_still_validates(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    _write(
        root / ".agentsec/project.yaml",
        PROJECT.replace("skills: .claude/skills", "skills: ./.claude//skills"),
    )

    assert validate_static(root).status == "valid"


def test_missing_declared_skill_root_remains_not_tested(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _write(root / ".agentsec/project.yaml", PROJECT)

    report = validate_static(root)

    assert report.status == "not_tested"
    assert report.exit_code == 2
    assert report.skills == []


def test_missing_script_is_a_blocking_invalid_result(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    (root / ".claude/skills/deploy/scripts/check.py").unlink()

    report = validate_static(root)

    assert report.status == "invalid"
    assert "asset_missing" in _codes(report)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="platform has no FIFO support")
def test_nonregular_pinned_asset_is_rejected_without_blocking(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    red = root / ".claude/skills/deploy/references/red.md"
    red.unlink()
    os.mkfifo(red)

    report = validate_static(root)

    assert report.status == "error"
    assert "nonregular_forbidden" in _codes(report)


def test_invalid_role_location_stops_before_any_skill_file_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec.skill_eval import static as static_module

    root = _install_project(tmp_path)
    misplaced = ".claude/skills/deploy/misplaced.md"
    _write(root / misplaced, "reviewed but outside references/\n")
    document = _suite_document(root)
    references = document["references"]
    assert isinstance(references, list)
    references[0] = {"path": misplaced, "digest": _digest(root / misplaced)}
    _rewrite_suite(root, document)

    original = static_module._read_regular
    artifact_reads: list[str] = []

    def guarded(root_path: Path, relative: str, *, limit: int) -> bytes:
        if relative.startswith(".agentsec/skill_eval/"):
            return original(root_path, relative, limit=limit)
        artifact_reads.append(relative)
        raise AssertionError("invalid suite reached an artifact read")

    monkeypatch.setattr(static_module, "_read_regular", guarded)
    report = validate_static(root)

    assert report.status == "invalid"
    assert "reference_location_invalid" in _codes(report)
    assert artifact_reads == []


def test_regular_file_read_is_anchored_through_descriptor_relative_components(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec.skill_eval import static as static_module

    root = tmp_path / "root"
    target = _write(root / "a/b/file.txt", "bytes\n")
    original_open = static_module.os.open
    calls: list[tuple[object, int | None]] = []

    def observed_open(
        path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        calls.append((path, dir_fd))
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(static_module.os, "open", observed_open)
    monkeypatch.setattr(static_module.os, "supports_dir_fd", {observed_open})
    assert _read_regular(root.resolve(), "a/b/file.txt", limit=100) == target.read_bytes()
    assert calls[0][1] is None
    assert all(dir_fd is not None for _, dir_fd in calls[1:])


def test_platform_without_race_safe_descriptor_walk_fails_closed_as_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec.skill_eval import static as static_module

    root = _install_project(tmp_path)
    monkeypatch.setattr(static_module.os, "supports_dir_fd", set())

    result = CliRunner().invoke(
        app, ["skill", "validate", "--profile", "static", "--workspace", str(root)]
    )

    assert result.exit_code == 2
    body = json.loads(result.stdout)
    assert body["status"] == "error"
    assert body["issues"] == [
        {
            "code": "platform_unsupported",
            "path": ".agentsec/skill_eval/deploy-static.yaml",
        }
    ]


def test_suite_directory_iteration_is_bounded_before_sorting(tmp_path: Path) -> None:
    reports = []
    names = [f"extra-{index:03d}.txt" for index in range(70)]
    for parent, creation_order in (
        (tmp_path / "forward", names),
        (tmp_path / "reverse", list(reversed(names))),
    ):
        root = _install_project(parent)
        for name in creation_order:
            _write(root / ".agentsec/skill_eval" / name, "x")
        reports.append(validate_static(root))

    assert reports[0].to_dict() == reports[1].to_dict()
    for report in reports:
        assert report.status == "error"
        assert report.skills == []
        assert report.to_dict()["issues"] == [
            {"code": "suite_too_many_entries", "path": ".agentsec/skill_eval"}
        ]


def test_bundle_overflow_discards_filesystem_order_subset(tmp_path: Path) -> None:
    reports = []
    names = [f"file-{index:03d}.txt" for index in range(140)]
    for parent, creation_order in (
        (tmp_path / "forward", names),
        (tmp_path / "reverse", list(reversed(names))),
    ):
        root = _install_project(parent)
        for name in creation_order:
            _write(root / ".claude/skills/deploy/overflow" / name, "x")
        reports.append(validate_static(root))

    assert reports[0].to_dict() == reports[1].to_dict()
    for report in reports:
        assert report.status == "error"
        assert _codes(report) == {"bundle_too_many_entries"}


def test_no_suite_is_explicit_not_tested_and_never_green(tmp_path: Path) -> None:
    root = _install_project(tmp_path, suite=False)

    report = validate_static(root)

    assert report.status == "not_tested"
    assert report.exit_code == 2
    assert "static_suite_missing" in _codes(report)


def test_output_contains_no_absolute_paths_or_raw_skill_content(tmp_path: Path) -> None:
    root = _install_project(tmp_path)
    body = json.dumps(validate_static(root).to_dict())

    assert str(root) not in body
    assert "Review a deployment" not in body
    assert "this must never run" not in body
    for result in validate_static(root).to_dict()["skills"]:
        assert not result["entrypoint"].startswith("/")


def test_static_workflow_is_separate_read_only_and_has_no_credentials() -> None:
    workflow = REPO_ROOT / ".github/workflows/skill-eval-static.yml"
    text = workflow.read_text(encoding="utf-8")

    assert "agentsec skill validate --profile static" in text
    assert "contents: read" in text
    assert "persist-credentials: false" in text
    assert "push:\n    branches: [main]" in text
    assert "pull_request:" in text
    assert "paths:" not in text
    assert "continue-on-error" not in text
    assert "timeout-minutes: 10" in text
    assert "secrets." not in text
    assert "OPENAI" not in text and "ANTHROPIC" not in text
    assert "agentsec run" not in text


def test_phase0_does_not_expand_existing_product_surfaces() -> None:
    assert [
        path.relative_to(REPO_ROOT).as_posix()
        for path in sorted(REPO_ROOT.glob(".claude/skills/**/SKILL.md"))
    ] == [".claude/skills/agentsec/SKILL.md"]
    for lane in ("red-execution.md", "blue-evidence.md"):
        assert (REPO_ROOT / ".claude/skills/agentsec/references" / lane).is_file()

    assert [status.value for status in AxisStatus] == [
        "pass",
        "fail",
        "not_tested",
        "error",
    ]
    verdicts = [
        "error",
        "detection_gap",
        "prevention_gap",
        "evidence_gap",
        "response_gap",
        "secure",
    ]
    assert [verdict.value for verdict in PurpleVerdict] == verdicts
    assert [verdict.value for verdict in VERDICT_PRECEDENCE] == verdicts
    assert get_args(ExecutorName) == ("replay", "promptfoo", "pyrit", "pytest")

    assert [tool.name for tool in TOOLS] == [
        "agentsec_list_targets",
        "agentsec_get_target_schema",
        "agentsec_validate_scenario",
        "agentsec_preview_run",
        "agentsec_start_run",
        "agentsec_get_run",
        "agentsec_compare_runs",
        "agentsec_promote_finding",
        "agentsec_validate_detection",
        "agentsec_create_regression_draft",
        "agentsec_generate_report",
    ]
    assert [tool.name for tool in TOOLS if tool.risk == "execute"] == [
        "agentsec_start_run"
    ]
    assert [resource.uri_template for resource in RESOURCES] == [
        "agentsec://targets",
        "agentsec://targets/{target_id}",
        "agentsec://scenarios",
        "agentsec://runs/{run_id}",
        "agentsec://runs/{run_id}/evidence",
        "agentsec://project/risks",
        "agentsec://findings",
        "agentsec://dashboard/latest",
        "agentsec://coverage",
        "agentsec://audit",
    ]
    assert [prompt.name for prompt in PROMPTS] == [
        "agentsec-create-scenario",
        "agentsec-investigate-finding",
        "agentsec-purple-review",
        "agentsec-promote-regression",
        "agentsec-detection-review",
    ]
