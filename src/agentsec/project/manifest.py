"""The committed project manifest, ``.agentsec/project.yaml``.

Why a file rather than a tool argument: no MCP tool accepts a path, and that is
[ADR 0003](../../../docs/adr/0003-constrained-mcp-tools.md) rather than an
oversight. Directory selection has to happen somewhere, so it happens at the
process boundary (which repository the harness was started in) and in a file a
human wrote and a reviewer merged. A caller names a ``project_id``; it never
names a location.

This puts the manifest on the *declared configuration* side of the line drawn in
`reporting/publish.py`: operator-written, reviewed, and therefore publishable as
written. That standing is exactly why the contents are constrained here rather
than sanitised later — a manifest that can carry a credential or an endpoint is a
manifest whose review no longer means anything.

`path` is a forbidden MCP parameter name and a required manifest concept. Those
do not conflict, and the distinction is worth stating plainly: a location a
reviewer merged is not a location a caller supplied.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from agentsec.errors import ProjectError, ProjectNotInitialised
from agentsec.project.resolver import check_location, resolve_root

API_VERSION: Final = "agentsec.dev/v1alpha1"
KIND: Final = "Project"

MANIFEST_DIR = ".agentsec"
MANIFEST_NAME = "project.yaml"
MANIFEST_PATH = f"{MANIFEST_DIR}/{MANIFEST_NAME}"

PROJECT_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{2,63}$"


class Surfaces(BaseModel):
    """Where this repository keeps the things AgentSec can look at.

    Defaults describe a stock Claude Code project. They are declared rather than
    hardcoded so a repository that puts its skills somewhere else can say so in
    review, instead of the harness reporting an empty project and calling it
    clean.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    skills: str = ".claude/skills"
    agents: str = ".claude/agents"
    hooks: str = ".claude/hooks"
    settings: str = ".claude/settings.json"
    instructions: str = "CLAUDE.md"
    mcp_config: str = ".mcp.json"
    memory: str = ".claude/memory"
    """Retrieved context the agent reads but no reviewer diffs.

    Declared like every other surface rather than inferred, and defaulting to a
    directory most repositories do not have: an absent memory store is a real
    and common state, and it inventories as empty. What it must not do is
    inventory as *safe* — a repository that keeps its RAG corpus somewhere else
    says so here, because the alternative is a plane that reports zero memory
    surfaces for a project whose whole attack path runs through one.
    """

    @field_validator("*")
    @classmethod
    def _relative_and_inert(cls, value: str, info: ValidationInfo) -> str:
        check_location(value, field=str(info.field_name))
        return value

    def as_dict(self) -> dict[str, str]:
        return self.model_dump()


class ProjectManifest(BaseModel):
    """``.agentsec/project.yaml``.

    ``project_id`` is committed rather than derived from the checkout, so it
    survives a clone into a different directory, a worktree, and a CI runner that
    checks out into a hashed path. Deriving it from an absolute path would give
    the same repository a different identity on every machine, which is the one
    thing an id must not do.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    apiVersion: Literal["agentsec.dev/v1alpha1"] = API_VERSION  # noqa: N815 - the wire name
    kind: Literal["Project"] = KIND
    project_id: str = Field(pattern=PROJECT_ID_PATTERN)
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    surfaces: Surfaces = Field(default_factory=Surfaces)
    static_posture_report: str | None = Field(
        default=None,
        description=(
            "Where a static scanner's report (AgentShield JSON or SARIF) lives, "
            "relative to this file's repository. Unlike `surfaces`, this has no "
            "default: most repositories have not run a scanner, and inventing a "
            "location no report lives at would make `not_tested` look like a "
            "path resolution error instead of an honest absence."
        ),
    )

    @field_validator("static_posture_report")
    @classmethod
    def _report_location_is_safe(cls, value: str | None) -> str | None:
        if value is not None:
            check_location(value, field="static_posture_report")
        return value

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "name": self.name,
            "description": self.description,
            "surfaces": self.surfaces.as_dict(),
            "static_posture_report": self.static_posture_report,
        }


@lru_cache(maxsize=1)
def _schema() -> Draft202012Validator:
    # Imported here rather than at module scope: `config` resolves its root
    # through `project.resolver`, so a module-level import would close the loop.
    from agentsec.config import package_schema_dir

    schema = json.loads(
        (package_schema_dir() / "project.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(schema)


def manifest_path(root: Path) -> Path:
    return root / MANIFEST_DIR / MANIFEST_NAME


def load_manifest(root: Path) -> ProjectManifest:
    """Read and validate the manifest at ``root``.

    ``yaml.safe_load``, not ``load``: a manifest travels with a repository, and a
    repository is not trusted input just because it is checked out locally.
    """
    path = manifest_path(root)
    if not path.is_file():
        raise ProjectNotInitialised(
            f"no {MANIFEST_PATH} in {root}. Run `agentsec init` to create one, then "
            f"review and commit it.",
            details={"root": str(root)},
        )
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ProjectError(f"{MANIFEST_PATH}: invalid YAML: {exc}") from exc
    except OSError as exc:
        raise ProjectError(f"cannot read {MANIFEST_PATH}: {exc}") from exc

    if not isinstance(data, dict):
        raise ProjectError(f"{MANIFEST_PATH}: expected a mapping at the document root")

    # Locations first, before the schema and before Pydantic. The acceptance rule
    # is that a manifest naming `../../secret` is refused *and the target is never
    # read*, and the refusal should say which field and why rather than report a
    # pattern mismatch. The schema encodes the same constraint for anyone
    # validating the file without importing this package.
    surfaces = data.get("surfaces")
    if isinstance(surfaces, dict):
        for key, value in surfaces.items():
            if isinstance(value, str):
                check_location(value, field=f"surfaces.{key}")

    errors = sorted(_schema().iter_errors(data), key=str)
    if errors:
        detail = "; ".join(
            f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}"
            for e in errors[:5]
        )
        raise ProjectError(f"{MANIFEST_PATH}: schema errors: {detail}")

    try:
        return ProjectManifest.model_validate(data)
    except ProjectError:
        raise
    except Exception as exc:  # pydantic ValidationError, kept generic as elsewhere
        raise ProjectError(f"{MANIFEST_PATH}: {exc}") from exc


def load_project(workspace: str | Path | None = None) -> tuple[Path, ProjectManifest]:
    """Canonical entry point: root first, then the manifest inside it."""
    root = resolve_root(workspace)
    return root, load_manifest(root)


def default_manifest_text(*, project_id: str, name: str) -> str:
    """The scaffold ``agentsec init`` writes.

    Written as text rather than dumped from the model so the comments survive.
    The file is meant to be read in review, and the two constraints a reviewer
    has to enforce are the two that cannot be expressed in the schema alone.
    """
    return f"""\
# AgentSec project manifest. Committed, and reviewed like the target allowlist.
#
# Two rules a reviewer enforces:
#   1. Locations are relative to this file's repository. No absolute paths, no
#      `..`, no URLs, no commands.
#   2. No credentials, ever. Credential *names* live in policy/targets.yaml and
#      their values only in the environment.
apiVersion: {API_VERSION}
kind: {KIND}

# Stable identity for this repository. Callers name this id; they never name a
# path. Keep it unchanged across clones, worktrees and CI checkouts — that is
# what makes results from different machines comparable.
project_id: {project_id}
name: {name}

# Where this repository keeps the surfaces AgentSec inspects. Delete a line to
# accept the default shown; keep one only if this repository differs.
surfaces:
  skills: .claude/skills
  agents: .claude/agents
  hooks: .claude/hooks
  settings: .claude/settings.json
  instructions: CLAUDE.md
  mcp_config: .mcp.json
  # Retrieved context the agent reads but no reviewer diffs. Most repositories
  # have no such directory, and that inventories as empty rather than as safe.
  memory: .claude/memory
"""


def suggest_project_id(root: Path) -> str:
    """A starting id from the directory name, normalised to the id pattern.

    A suggestion, not a derivation: the value written to the file is what counts,
    and `agentsec init` puts it there for a human to keep or change.
    """
    slug = "".join(c if c.isalnum() else "-" for c in root.name.lower())
    slug = "-".join(part for part in slug.split("-") if part)[:64]
    if len(slug) < 3 or not slug[0].isalnum():
        return "agentsec-project"
    return slug
