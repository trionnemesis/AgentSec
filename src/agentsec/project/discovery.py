"""What is in this repository that AgentSec can look at.

Inventory, not judgement. Discovery answers "what surfaces exist and can we read
them", and nothing here decides whether any of them is any good — that is
`skill_eval`'s job ([ADR 0008](../../../docs/adr/0008-skill-assurance-bounded-context.md),
[#14](https://github.com/trionnemesis/AgentSec/issues/14)), which does not exist
yet. The `skill_assurance` block therefore reports `not_tested` in every case,
with a reason that distinguishes *nothing to test* from *nothing to test with*.

Three properties this module is built to hold:

**Nothing absolute leaves.** Every path in the output is relative to the project
root, so two checkouts of the same commit produce byte-identical results and an
id never encodes one machine's directory layout.

**Nothing is dropped in silence.** A surface that is unreadable, malformed,
unsupported or truncated becomes an entry in ``problems``. An empty inventory
that means "we could not look" must not read like one that means "there is
nothing there".

**Values stay behind.** Inventory records that a hook exists, that settings.json
configures three events, that `.mcp.json` names two servers. It does not copy
their contents. That keeps the whole document publishable without a second
redaction pass — the projection in `reporting/publish.py` exists because observed
data cannot be trusted to be safe, and the cheapest way not to need it here is
not to read the values in the first place.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentsec.errors import UnsafePath
from agentsec.project.manifest import MANIFEST_PATH, ProjectManifest, load_project
from agentsec.project.resolver import relative_display, safe_child

PROJECT_SCHEMA_VERSION = "1.0.0"

#: Per surface. A repository with more entries than this is not wrong, but the
#: listing stops and says so rather than walking an unbounded tree.
MAX_ENTRIES = 200

MAX_DESCRIPTION = 300

SKILL_FILE = "SKILL.md"


def _digest(path: Path) -> str:
    """Content digest, so drift is detectable without keeping the content."""
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()[:16]


@dataclass(frozen=True)
class Problem:
    """Something that could not be inventoried, stated rather than skipped."""

    path: str
    kind: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "kind": self.kind, "detail": self.detail}


@dataclass(frozen=True)
class Surface:
    """One discovered file or directory."""

    id: str
    kind: str
    path: str
    status: str = "supported"
    name: str = ""
    description: str = ""
    content_digest: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "path": self.path,
            "status": self.status,
        }
        if self.name:
            out["name"] = self.name
        if self.description:
            out["description"] = self.description
        if self.content_digest:
            out["content_digest"] = self.content_digest
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class Discovery:
    project_id: str
    name: str
    description: str
    skills: list[Surface] = field(default_factory=list)
    agents: list[Surface] = field(default_factory=list)
    hooks: list[Surface] = field(default_factory=list)
    settings: Surface | None = None
    instructions: Surface | None = None
    mcp_servers: list[Surface] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    static_posture_report: str | None = None
    """Manifest-declared location of a static scanner's report, if any (#25).
    Carried here rather than re-read from the manifest so the harness's static
    posture plane needs only one parse of `.agentsec/project.yaml`. Not part of
    `to_dict()`: this document is an inventory of surfaces, not of reports."""

    @property
    def supported_skills(self) -> list[Surface]:
        return [s for s in self.skills if s.status == "supported"]

    def skill_assurance(self) -> dict[str, str]:
        """Always ``not_tested`` today, with the reason spelled out.

        Two different absences, and rounding either of them up to a pass is the
        failure this project exists to prevent:

        * no skill surface at all — there is nothing to evaluate;
        * skills present — but no evaluator has been built to evaluate them.
        """
        if not self.supported_skills:
            return {
                "status": "not_tested",
                "reason": "no_skill_surface",
                "detail": "no readable SKILL.md was found under the declared skills location",
            }
        return {
            "status": "not_tested",
            "reason": "no_evaluator",
            "detail": (
                "skills were discovered but skill_eval is not built; see ADR 0008 and "
                "issue #14. Discovery is an inventory and never a verdict."
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROJECT_SCHEMA_VERSION,
            "kind": "project",
            "project": {
                "project_id": self.project_id,
                "name": self.name,
                "description": self.description,
                "manifest": MANIFEST_PATH,
            },
            "surfaces": {
                "skills": [s.to_dict() for s in self.skills],
                "agents": [s.to_dict() for s in self.agents],
                "hooks": [s.to_dict() for s in self.hooks],
                "settings": self.settings.to_dict() if self.settings else None,
                "instructions": self.instructions.to_dict() if self.instructions else None,
                "mcp_servers": [s.to_dict() for s in self.mcp_servers],
            },
            "skill_assurance": self.skill_assurance(),
            "problems": [p.to_dict() for p in self.problems],
            "counts": {
                "skills": len(self.skills),
                "supported_skills": len(self.supported_skills),
                "agents": len(self.agents),
                "hooks": len(self.hooks),
                "mcp_servers": len(self.mcp_servers),
                "problems": len(self.problems),
            },
        }


class _Walker:
    """Discovery state. One instance per call; not reused."""

    def __init__(self, root: Path, manifest: ProjectManifest) -> None:
        self.root = root
        self.manifest = manifest
        self.problems: list[Problem] = []
        self._ids: set[str] = set()

    # -- helpers ------------------------------------------------------------

    def note(self, path: str, kind: str, detail: str) -> None:
        self.problems.append(Problem(path=path, kind=kind, detail=detail))

    def locate(self, field_name: str) -> Path | None:
        """Resolve one declared surface, recording a refusal instead of raising.

        A manifest that names an unsafe location for one surface should still
        produce an inventory of the others, with the refusal visible. The
        manifest is validated on load, so this catches what only the filesystem
        can reveal: a symlink pointing out of the repository.
        """
        location = getattr(self.manifest.surfaces, field_name)
        try:
            return safe_child(self.root, location, field=field_name)
        except UnsafePath as exc:
            self.note(location, "unsafe_location", exc.message)
            return None

    def unique(self, candidate: str, path: str) -> str:
        if candidate not in self._ids:
            self._ids.add(candidate)
            return candidate
        suffix = hashlib.blake2s(path.encode("utf-8"), digest_size=3).hexdigest()
        resolved = f"{candidate}-{suffix}"
        self.note(path, "duplicate_id", f"id {candidate!r} already taken; using {resolved!r}")
        self._ids.add(resolved)
        return resolved

    def audit_symlinks(self, base: Path) -> set[str]:
        """State what the glob will quietly refuse to walk.

        ``Path.rglob`` does not follow directory symlinks, so a skills directory
        that is a link to somewhere else does not raise and does not appear — it
        is simply absent from the results. That is the silent drop this module
        exists to prevent, and no containment check further down can catch it,
        because nothing ever gets that far. So walk once without following, and
        report every link that leaves the project.
        """
        escaped: set[str] = set()
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            here = Path(dirpath)
            for entry in sorted([*dirnames, *filenames]):
                candidate = here / entry
                if not candidate.is_symlink():
                    continue
                rel = self.display_best_effort(candidate)
                try:
                    resolved = candidate.resolve()
                except OSError as exc:
                    self.note(rel, "unreadable", str(exc))
                    continue
                if not resolved.is_relative_to(self.root):
                    self.note(
                        rel,
                        "escapes_project",
                        "symlink resolves outside the project root; not read",
                    )
                    escaped.add(rel)
        return escaped

    def files_under(self, base: Path, pattern: str, *, label: str) -> list[Path]:
        """Sorted matches under ``base``, refusing anything that leaves the root.

        ``Path.rglob`` follows directory symlinks, so the containment check is
        repeated per result rather than assumed from the parent.
        """
        found: list[Path] = []
        for candidate in sorted(base.rglob(pattern)):
            try:
                resolved = candidate.resolve()
            except OSError as exc:
                self.note(self.display(candidate), "unreadable", str(exc))
                continue
            if not resolved.is_relative_to(self.root):
                self.note(
                    self.display_best_effort(candidate),
                    "escapes_project",
                    "symlink resolves outside the project root; not read",
                )
                continue
            if not resolved.is_file():
                continue
            found.append(resolved)
            if len(found) > MAX_ENTRIES:
                self.note(
                    self.display(base),
                    "truncated",
                    f"more than {MAX_ENTRIES} {label} entries; listing stopped",
                )
                return found[:MAX_ENTRIES]
        return found

    def display(self, path: Path) -> str:
        return relative_display(self.root, path)

    def display_best_effort(self, path: Path) -> str:
        """Relative form for a path that may not be under the root at all."""
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.name

    # -- surfaces -----------------------------------------------------------

    def skills(self) -> list[Surface]:
        base = self.locate("skills")
        if base is None or not base.is_dir():
            return []
        escaped = self.audit_symlinks(base)
        out: list[Surface] = []
        for path in self.files_under(base, SKILL_FILE, label="skill"):
            rel = self.display(path)
            skill_dir = path.parent
            stem = skill_dir.relative_to(base).as_posix().replace("/", ".") or skill_dir.name
            surface_id = self.unique(stem.lower(), rel)
            name, description, problem = self._frontmatter(path)
            if problem is not None:
                self.note(rel, "malformed", problem)
                out.append(
                    Surface(
                        id=surface_id, kind="skill", path=rel, status="malformed",
                        content_digest=_digest(path),
                    )
                )
                continue
            out.append(
                Surface(
                    id=surface_id, kind="skill", path=rel, name=name,
                    description=description, content_digest=_digest(path),
                )
            )
        self._note_directories_without_skill_file(base, {s.path for s in out}, escaped)
        return sorted(out, key=lambda s: s.id)

    def _note_directories_without_skill_file(
        self, base: Path, found: set[str], escaped: set[str]
    ) -> None:
        """A directory that looks like a skill but has no ``SKILL.md``.

        Silence here would report a repository as having no skills when what it
        has is a skill in a format this version does not read.
        """
        covered = {Path(p).parent.as_posix() for p in found}
        for child in sorted(base.iterdir()):
            if not child.is_dir():
                continue
            rel = self.display_best_effort(child)
            if rel in covered or rel in escaped:
                # Already inventoried, or already refused for leaving the project.
                continue
            if any(child.rglob(SKILL_FILE)):
                continue
            self.note(rel, "unsupported", f"no {SKILL_FILE}; not a Claude Skill this version reads")

    def _frontmatter(self, path: Path) -> tuple[str, str, str | None]:
        """``name`` and ``description`` from YAML frontmatter.

        Authored in-repo and reviewed, so it is declared configuration and may be
        carried as written — capped, because a length is not a review.
        """
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return "", "", f"cannot read: {exc}"
        if not text.startswith("---"):
            return "", "", "no YAML frontmatter"
        _, _, rest = text.partition("---")
        block, sep, _ = rest.partition("\n---")
        if not sep:
            return "", "", "unterminated YAML frontmatter"
        try:
            data = yaml.safe_load(block)
        except yaml.YAMLError as exc:
            return "", "", f"invalid frontmatter YAML: {exc}"
        if not isinstance(data, dict):
            return "", "", "frontmatter is not a mapping"
        name = str(data.get("name", ""))[:120]
        description = str(data.get("description", ""))[:MAX_DESCRIPTION]
        if not name:
            return "", description, "frontmatter has no 'name'"
        return name, description, None

    def agents(self) -> list[Surface]:
        base = self.locate("agents")
        if base is None or not base.is_dir():
            return []
        self.audit_symlinks(base)
        out: list[Surface] = []
        for path in self.files_under(base, "*.md", label="agent"):
            rel = self.display(path)
            stem = path.relative_to(base).with_suffix("").as_posix().replace("/", ".")
            name, description, problem = self._frontmatter(path)
            status = "supported"
            if problem is not None:
                self.note(rel, "malformed", problem)
                status = "malformed"
            out.append(
                Surface(
                    id=self.unique(stem.lower(), rel), kind="agent", path=rel, status=status,
                    name=name, description=description, content_digest=_digest(path),
                )
            )
        return sorted(out, key=lambda s: s.id)

    def hooks(self) -> list[Surface]:
        base = self.locate("hooks")
        if base is None or not base.is_dir():
            return []
        self.audit_symlinks(base)
        out: list[Surface] = []
        for path in self.files_under(base, "*", label="hook"):
            rel = self.display(path)
            stem = path.relative_to(base).with_suffix("").as_posix().replace("/", ".")
            out.append(
                Surface(
                    id=self.unique(stem.lower(), rel), kind="hook", path=rel,
                    content_digest=_digest(path),
                    detail={"executable": path.stat().st_mode & 0o111 != 0},
                )
            )
        return sorted(out, key=lambda s: s.id)

    def settings(self) -> Surface | None:
        path = self.locate("settings")
        if path is None or not path.is_file():
            return None
        rel = self.display(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.note(rel, "malformed", f"cannot parse settings: {exc}")
            return Surface(id="settings", kind="settings", path=rel, status="malformed")
        if not isinstance(data, dict):
            self.note(rel, "malformed", "settings is not a mapping")
            return Surface(id="settings", kind="settings", path=rel, status="malformed")

        hooks = data.get("hooks")
        permissions = data.get("permissions")
        detail: dict[str, Any] = {
            # Event names and counts. The rules themselves name internal tools
            # and paths, and an inventory does not need them to be useful.
            "hook_events": sorted(hooks) if isinstance(hooks, dict) else [],
            "permission_rules": {
                key: len(value)
                for key, value in sorted((permissions or {}).items())
                if isinstance(value, list)
            }
            if isinstance(permissions, dict)
            else {},
        }
        return Surface(
            id="settings", kind="settings", path=rel, content_digest=_digest(path), detail=detail
        )

    def instructions(self) -> Surface | None:
        path = self.locate("instructions")
        if path is None or not path.is_file():
            return None
        rel = self.display(path)
        try:
            lines = len(path.read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeDecodeError) as exc:
            self.note(rel, "unreadable", str(exc))
            return Surface(id="instructions", kind="instructions", path=rel, status="malformed")
        return Surface(
            id="instructions", kind="instructions", path=rel,
            content_digest=_digest(path), detail={"lines": lines},
        )

    def mcp_servers(self) -> list[Surface]:
        """Server names from the project MCP config — names, never values.

        `.mcp.json` carries an ``env`` block, and in some repositories that block
        is where a token ends up. Reading the keys and not the values keeps a
        mistake in someone else's repository from becoming a leak in this one's
        inventory.
        """
        path = self.locate("mcp_config")
        if path is None or not path.is_file():
            return []
        rel = self.display(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.note(rel, "malformed", f"cannot parse MCP config: {exc}")
            return []
        servers = data.get("mcpServers") if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            self.note(rel, "malformed", "no 'mcpServers' mapping")
            return []
        out: list[Surface] = []
        for server_name, config in sorted(servers.items()):
            env = config.get("env") if isinstance(config, dict) else None
            out.append(
                Surface(
                    id=self.unique(f"mcp.{server_name}".lower(), rel),
                    kind="mcp_server",
                    path=rel,
                    name=str(server_name)[:120],
                    detail={"env_keys": sorted(env) if isinstance(env, dict) else []},
                )
            )
        return out


def discover(workspace: str | Path | None = None) -> Discovery:
    """Inventory the selected project.

    The only argument is which root, and it comes from the process boundary — the
    directory the harness was started in — not from a caller naming a path.
    """
    root, manifest = load_project(workspace)
    walker = _Walker(root, manifest)
    result = Discovery(
        project_id=manifest.project_id,
        name=manifest.name,
        description=manifest.description,
        skills=walker.skills(),
        agents=walker.agents(),
        hooks=walker.hooks(),
        settings=walker.settings(),
        instructions=walker.instructions(),
        mcp_servers=walker.mcp_servers(),
        static_posture_report=manifest.static_posture_report,
    )
    result.problems = sorted(walker.problems, key=lambda p: (p.kind, p.path))
    return result
