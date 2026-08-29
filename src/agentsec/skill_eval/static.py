"""Read-only, deterministic static Skill Assurance (ADR 0008 Phase 0).

This module validates reviewed structure and byte integrity.  It does not run a
skill, judge its semantic quality, create a verdict, write a database, or update
the dashboard. A ``valid`` result means only that the current workspace bundle
matches its reviewed manifest and that declared asset tokens plus parsed Markdown
link destinations stay inside that bundle. It is not a scan of prose or bare URLs.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final, Literal

import yaml

from agentsec.project import discover, load_project, resolve_root
from agentsec.skill_eval.manifest import (
    MAX_MANIFEST_BYTES,
    ManifestProblem,
    SkillEvalSuite,
    StrictLoader,
    parse_suite,
    suite_directory,
)

REPORT_API_VERSION: Final = "agentsec.dev/v1alpha1"
REPORT_KIND: Final = "SkillEvalStaticReport"

MAX_ARTIFACT_BYTES: Final = 1024 * 1024
MAX_BUNDLE_ENTRIES: Final = 128
MAX_BUNDLE_DEPTH: Final = 12
MAX_FRONTMATTER_BYTES: Final = 16 * 1024
MAX_SUITE_ENTRIES: Final = 64
MAX_SKILL_ROOT_ENTRIES: Final = MAX_SUITE_ENTRIES * (MAX_BUNDLE_ENTRIES + 1)
MAX_SKILL_ROOT_DEPTH: Final = 128

StaticStatus = Literal["valid", "invalid", "not_tested", "error"]

_SAFE_PATH = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_CONTROL_OR_BIDI = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
    "\u061c\u200b-\u200f\u2028-\u202e\u2060\u2066-\u2069\ufeff"
    "\U000e0000-\U000e007f]"
)

# The router uses ordinary Markdown links. Reference definitions, autolinks and
# raw HTML destinations are also inspected. The fallback delimiter patterns
# catch escaped or nested labels our deliberately small extractor does not parse
# as CommonMark. This validates declared asset tokens and parsed destinations;
# it is not a semantic scan of prose, code spans, or bare URLs.
_INLINE_LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(?:<([^>\n]+)>|([^\s)\n]+))")
_REFERENCE_DEF = re.compile(r"(?m)^\s*\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|([^\s\n]+))")
_INLINE_LINK_FALLBACK = re.compile(r"\]\(\s*(?:<([^>\n]+)>|([^\s)\n]+))")
_REFERENCE_DEF_FALLBACK = re.compile(r"(?m)\]:\s*(?:<([^>\n]+)>|([^\s\n]+))")
_AUTOLINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]*:[^>\n]+)>")
_HTML_DEST = re.compile(
    r"(?i)\b(?:href|src)\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s>]+))"
)
_ASSET_TOKEN = re.compile(
    r"(?<![A-Za-z0-9._/-])((?:references|scripts)/[A-Za-z0-9._/-]+)"
)


@dataclass(frozen=True, order=True)
class StaticIssue:
    code: str
    path: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path}


@dataclass
class StaticSkillResult:
    skill_id: str
    status: StaticStatus
    suite_id: str | None = None
    entrypoint: str | None = None
    issues: list[StaticIssue] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "skill_id": self.skill_id,
            "status": self.status,
            "issues": [issue.to_dict() for issue in sorted(set(self.issues))],
        }
        if self.suite_id is not None:
            out["suite_id"] = self.suite_id
        if self.entrypoint is not None:
            out["entrypoint"] = self.entrypoint
        return out


@dataclass
class StaticReport:
    project_id: str
    status: StaticStatus
    skills: list[StaticSkillResult] = field(default_factory=list)
    issues: list[StaticIssue] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if self.status == "valid":
            return 0
        if self.status == "invalid":
            return 1
        return 2

    def to_dict(self) -> dict[str, object]:
        counts = {name: 0 for name in ("valid", "invalid", "not_tested", "error")}
        for result in self.skills:
            counts[result.status] += 1
        return {
            "apiVersion": REPORT_API_VERSION,
            "kind": REPORT_KIND,
            "profile": "static",
            "project_id": self.project_id,
            "status": self.status,
            "counts": counts,
            "skills": [item.to_dict() for item in sorted(self.skills, key=lambda s: s.skill_id)],
            "issues": [issue.to_dict() for issue in sorted(set(self.issues))],
        }


class FileProblem(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _relative_path(value: str) -> PurePosixPath:
    """Require one canonical, portable spelling before touching the filesystem."""
    if not isinstance(value, str) or not value:
        raise FileProblem("path_unsafe")
    if len(value) > 240 or not value.isascii():
        raise FileProblem("path_unsafe")
    if value != value.strip() or _CONTROL_OR_BIDI.search(value):
        raise FileProblem("path_unsafe")
    if value.startswith(("/", "~")) or _WINDOWS_DRIVE.match(value):
        raise FileProblem("path_unsafe")
    if _SCHEME.match(value) or "\\" in value or "%" in value:
        raise FileProblem("path_unsafe")
    if not _SAFE_PATH.fullmatch(value):
        raise FileProblem("path_unsafe")
    pure = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise FileProblem("path_unsafe")
    if pure.as_posix() != value:
        raise FileProblem("path_unsafe")
    return pure


def _component_path(root: Path, relative: str) -> Path:
    pure = _relative_path(relative)
    current = root
    for part in pure.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as exc:
            raise FileProblem("file_missing") from exc
        except OSError as exc:
            raise FileProblem("file_unreadable") from exc
        if stat.S_ISLNK(mode):
            raise FileProblem("symlink_forbidden")
    return current


def _read_regular(root: Path, relative: str, *, limit: int) -> bytes:
    """Open every component relative to an anchored root descriptor.

    ``lstat`` followed by an absolute ``open`` leaves a parent-component race:
    a same-user process can replace a checked directory with a symlink between
    the calls.  Descriptor-relative ``openat`` with ``O_NOFOLLOW`` holds each
    directory while the next component is opened, including the final file.
    """
    pure = _relative_path(relative)
    if (
        os.open not in os.supports_dir_fd
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise FileProblem("platform_unsupported")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        parent_fd = os.open(root, directory_flags)
    except NotImplementedError as exc:  # pragma: no cover - platform capability gate
        raise FileProblem("platform_unsupported") from exc
    except OSError as exc:  # pragma: no cover - resolve_root already checked it
        raise FileProblem("file_unreadable") from exc
    try:
        for component in pure.parts[:-1]:
            try:
                next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            except FileNotFoundError as exc:
                raise FileProblem("file_missing") from exc
            except NotImplementedError as exc:  # pragma: no cover - platform dependent
                raise FileProblem("platform_unsupported") from exc
            except OSError as exc:
                raise FileProblem("path_component_invalid") from exc
            os.close(parent_fd)
            parent_fd = next_fd
        try:
            descriptor = os.open(pure.parts[-1], file_flags, dir_fd=parent_fd)
        except FileNotFoundError as exc:
            raise FileProblem("file_missing") from exc
        except NotImplementedError as exc:  # pragma: no cover - platform dependent
            raise FileProblem("platform_unsupported") from exc
        except OSError as exc:
            raise FileProblem("file_unreadable") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise FileProblem("nonregular_forbidden")
            if before.st_size > limit:
                raise FileProblem("file_too_large")

            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > limit:
                raise FileProblem("file_too_large")

            after = os.fstat(descriptor)
            identity_before = (before.st_dev, before.st_ino)
            identity_after = (after.st_dev, after.st_ino)
            if (
                identity_before != identity_after
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or len(data) != after.st_size
            ):
                raise FileProblem("file_changed_during_read")
            return data
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _walk_bundle(
    root: Path, skill_dir: str, *, allowed_directories: set[str]
) -> tuple[set[str], list[StaticIssue]]:
    """Enumerate every entry without following links, including hidden entries.

    CI and local validation assume an isolated checkout with no concurrent
    same-user writer. File reads remain descriptor-anchored and reject a change
    during read; concurrent directory mutation can make inventory fail or become
    inconsistent, but cannot authorise an escaping read.
    """
    issues: list[StaticIssue] = []
    try:
        base = _component_path(root, skill_dir)
    except FileProblem as exc:
        return set(), [StaticIssue(exc.code, skill_dir)]
    try:
        if not base.is_dir():
            return set(), [StaticIssue("skill_directory_missing", skill_dir)]
    except OSError:
        return set(), [StaticIssue("file_unreadable", skill_dir)]

    files: set[str] = set()
    seen = 0
    overflow = False

    def visit(directory: Path, relative: PurePosixPath, depth: int) -> None:
        nonlocal overflow, seen
        if overflow:
            return
        if depth > MAX_BUNDLE_DEPTH:
            issues.append(StaticIssue("bundle_too_deep", relative.as_posix()))
            return
        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    seen += 1
                    if seen > MAX_BUNDLE_ENTRIES:
                        overflow = True
                        return
                    entries.append(entry)
        except OSError:
            issues.append(StaticIssue("file_unreadable", relative.as_posix()))
            return
        entries.sort(key=lambda item: item.name)
        for entry in entries:
            if overflow:
                return
            child_rel = relative / entry.name
            display = child_rel.as_posix()
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError:
                issues.append(StaticIssue("file_unreadable", display))
                continue
            if stat.S_ISLNK(mode):
                issues.append(StaticIssue("symlink_forbidden", display))
            elif stat.S_ISDIR(mode):
                if display not in allowed_directories:
                    issues.append(StaticIssue("asset_directory_unpinned", display))
                visit(Path(entry.path), child_rel, depth + 1)
            elif stat.S_ISREG(mode):
                files.add(display)
            else:
                issues.append(StaticIssue("nonregular_forbidden", display))

    visit(base, PurePosixPath(skill_dir), 0)
    if overflow:
        return set(), [StaticIssue("bundle_too_many_entries", skill_dir)]
    return files, issues


def _audit_skill_root(root: Path, skills_base: str) -> list[StaticIssue]:
    """Reject aliases anywhere in the declared skill-loading tree.

    Per-suite bundle walks cannot see a sibling directory symlink. Discovery
    deliberately resolves in-repository aliases, so such a link could otherwise
    expose another ``SKILL.md`` while the static report covered only the pinned
    directory. Audit the complete declared root first and never follow a link.

    As with :func:`_walk_bundle`, this inventory assumes an isolated checkout
    without a concurrent same-user writer. Overflow discards the native-order
    subset so the failure report remains stable across filesystems.
    """
    canonical_base = PurePosixPath(skills_base).as_posix()
    if canonical_base == ".":
        base = root
        base_relative = PurePosixPath()
        display_base = "."
    else:
        try:
            base = _component_path(root, canonical_base)
        except FileProblem as exc:
            if exc.code == "file_missing":
                return []
            return [StaticIssue(exc.code, canonical_base)]
        base_relative = PurePosixPath(canonical_base)
        display_base = canonical_base

    try:
        base_mode = base.lstat().st_mode
    except FileNotFoundError:
        return []
    except OSError:
        return [StaticIssue("file_unreadable", display_base)]
    if stat.S_ISLNK(base_mode):
        return [StaticIssue("symlink_forbidden", display_base)]
    if not stat.S_ISDIR(base_mode):
        return [StaticIssue("nonregular_forbidden", display_base)]

    issues: list[StaticIssue] = []
    seen = 0
    overflow = False

    def visit(directory: Path, relative: PurePosixPath, depth: int) -> None:
        nonlocal overflow, seen
        if overflow:
            return
        if depth > MAX_SKILL_ROOT_DEPTH:
            issues.append(StaticIssue("skill_root_too_deep", relative.as_posix()))
            return
        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    seen += 1
                    if seen > MAX_SKILL_ROOT_ENTRIES:
                        overflow = True
                        return
                    entries.append(entry)
        except OSError:
            issues.append(StaticIssue("file_unreadable", relative.as_posix() or display_base))
            return
        entries.sort(key=lambda item: item.name)
        for entry in entries:
            if overflow:
                return
            child_rel = relative / entry.name
            display = child_rel.as_posix()
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError:
                issues.append(StaticIssue("file_unreadable", display))
                continue
            if stat.S_ISLNK(mode):
                issues.append(StaticIssue("symlink_forbidden", display))
            elif stat.S_ISDIR(mode):
                visit(Path(entry.path), child_rel, depth + 1)
            elif not stat.S_ISREG(mode):
                issues.append(StaticIssue("nonregular_forbidden", display))

    visit(base, base_relative, 0)
    if overflow:
        return [StaticIssue("skill_root_too_many_entries", display_base)]
    return issues


def _frontmatter(data: bytes, path: str) -> tuple[str | None, list[StaticIssue]]:
    issues: list[StaticIssue] = []
    if data.startswith(b"\xef\xbb\xbf"):
        return None, [StaticIssue("frontmatter_bom_forbidden", path)]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, [StaticIssue("frontmatter_not_utf8", path)]
    if _CONTROL_OR_BIDI.search(text):
        return None, [StaticIssue("frontmatter_control_character", path)]
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return None, [StaticIssue("frontmatter_missing", path)]
    try:
        end = lines.index("---", 1)
    except ValueError:
        return None, [StaticIssue("frontmatter_unterminated", path)]
    block = "\n".join(lines[1:end])
    if len(block.encode("utf-8")) > MAX_FRONTMATTER_BYTES:
        return None, [StaticIssue("frontmatter_too_large", path)]
    try:
        # Reuse the suite's ambiguity checks by parsing a tiny synthetic suite is
        # wrong semantically; perform the same token constraints directly here.
        from agentsec.skill_eval.manifest import _check_shape, _reject_ambiguous_yaml

        _reject_ambiguous_yaml(block)
        document = yaml.load(block, Loader=StrictLoader)  # noqa: S506
        _check_shape(document)
    except (ManifestProblem, yaml.YAMLError, RecursionError):
        return None, [StaticIssue("frontmatter_yaml_invalid", path)]
    if not isinstance(document, dict):
        return None, [StaticIssue("frontmatter_not_mapping", path)]
    if set(document) != {"name", "description"}:
        issues.append(StaticIssue("frontmatter_fields_invalid", path))
    name = document.get("name")
    description = document.get("description")
    if not isinstance(name, str) or not name or len(name) > 120:
        issues.append(StaticIssue("frontmatter_name_invalid", path))
        name = None
    if not isinstance(description, str) or not description or len(description) > 2000:
        issues.append(StaticIssue("frontmatter_description_invalid", path))
    return name, issues


def _destinations(text: str) -> list[str]:
    found: list[str] = []
    for pattern in (
        _INLINE_LINK,
        _REFERENCE_DEF,
        _INLINE_LINK_FALLBACK,
        _REFERENCE_DEF_FALLBACK,
    ):
        for match in pattern.finditer(text):
            destination = match.group(1) or match.group(2)
            if destination:
                found.append(destination)
    found.extend(match.group(1) for match in _AUTOLINK.finditer(text))
    for match in _HTML_DEST.finditer(text):
        found.append(next(group for group in match.groups() if group is not None))
    return found


def _resolve_link(source: str, destination: str) -> str | None:
    if destination.startswith("#"):
        return None
    target = destination.split("#", 1)[0]
    if not target:
        return None
    pure = _relative_path(target)
    combined = PurePosixPath(source).parent / pure
    # ``target`` itself cannot contain dot segments, so this is already
    # canonical.  Validate the combined spelling as a second invariant.
    return _relative_path(combined.as_posix()).as_posix()


def _scan_links(
    markdown: dict[str, bytes], pinned: set[str], skill_dir: PurePosixPath
) -> tuple[set[str], set[str], list[StaticIssue]]:
    issues: list[StaticIssue] = []
    router_refs: set[str] = set()
    router_scripts: set[str] = set()
    entrypoint = (skill_dir / "SKILL.md").as_posix()

    for path, data in sorted(markdown.items()):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            issues.append(StaticIssue("markdown_not_utf8", path))
            continue
        if _CONTROL_OR_BIDI.search(text):
            issues.append(StaticIssue("markdown_control_character", path))
            continue

        for destination in _destinations(text):
            try:
                resolved = _resolve_link(path, destination)
            except FileProblem:
                issues.append(StaticIssue("dangerous_reference", path))
                continue
            if resolved is None:
                continue
            if resolved not in pinned:
                issues.append(StaticIssue("reference_unpinned", path))
                continue
            if path == entrypoint:
                try:
                    within_skill = PurePosixPath(resolved).relative_to(skill_dir).as_posix()
                except ValueError:
                    issues.append(StaticIssue("reference_outside_skill", path))
                    continue
                if within_skill.startswith("references/"):
                    router_refs.add(resolved)
                elif within_skill.startswith("scripts/"):
                    router_scripts.add(resolved)

        token_paths: set[str] = set()
        for match in _ASSET_TOKEN.finditer(text):
            token = match.group(1).rstrip(".,;:)")
            try:
                token_paths.add(_relative_path((skill_dir / token).as_posix()).as_posix())
            except FileProblem:
                issues.append(StaticIssue("dangerous_reference", path))
        if token_paths - pinned:
            issues.append(StaticIssue("asset_token_unpinned", path))
        if path == entrypoint:
            linked = router_refs | router_scripts
            if token_paths != linked:
                issues.append(StaticIssue("router_asset_not_linked", path))

    return router_refs, router_scripts, issues


def _under(child: PurePosixPath, parent: PurePosixPath) -> bool:
    return child != parent and child.is_relative_to(parent)


def _validate_suite(
    root: Path,
    suite: SkillEvalSuite,
    *,
    discovered_path: str,
    discovered_status: str,
    skills_base: str,
) -> StaticSkillResult:
    result = StaticSkillResult(
        skill_id=suite.skill_id,
        suite_id=suite.suite_id,
        entrypoint=suite.entrypoint.path,
        status="valid",
    )
    issues = result.issues

    pins = [suite.entrypoint, *suite.references, *suite.scripts]
    for pin in pins:
        try:
            _relative_path(pin.path)
        except FileProblem as exc:
            issues.append(StaticIssue(exc.code, pin.path if isinstance(pin.path, str) else "."))

    if issues:
        result.status = "error"
        return result

    entry = PurePosixPath(suite.entrypoint.path)
    skill_dir = entry.parent
    declared_base = PurePosixPath(skills_base)
    if entry.name != "SKILL.md" or not _under(entry, declared_base):
        issues.append(StaticIssue("entrypoint_invalid", suite.entrypoint.path))
    if suite.entrypoint.path != discovered_path:
        issues.append(StaticIssue("entrypoint_not_discovered", suite.entrypoint.path))
    reference_root = skill_dir / "references"
    script_root = skill_dir / "scripts"
    for pin in suite.references:
        path = PurePosixPath(pin.path)
        if not _under(path, reference_root) or path.suffix.lower() != ".md":
            issues.append(StaticIssue("reference_location_invalid", pin.path))
    for pin in suite.scripts:
        path = PurePosixPath(pin.path)
        if not _under(path, script_root):
            issues.append(StaticIssue("script_location_invalid", pin.path))

    # The suite is not authorised to read until every locator has been bound to
    # the discovered skill and its role-specific subtree.  A later digest check
    # must never turn an invalid locator into a repository-file hash oracle.
    if issues:
        result.status = "invalid"
        return result

    if discovered_status != "supported":
        # Exact discovery still binds the read to this skill. Continue so the
        # stricter frontmatter parser can return the concrete static failure.
        issues.append(StaticIssue("skill_surface_unsupported", discovered_path))

    expected = {pin.path for pin in pins}
    allowed_directories = {skill_dir.as_posix()}
    for pinned_path in expected:
        parent = PurePosixPath(pinned_path).parent
        while parent != skill_dir and parent.is_relative_to(skill_dir):
            allowed_directories.add(parent.as_posix())
            parent = parent.parent
    actual, walk_issues = _walk_bundle(
        root, skill_dir.as_posix(), allowed_directories=allowed_directories
    )
    issues.extend(walk_issues)
    if any(issue.code == "bundle_too_many_entries" for issue in walk_issues):
        result.status = "error"
        return result
    for missing in sorted(expected - actual):
        issues.append(StaticIssue("asset_missing", missing))
    for extra in sorted(actual - expected):
        issues.append(StaticIssue("asset_unpinned", extra))

    buffers: dict[str, bytes] = {}
    for pin in pins:
        try:
            data = _read_regular(root, pin.path, limit=MAX_ARTIFACT_BYTES)
        except FileProblem as exc:
            issues.append(StaticIssue(exc.code, pin.path))
            continue
        buffers[pin.path] = data
        if _digest(data) != pin.digest:
            issues.append(StaticIssue("digest_mismatch", pin.path))

    entry_data = buffers.get(suite.entrypoint.path)
    if entry_data is not None:
        name, frontmatter_issues = _frontmatter(entry_data, suite.entrypoint.path)
        issues.extend(frontmatter_issues)
        if name is not None and name != skill_dir.name:
            issues.append(StaticIssue("frontmatter_name_mismatch", suite.entrypoint.path))

    markdown = {
        path: data
        for path, data in buffers.items()
        if path == suite.entrypoint.path or path in {pin.path for pin in suite.references}
    }
    router_refs, router_scripts, link_issues = _scan_links(markdown, expected, skill_dir)
    issues.extend(link_issues)
    declared_refs = {pin.path for pin in suite.references}
    declared_scripts = {pin.path for pin in suite.scripts}
    if router_refs != declared_refs:
        issues.append(StaticIssue("router_references_mismatch", suite.entrypoint.path))
    if router_scripts != declared_scripts:
        issues.append(StaticIssue("router_scripts_mismatch", suite.entrypoint.path))

    if issues:
        # Structural problems are deterministic invalidity.  Unsafe/unreadable
        # filesystem state is an error because no content conclusion was made.
        error_codes = {
            "path_unsafe",
            "symlink_forbidden",
            "nonregular_forbidden",
            "file_unreadable",
            "path_component_invalid",
            "platform_unsupported",
            "file_changed_during_read",
            "bundle_too_many_entries",
            "bundle_too_deep",
        }
        result.status = "error" if any(i.code in error_codes for i in issues) else "invalid"
    return result


def _overall(skills: list[StaticSkillResult], issues: list[StaticIssue]) -> StaticStatus:
    infrastructure_issues = [
        issue for issue in issues if issue.code != "skill_surface_not_tested"
    ]
    if infrastructure_issues or any(skill.status == "error" for skill in skills):
        return "error"
    if any(skill.status == "invalid" for skill in skills):
        return "invalid"
    if issues or not skills or any(skill.status == "not_tested" for skill in skills):
        return "not_tested"
    return "valid"


def validate_static(workspace: str | Path | None = None) -> StaticReport:
    """Validate every reviewed static suite in the selected workspace.

    ``workspace`` is the same CLI/process-boundary selection used by the rest of
    AgentSec.  There is no suite path argument: suites are loaded only from the
    reviewed ``.agentsec/skill_eval/*.yaml`` directory.
    """
    root = resolve_root(workspace)
    _, project_manifest = load_project(root)
    skill_root_issues = _audit_skill_root(root, project_manifest.surfaces.skills)
    if skill_root_issues:
        return StaticReport(
            project_id=project_manifest.project_id,
            status="error",
            skills=[],
            issues=skill_root_issues,
        )
    inventory = discover(root)
    discovered = {surface.id: surface for surface in inventory.skills}
    report_issues: list[StaticIssue] = []
    loaded: list[tuple[SkillEvalSuite, str]] = []

    directory = suite_directory(root)
    suite_dir_rel = ".agentsec/skill_eval"
    try:
        suite_dir_mode = directory.lstat().st_mode
    except FileNotFoundError:
        suite_dir_mode = None
    except OSError:
        suite_dir_mode = 0
        report_issues.append(StaticIssue("file_unreadable", suite_dir_rel))
    if suite_dir_mode is not None:
        if stat.S_ISLNK(suite_dir_mode):
            report_issues.append(StaticIssue("symlink_forbidden", suite_dir_rel))
            suite_dir_mode = 0
        elif not stat.S_ISDIR(suite_dir_mode):
            report_issues.append(StaticIssue("nonregular_forbidden", suite_dir_rel))
            suite_dir_mode = 0
    if suite_dir_mode:
        suite_overflow = False
        try:
            _component_path(root, suite_dir_rel)
            entries: list[os.DirEntry[str]] = []
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    if len(entries) >= MAX_SUITE_ENTRIES:
                        suite_overflow = True
                        entries = []
                        break
                    entries.append(entry)
            entries.sort(key=lambda item: item.name)
        except FileProblem as exc:
            entries = []
            report_issues.append(StaticIssue(exc.code, suite_dir_rel))
        except OSError:
            entries = []
            report_issues.append(StaticIssue("file_unreadable", suite_dir_rel))
        if suite_overflow:
            return StaticReport(
                project_id=inventory.project_id,
                status="error",
                skills=[],
                issues=[StaticIssue("suite_too_many_entries", suite_dir_rel)],
            )
        for entry in entries:
            relative = f"{suite_dir_rel}/{entry.name}"
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError:
                report_issues.append(StaticIssue("file_unreadable", relative))
                continue
            if stat.S_ISLNK(mode):
                report_issues.append(StaticIssue("symlink_forbidden", relative))
                continue
            if stat.S_ISDIR(mode):
                report_issues.append(StaticIssue("suite_entry_unsupported", relative))
                continue
            if not stat.S_ISREG(mode):
                report_issues.append(StaticIssue("nonregular_forbidden", relative))
                continue
            if not entry.name.endswith(".yaml"):
                report_issues.append(StaticIssue("suite_format_unsupported", relative))
                continue
            try:
                body = _read_regular(root, relative, limit=MAX_MANIFEST_BYTES)
                loaded.append((parse_suite(body), relative))
            except FileProblem as exc:
                report_issues.append(StaticIssue(exc.code, relative))
            except ManifestProblem as exc:
                report_issues.append(StaticIssue(exc.code, relative))

    suite_ids: set[str] = set()
    skill_ids: set[str] = set()
    accepted: list[SkillEvalSuite] = []
    for suite, source in loaded:
        if suite.suite_id in suite_ids:
            report_issues.append(StaticIssue("suite_id_duplicate", source))
            continue
        if suite.skill_id in skill_ids:
            report_issues.append(StaticIssue("skill_suite_duplicate", source))
            continue
        suite_ids.add(suite.suite_id)
        skill_ids.add(suite.skill_id)
        accepted.append(suite)

    skill_results: list[StaticSkillResult] = []
    for suite in sorted(accepted, key=lambda item: item.skill_id):
        surface = discovered.get(suite.skill_id)
        if surface is None:
            skill_results.append(
                StaticSkillResult(
                    skill_id=suite.skill_id,
                    suite_id=suite.suite_id,
                    entrypoint=suite.entrypoint.path,
                    status="invalid",
                    issues=[StaticIssue("skill_id_not_discovered", suite.entrypoint.path)],
                )
            )
            continue
        skill_results.append(
            _validate_suite(
                root,
                suite,
                discovered_path=surface.path,
                discovered_status=surface.status,
                skills_base=project_manifest.surfaces.skills,
            )
        )

    for skill_id, surface in sorted(discovered.items()):
        if skill_id not in skill_ids:
            skill_results.append(
                StaticSkillResult(
                    skill_id=skill_id,
                    entrypoint=surface.path,
                    status="not_tested",
                    issues=[StaticIssue("static_suite_missing", surface.path)],
                )
            )

    skills_prefix = project_manifest.surfaces.skills.rstrip("/") + "/"
    discovered_paths = {surface.path for surface in inventory.skills}
    for problem in inventory.problems:
        under_skills = (
            problem.path == project_manifest.surfaces.skills
            or problem.path.startswith(skills_prefix)
        )
        if under_skills and problem.path not in discovered_paths:
            report_issues.append(StaticIssue("skill_surface_not_tested", problem.path))

    status = _overall(skill_results, report_issues)
    return StaticReport(
        project_id=inventory.project_id,
        status=status,
        skills=skill_results,
        issues=report_issues,
    )
