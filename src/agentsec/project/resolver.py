"""The one place a path is turned into a path.

Everything that reads project content goes through here, because the alternative
is each caller inventing its own idea of what a root is. The CLI, the service and
any future MCP adapter share these two functions, so a traversal that is refused
in one is refused in all of them.

The order matters as much as the checks. The root is canonicalised *before*
anything under it is read, and every child is canonicalised *before* being
compared to the root — a check against the unresolved path would pass for a
symlink whose target is elsewhere, which is the interesting case rather than an
edge case.

`..`, absolute paths, drive letters, `~`, URLs and shell metacharacters are
refused rather than normalised. A manifest is reviewed by a human, and something
that has to be normalised before it is safe is something the reviewer read
differently from the machine.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

from agentsec.errors import ConfigError, UnsafePath

ENV_WORKSPACE = "AGENTSEC_WORKSPACE"

MAX_LOCATION = 200

#: Shell metacharacters, so a location that is really a command is refused where
#: it is written rather than wherever it would eventually be interpolated.
_METACHARACTERS = re.compile(r"[;|&`$<>\n\r\t\x00]|\$\(")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_WINDOWS_DRIVE = re.compile(r"^[a-z]:", re.I)


def resolve_root(candidate: str | Path | None = None) -> Path:
    """Canonicalise a project/workspace root, or explain why it is not one.

    ``strict=True`` so a root that does not exist fails here rather than
    producing a plausible-looking path that every later check then passes.
    """
    raw = Path(candidate or os.environ.get(ENV_WORKSPACE) or Path.cwd())
    try:
        root = raw.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ConfigError(f"workspace does not exist: {raw}", details={"error": str(exc)}) from exc
    if not root.is_dir():
        raise ConfigError(f"workspace is not a directory: {root}")
    return root


def check_location(location: str, *, field: str) -> PurePosixPath:
    """Validate a declared relative location without touching the filesystem.

    Split out from :func:`safe_child` so a manifest can be rejected on its
    contents alone — the acceptance rule is that a manifest naming
    ``../../secret`` is refused *and the target is never read*, which is only
    true if the refusal happens before any path is joined.
    """
    if not isinstance(location, str) or not location:
        raise UnsafePath(f"{field}: expected a non-empty relative location")
    if location != location.strip():
        raise UnsafePath(f"{field}: leading or trailing whitespace in {location!r}")
    if len(location) > MAX_LOCATION:
        raise UnsafePath(f"{field}: location longer than {MAX_LOCATION} characters")
    if _SCHEME.match(location):
        raise UnsafePath(
            f"{field}: {location!r} is a URL. The manifest names locations inside "
            f"this repository; endpoints are resolved from the target allowlist."
        )
    if _METACHARACTERS.search(location):
        raise UnsafePath(f"{field}: {location!r} contains shell metacharacters")
    if "\\" in location:
        raise UnsafePath(f"{field}: use '/' in {location!r}; the manifest is portable")
    if location.startswith("~"):
        raise UnsafePath(f"{field}: {location!r} is a home-relative path")
    if _WINDOWS_DRIVE.match(location):
        raise UnsafePath(f"{field}: {location!r} is an absolute path")

    pure = PurePosixPath(location)
    if pure.is_absolute():
        raise UnsafePath(f"{field}: {location!r} is an absolute path")
    if ".." in pure.parts:
        raise UnsafePath(
            f"{field}: {location!r} escapes the project. Locations are relative to "
            f"the project root and may not traverse above it."
        )
    return pure


def safe_child(root: Path, location: str, *, field: str = "location") -> Path:
    """Resolve a declared location under ``root``, refusing anything that leaves it.

    ``root`` must already be canonical (:func:`resolve_root`). The child is
    resolved non-strictly, so a location that does not exist yet still gets its
    symlink components followed — a dangling name is a discovery result, while a
    symlink pointing outside the repository is a refusal.
    """
    pure = check_location(location, field=field)
    resolved = (root / pure).resolve()
    if resolved != root and not resolved.is_relative_to(root):
        raise UnsafePath(
            f"{field}: {location!r} resolves outside the project root. A symlink "
            f"inside the repository does not extend it.",
            details={"root": str(root)},
        )
    return resolved


def relative_display(root: Path, path: Path) -> str:
    """Posix path relative to the root — the only form that leaves this package.

    Absolute paths are a property of one machine's checkout. Nothing downstream
    (an id, a report, a published resource) may depend on one, so the conversion
    happens once, here.
    """
    return path.resolve().relative_to(root).as_posix()
