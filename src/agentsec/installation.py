"""Read installation identity from installer metadata, never from the caller's Git tree."""

from __future__ import annotations

import json
import re
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from agentsec.errors import ConfigError


def package_identity(expected_commit: str | None = None) -> tuple[str | None, str | None]:
    """PEP 610 records the resolved commit for a non-editable VCS installation.

    A version alone, a caller-provided environment variable, and an editable
    checkout are not evidence of the installed source commit. Legacy/source
    installations may have unknown identity; the external gate requires an
    exact match before any scenario is loaded or executed.
    """
    if expected_commit is not None and not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise ConfigError("版本格式錯誤 / AgentSec requires a full lowercase commit SHA")
    try:
        dist = distribution("agentsec")
    except PackageNotFoundError:
        if expected_commit is not None:
            raise ConfigError(
                "找不到安裝資訊 / AgentSec installation metadata is missing"
            ) from None
        return None, None

    commit: str | None = None
    # Ensure metadata describes the code actually imported, not another copy on sys.path.
    installed_module = Path(str(dist.locate_file("agentsec/installation.py"))).resolve()
    if installed_module == Path(__file__).resolve():
        try:
            direct = json.loads(dist.read_text("direct_url.json") or "{}")
            vcs = direct.get("vcs_info", {})
            candidate = vcs.get("commit_id")
            if (
                vcs.get("vcs") == "git"
                and not direct.get("dir_info", {}).get("editable")
                and isinstance(candidate, str)
                and re.fullmatch(r"[0-9a-f]{40}", candidate)
            ):
                commit = candidate
        except (ValueError, AttributeError, TypeError):
            pass
    if expected_commit is not None and commit != expected_commit:
        raise ConfigError(
            "安裝來源不符 / Installed AgentSec commit does not match the required SHA"
        )
    version = dist.version if installed_module == Path(__file__).resolve() else None
    return version, commit
