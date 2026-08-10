"""Selected-project resolution and surface discovery.

Directory selection is a process-boundary and file-review concern, never a tool
argument: see `manifest.py` for why, and `resolver.py` for the checks that make
"relative location in a reviewed file" a meaningful constraint rather than a
convention.
"""

from agentsec.project.discovery import (
    PROJECT_SCHEMA_VERSION,
    Discovery,
    Problem,
    Surface,
    discover,
)
from agentsec.project.fingerprint import FINGERPRINT_SCHEMA_VERSION, fingerprint_repository
from agentsec.project.manifest import (
    API_VERSION,
    KIND,
    MANIFEST_PATH,
    ProjectManifest,
    Surfaces,
    default_manifest_text,
    load_manifest,
    load_project,
    manifest_path,
    suggest_project_id,
)
from agentsec.project.resolver import check_location, relative_display, resolve_root, safe_child

__all__ = [
    "API_VERSION",
    "KIND",
    "MANIFEST_PATH",
    "PROJECT_SCHEMA_VERSION",
    "Discovery",
    "FINGERPRINT_SCHEMA_VERSION",
    "Problem",
    "ProjectManifest",
    "Surface",
    "Surfaces",
    "check_location",
    "default_manifest_text",
    "discover",
    "fingerprint_repository",
    "load_manifest",
    "load_project",
    "manifest_path",
    "relative_display",
    "resolve_root",
    "safe_child",
    "suggest_project_id",
]
