"""The reviewed manifest for the ``skill_eval`` static profile.

The manifest is reviewed configuration, never a caller-supplied locator.  It
selects a skill by the stable id emitted by project discovery and pins the
entrypoint, references and scripts by full SHA-256.  Loading is intentionally
stricter than ``yaml.safe_load`` alone: aliases, anchors, explicit tags, merge
keys, duplicate keys and type coercion at model boundaries are all refused.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Final, Literal

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, field_validator
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.tokens import (
    AliasToken,
    AnchorToken,
    BlockEndToken,
    BlockMappingStartToken,
    BlockSequenceStartToken,
    FlowMappingEndToken,
    FlowMappingStartToken,
    FlowSequenceEndToken,
    FlowSequenceStartToken,
    ScalarToken,
    TagToken,
)

from agentsec.config import package_schema_dir

API_VERSION: Final = "agentsec.dev/v1alpha1"
KIND: Final = "SkillEvalSuite"
PROFILE: Final = "static"
SUITE_DIR: Final = ".agentsec/skill_eval"

MAX_MANIFEST_BYTES: Final = 64 * 1024
MAX_YAML_DEPTH: Final = 16
MAX_YAML_NODES: Final = 512
MAX_YAML_TOKENS: Final = 2048

_FORBIDDEN_TEXT = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
    "\u061c\u200b-\u200f\u2028-\u202e\u2060\u2066-\u2069\ufeff"
    "\U000e0000-\U000e007f]"
)

SUITE_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{2,63}$"
SKILL_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{1,119}$"
DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"


class PinnedArtifact(BaseModel):
    """One repository-relative file and the bytes a reviewer approved."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: str = Field(min_length=1, max_length=240)
    digest: str = Field(pattern=DIGEST_PATTERN)


class SkillEvalSuite(BaseModel):
    """Phase 0 only; dynamic cases belong to a later runner protocol."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    apiVersion: Literal["agentsec.dev/v1alpha1"] = API_VERSION  # noqa: N815
    kind: Literal["SkillEvalSuite"] = KIND
    suite_id: str = Field(pattern=SUITE_ID_PATTERN)
    profile: Literal["static"] = PROFILE
    skill_id: str = Field(pattern=SKILL_ID_PATTERN)
    entrypoint: PinnedArtifact
    references: tuple[PinnedArtifact, ...] = Field(default=(), max_length=64)
    scripts: tuple[PinnedArtifact, ...] = Field(default=(), max_length=64)

    @field_validator("references", "scripts", mode="before")
    @classmethod
    def _yaml_sequences_become_frozen(cls, value: object) -> object:
        """YAML sequences are lists; freeze only the container, not its scalars."""
        if not isinstance(value, list):
            raise ValueError("expected a YAML sequence")
        return tuple(value)


class StrictLoader(yaml.SafeLoader):
    """SafeLoader with duplicate keys disabled.

    Token validation below rejects aliases, tags and merge keys before this
    loader is invoked.  This constructor closes the remaining last-key-wins
    ambiguity that makes a reviewed YAML file mean two different things.
    """


def _construct_unique_mapping(
    loader: StrictLoader, node: MappingNode, deep: bool = False
) -> dict[str, object]:
    mapping: dict[str, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping keys must be strings",
                key_node.start_mark,
            )
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class ManifestProblem(ValueError):
    """A stable code for a manifest failure; messages never enter JSON output."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@lru_cache(maxsize=1)
def suite_schema() -> Draft202012Validator:
    body = json.loads(
        (package_schema_dir() / "skill-eval-suite.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(body)


def _reject_ambiguous_yaml(text: str) -> None:
    if text.startswith("\ufeff"):
        raise ManifestProblem("yaml_bom_forbidden")
    if _FORBIDDEN_TEXT.search(text):
        raise ManifestProblem("yaml_control_character")
    depth = 0
    count = 0
    try:
        tokens = yaml.scan(text)
        for token in tokens:
            count += 1
            if count > MAX_YAML_TOKENS:
                raise ManifestProblem("yaml_too_many_tokens")
            if isinstance(token, (AnchorToken, AliasToken, TagToken)):
                raise ManifestProblem("yaml_indirection_forbidden")
            if isinstance(token, ScalarToken) and token.value == "<<":
                raise ManifestProblem("yaml_merge_forbidden")
            if isinstance(
                token,
                (
                    BlockMappingStartToken,
                    BlockSequenceStartToken,
                    FlowMappingStartToken,
                    FlowSequenceStartToken,
                ),
            ):
                depth += 1
                if depth > MAX_YAML_DEPTH:
                    raise ManifestProblem("yaml_too_deep")
            elif isinstance(
                token,
                (BlockEndToken, FlowMappingEndToken, FlowSequenceEndToken),
            ):
                depth = max(0, depth - 1)
    except RecursionError as exc:
        raise ManifestProblem("yaml_too_deep") from exc
    except yaml.YAMLError as exc:
        raise ManifestProblem("yaml_invalid") from exc


def _check_shape(value: object, *, depth: int = 0, seen: list[int] | None = None) -> None:
    if depth > MAX_YAML_DEPTH:
        raise ManifestProblem("yaml_too_deep")
    counter = seen if seen is not None else [0]
    counter[0] += 1
    if counter[0] > MAX_YAML_NODES:
        raise ManifestProblem("yaml_too_many_nodes")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ManifestProblem("yaml_key_not_string")
            _check_shape(child, depth=depth + 1, seen=counter)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _check_shape(child, depth=depth + 1, seen=counter)


def parse_suite(data: bytes) -> SkillEvalSuite:
    """Parse bytes already read through the bounded regular-file reader."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestProblem("manifest_too_large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestProblem("manifest_not_utf8") from exc

    _reject_ambiguous_yaml(text)
    try:
        document = yaml.load(text, Loader=StrictLoader)  # noqa: S506 - strict SafeLoader subclass
        _check_shape(document)
    except RecursionError as exc:
        raise ManifestProblem("yaml_too_deep") from exc
    except (yaml.YAMLError, ConstructorError) as exc:
        raise ManifestProblem("yaml_invalid") from exc
    if not isinstance(document, dict):
        raise ManifestProblem("manifest_root_not_mapping")

    errors = sorted(suite_schema().iter_errors(document), key=str)
    if errors:
        raise ManifestProblem("manifest_schema_invalid")
    try:
        suite = SkillEvalSuite.model_validate(document, strict=True)
    except Exception as exc:
        raise ManifestProblem("manifest_model_invalid") from exc

    paths = [suite.entrypoint.path]
    paths.extend(pin.path for pin in suite.references)
    paths.extend(pin.path for pin in suite.scripts)
    if len(paths) != len(set(paths)):
        raise ManifestProblem("artifact_pin_duplicate")
    return suite


def suite_directory(root: Path) -> Path:
    """The fixed reviewed location. There is intentionally no path argument."""
    return root / SUITE_DIR
