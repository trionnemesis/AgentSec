"""Deterministic, read-only AI-agent framework fingerprinting.

No repository code is imported or executed.  Python is inspected with ``ast``;
JavaScript and TypeScript use bounded structural matching.  A recognised
framework dependency or import is only ``likely``.  ``confirmed`` requires a
framework-specific builder call in application source.  Development-agent
files are inventoried separately and can only produce ``configuration_only``.
"""

from __future__ import annotations

import ast
import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from agentsec.errors import ProjectError
from agentsec.models.fingerprint import (
    DevelopmentAgentConfig,
    DevelopmentPlatform,
    FingerprintEvidence,
    FingerprintLanguage,
    FingerprintProblem,
    FingerprintProblemKind,
    FingerprintReport,
    RuntimeAgentFingerprint,
)

FINGERPRINT_SCHEMA_VERSION = "1.0.0"
MAX_SOURCE_FILES = 2_000
MAX_READ_BYTES = 512 * 1024

_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".agentsec",
        ".claude",
        ".codex",
        ".cursor",
        ".gemini",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "docs",
        "example",
        "examples",
        "fixtures",
        "node_modules",
        "site",
        "tests",
        "vendor",
        "venv",
    }
)
_PYTHON_SUFFIXES = frozenset({".py"})
_JAVASCRIPT_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
_SOURCE_SUFFIXES = _PYTHON_SUFFIXES | _JAVASCRIPT_SUFFIXES


@dataclass(frozen=True)
class _FrameworkSpec:
    packages: frozenset[str]
    python_modules: frozenset[str]
    javascript_packages: frozenset[str]
    builders: frozenset[str]


_FRAMEWORKS: dict[str, _FrameworkSpec] = {
    "langgraph": _FrameworkSpec(
        packages=frozenset({"langgraph"}),
        python_modules=frozenset({"langgraph"}),
        javascript_packages=frozenset({"@langchain/langgraph"}),
        builders=frozenset({"StateGraph", "MessageGraph"}),
    ),
    "langchain": _FrameworkSpec(
        packages=frozenset({"langchain"}),
        python_modules=frozenset({"langchain"}),
        javascript_packages=frozenset({"langchain"}),
        builders=frozenset(
            {
                "AgentExecutor",
                "create_openai_functions_agent",
                "createAgent",
                "create_agent",
                "create_react_agent",
                "create_structured_chat_agent",
                "create_tool_calling_agent",
                "initialize_agent",
            }
        ),
    ),
    "openai_agents": _FrameworkSpec(
        packages=frozenset({"openai-agents"}),
        python_modules=frozenset({"agents"}),
        javascript_packages=frozenset({"@openai/agents"}),
        builders=frozenset({"Agent"}),
    ),
    "autogen": _FrameworkSpec(
        packages=frozenset({"ag2", "autogen-agentchat", "pyautogen"}),
        python_modules=frozenset({"autogen", "autogen_agentchat"}),
        javascript_packages=frozenset(),
        builders=frozenset(
            {"AssistantAgent", "ConversableAgent", "RoundRobinGroupChat", "UserProxyAgent"}
        ),
    ),
    "semantic_kernel": _FrameworkSpec(
        packages=frozenset({"semantic-kernel"}),
        python_modules=frozenset({"semantic_kernel"}),
        javascript_packages=frozenset(),
        builders=frozenset({"AgentGroupChat", "ChatCompletionAgent"}),
    ),
    "crewai": _FrameworkSpec(
        packages=frozenset({"crewai"}),
        python_modules=frozenset({"crewai"}),
        javascript_packages=frozenset(),
        builders=frozenset({"Crew"}),
    ),
}

_PROVIDER_MODULES = frozenset(
    {"anthropic", "google.genai", "google.generativeai", "mistralai", "openai"}
)
_PROVIDER_PACKAGES = frozenset(
    {"@anthropic-ai/sdk", "@google/genai", "@mistralai/mistralai", "openai"}
)
_DEPENDENCY_PATTERN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_JS_IMPORT_PATTERN = re.compile(
    r"(?:from\s*|require\s*\(\s*|import\s*\(\s*)['\"]([^'\"]+)['\"]"
)
_TOOLS_PATTERN = re.compile(r"\btools\s*[:=]")
_TOOL_RESULT_PATTERN = re.compile(r"\b(?:tool_calls|tool_use|function_call)\b")

_DEVELOPMENT_MARKERS: dict[DevelopmentPlatform, tuple[str, ...]] = {
    "claude_code": (".claude", "CLAUDE.md"),
    "codex": (".codex", "AGENTS.md"),
    "gemini_cli": (".gemini", "GEMINI.md"),
    "cursor": (".cursor", ".cursorrules"),
    "mcp": (".mcp.json",),
}


@dataclass
class _Observation:
    dependencies: set[tuple[str, str]] = field(default_factory=set)
    imports: set[tuple[str, str, FingerprintLanguage]] = field(default_factory=set)
    builders: set[tuple[str, str, FingerprintLanguage]] = field(default_factory=set)
    runtime_configs: set[tuple[str, str, FingerprintLanguage]] = field(default_factory=set)
    tool_calling: set[tuple[str, str, FingerprintLanguage]] = field(default_factory=set)


class _Scanner:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.observations = {name: _Observation() for name in _FRAMEWORKS}
        self.observations["custom_tool_calling"] = _Observation()
        self.problems: list[FingerprintProblem] = []
        self._problem_keys: set[tuple[str, str]] = set()
        self.files_seen = 0
        self.limit_reached = False

    def note(self, path: str, kind: FingerprintProblemKind, detail: str) -> None:
        key = (path, kind)
        if key in self._problem_keys:
            return
        self._problem_keys.add(key)
        self.problems.append(FingerprintProblem(path=path, kind=kind, detail=detail))

    def relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def safe_file(self, path: Path) -> bool:
        if path.is_symlink():
            try:
                target = path.resolve(strict=True)
            except OSError:
                target = path.resolve(strict=False)
            try:
                target.relative_to(self.root)
            except ValueError:
                self.note(
                    self.relative(path),
                    "outside_root_symlink",
                    "symlink target is outside the selected repository and was not read",
                )
            else:
                self.note(
                    self.relative(path),
                    "symlink_skipped",
                    "symlinks are not followed; the real in-repository path is scanned instead",
                )
            return False
        return path.is_file()

    def text(self, path: Path) -> str | None:
        relative = self.relative(path)
        try:
            size = path.stat().st_size
        except OSError as exc:
            self.note(relative, "undecodable", f"could not stat file: {type(exc).__name__}")
            return None
        if size > MAX_READ_BYTES:
            self.note(
                relative,
                "too_large",
                f"file is {size} bytes; fingerprint limit is {MAX_READ_BYTES}",
            )
            return None
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            self.note(relative, "undecodable", f"not readable as UTF-8: {type(exc).__name__}")
            return None

    def candidate_files(self) -> list[Path]:
        out: list[Path] = []
        for current, directories, files in os.walk(self.root, followlinks=False):
            current_path = Path(current)
            kept_directories: list[str] = []
            for name in sorted(directories):
                if name in _IGNORED_DIRS:
                    continue
                path = current_path / name
                if path.is_symlink():
                    self.safe_file(path)
                    continue
                kept_directories.append(name)
            directories[:] = kept_directories
            for name in sorted(files):
                path = current_path / name
                is_manifest = name in {
                    "crew.json",
                    "crew.jsonc",
                    "package.json",
                    "pyproject.toml",
                }
                is_requirements = name.startswith("requirements") and name.endswith(".txt")
                if not (is_manifest or is_requirements or path.suffix.lower() in _SOURCE_SUFFIXES):
                    continue
                self.files_seen += 1
                if self.files_seen > MAX_SOURCE_FILES:
                    self.limit_reached = True
                    break
                if self.safe_file(path):
                    out.append(path)
            if self.limit_reached:
                break
        if self.limit_reached:
            self.note(
                ".",
                "scan_limit",
                f"stopped after {MAX_SOURCE_FILES} candidate source and manifest files",
            )
        return out

    def scan(self) -> FingerprintReport:
        files = self.candidate_files()
        for path in files:
            name = path.name
            if name == "pyproject.toml":
                self.scan_pyproject(path)
            elif name == "package.json":
                self.scan_package_json(path)
            elif name in {"crew.json", "crew.jsonc"}:
                self.scan_crewai_config(path)
            elif name.startswith("requirements") and name.endswith(".txt"):
                self.scan_requirements(path)
            elif path.suffix.lower() in _PYTHON_SUFFIXES:
                self.scan_python(path)
            else:
                self.scan_javascript(path)

        runtime = self.runtime_fingerprints()
        development = self.development_config()
        if any(item.confidence == "high" for item in runtime):
            presence: Literal[
                "confirmed", "likely", "configuration_only", "not_detected", "unsupported"
            ] = "confirmed"
            confidence: Literal["high", "medium", "none"] = "high"
        elif runtime:
            presence = "likely"
            confidence = "medium"
        elif any(problem.kind != "symlink_skipped" for problem in self.problems):
            presence = "unsupported"
            confidence = "none"
        elif development:
            presence = "configuration_only"
            confidence = "medium"
        else:
            presence = "not_detected"
            confidence = "none"
        return FingerprintReport(
            schema_version=FINGERPRINT_SCHEMA_VERSION,
            agent_presence=presence,
            confidence=confidence,
            runtime_agents=runtime,
            development_agent_config=development,
            problems=sorted(self.problems, key=lambda item: (item.path, item.kind)),
        )

    def add_dependency(self, relative: str, package: str) -> None:
        normalised = _normalise_package(package)
        for framework, spec in _FRAMEWORKS.items():
            if normalised in spec.packages or package.lower() in spec.javascript_packages:
                self.observations[framework].dependencies.add((relative, package.lower()))

    def scan_pyproject(self, path: Path) -> None:
        text = self.text(path)
        if text is None:
            return
        relative = self.relative(path)
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            self.note(relative, "invalid_manifest", f"invalid TOML: {type(exc).__name__}")
            return
        project = data.get("project") if isinstance(data, dict) else None
        if isinstance(project, dict):
            for dependency in project.get("dependencies") or []:
                if isinstance(dependency, str):
                    self.add_dependency(relative, dependency)
            optional = project.get("optional-dependencies") or {}
            if isinstance(optional, dict):
                for dependencies in optional.values():
                    for dependency in dependencies if isinstance(dependencies, list) else []:
                        if isinstance(dependency, str):
                            self.add_dependency(relative, dependency)
        poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data, dict) else {}
        if isinstance(poetry, dict):
            dependencies = poetry.get("dependencies") or {}
            if isinstance(dependencies, dict):
                for dependency in dependencies:
                    self.add_dependency(relative, dependency)

    def scan_requirements(self, path: Path) -> None:
        text = self.text(path)
        if text is None:
            return
        relative = self.relative(path)
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            self.add_dependency(relative, stripped)

    def scan_package_json(self, path: Path) -> None:
        text = self.text(path)
        if text is None:
            return
        relative = self.relative(path)
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            self.note(relative, "invalid_manifest", f"invalid JSON: {type(exc).__name__}")
            return
        if not isinstance(data, dict):
            self.note(relative, "invalid_manifest", "package.json root is not an object")
            return
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            dependencies = data.get(key) or {}
            if not isinstance(dependencies, dict):
                continue
            for package in dependencies:
                self.add_dependency(relative, package)

    def scan_crewai_config(self, path: Path) -> None:
        text = self.text(path)
        if text is None:
            return
        relative = self.relative(path)
        try:
            data = json.loads(_strip_json_comments(text))
        except (json.JSONDecodeError, ValueError) as exc:
            self.note(relative, "invalid_manifest", f"invalid JSONC: {type(exc).__name__}")
            return
        if not isinstance(data, dict):
            self.note(relative, "invalid_manifest", "CrewAI definition root is not an object")
            return
        if isinstance(data.get("agents"), list) and isinstance(data.get("tasks"), list):
            self.observations["crewai"].runtime_configs.add(
                (relative, "crew_definition", "unknown")
            )

    def scan_python(self, path: Path) -> None:
        text = self.text(path)
        if text is None or not _has_runtime_hint(text):
            return
        relative = self.relative(path)
        try:
            tree = ast.parse(text, filename=relative)
        except SyntaxError:
            self.note(relative, "syntax_error", "candidate Python file could not be parsed")
            return

        aliases, imported_frameworks, providers = _python_imports(tree)
        for framework, module in imported_frameworks:
            self.observations[framework].imports.add((relative, module, "python"))

        has_tools = False
        has_tool_result = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                resolved = _resolve_call_name(node.func, aliases)
                short = resolved.rsplit(".", 1)[-1]
                for framework, _module in imported_frameworks:
                    if short in _FRAMEWORKS[framework].builders:
                        self.observations[framework].builders.add(
                            (relative, short, "python")
                        )
                if any(keyword.arg in {"tools", "functions"} for keyword in node.keywords):
                    has_tools = True
            elif isinstance(node, ast.Attribute):
                if node.attr in {"tool_calls", "function_call"}:
                    has_tool_result = True
            elif isinstance(node, ast.Constant) and node.value == "tool_use":
                has_tool_result = True

        if providers and has_tools and has_tool_result:
            provider = sorted(providers)[0]
            self.observations["custom_tool_calling"].tool_calling.add(
                (relative, provider, "python")
            )

    def scan_javascript(self, path: Path) -> None:
        text = self.text(path)
        if text is None or not _has_runtime_hint(text):
            return
        relative = self.relative(path)
        language: FingerprintLanguage = (
            "typescript" if path.suffix.lower() in {".ts", ".tsx"} else "javascript"
        )
        packages = set(_JS_IMPORT_PATTERN.findall(text))
        imported_frameworks: set[str] = set()
        for framework, spec in _FRAMEWORKS.items():
            matched = packages & spec.javascript_packages
            for package in matched:
                imported_frameworks.add(framework)
                self.observations[framework].imports.add((relative, package, language))
        for framework in imported_frameworks:
            for builder in _FRAMEWORKS[framework].builders:
                if re.search(rf"\b(?:new\s+)?{re.escape(builder)}\s*\(", text):
                    self.observations[framework].builders.add((relative, builder, language))
        providers = packages & _PROVIDER_PACKAGES
        if providers and _TOOLS_PATTERN.search(text) and _TOOL_RESULT_PATTERN.search(text):
            self.observations["custom_tool_calling"].tool_calling.add(
                (relative, sorted(providers)[0], language)
            )

    def runtime_fingerprints(self) -> list[RuntimeAgentFingerprint]:
        results: list[RuntimeAgentFingerprint] = []
        for framework in (*_FRAMEWORKS, "custom_tool_calling"):
            observation = self.observations[framework]
            if framework == "openai_agents" and not observation.dependencies and not any(
                value == "@openai/agents" for _file, value, _language in observation.imports
            ):
                # Python's official import root is simply ``agents``, which is
                # also a common local module. Without the distribution name
                # from a manifest, attributing it to OpenAI would be a guess.
                continue
            if not any(
                (
                    observation.dependencies,
                    observation.imports,
                    observation.builders,
                    observation.runtime_configs,
                    observation.tool_calling,
                )
            ):
                continue
            high = bool(observation.builders or observation.runtime_configs)
            entrypoints = sorted(
                {
                    item[0]
                    for item in observation.builders
                    | observation.runtime_configs
                    | observation.tool_calling
                }
            )
            evidence: list[FingerprintEvidence] = []
            for file, value in sorted(observation.dependencies):
                evidence.append(FingerprintEvidence(kind="dependency", file=file, value=value))
            for file, value, _language in sorted(observation.imports):
                evidence.append(FingerprintEvidence(kind="import", file=file, value=value))
            for file, value, _language in sorted(observation.builders):
                evidence.append(FingerprintEvidence(kind="builder_call", file=file, value=value))
            for file, value, _language in sorted(observation.runtime_configs):
                evidence.append(FingerprintEvidence(kind="runtime_config", file=file, value=value))
            for file, value, _language in sorted(observation.tool_calling):
                evidence.append(FingerprintEvidence(kind="tool_calling", file=file, value=value))
            languages = {
                item[2]
                for item in observation.imports
                | observation.builders
                | observation.runtime_configs
                | observation.tool_calling
            }
            if len(languages) > 1:
                language: FingerprintLanguage = "mixed"
            elif languages:
                language = next(iter(languages))
            else:
                language = "unknown"
            results.append(
                RuntimeAgentFingerprint(
                    framework=framework,
                    language=language,
                    confidence="high" if high else "medium",
                    entrypoints=entrypoints,
                    evidence=evidence,
                )
            )
        return sorted(results, key=lambda item: (item.confidence != "high", item.framework))

    def development_config(self) -> list[DevelopmentAgentConfig]:
        results: list[DevelopmentAgentConfig] = []
        for platform, markers in _DEVELOPMENT_MARKERS.items():
            paths: list[str] = []
            for marker in markers:
                path = self.root / marker
                if not path.exists() and not path.is_symlink():
                    continue
                if path.is_symlink():
                    self.safe_file(path)
                    continue
                paths.append(marker)
            if paths:
                results.append(DevelopmentAgentConfig(platform=platform, paths=sorted(paths)))
        return results


def _normalise_package(dependency: str) -> str:
    match = _DEPENDENCY_PATTERN.match(dependency)
    if not match:
        return ""
    return re.sub(r"[-_.]+", "-", match.group(1).lower())


def _strip_json_comments(text: str) -> str:
    """Remove JSONC comments without treating comment markers inside strings as syntax."""
    out: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and next_char == "*":
            index += 2
            closed = False
            while index + 1 < len(text) and text[index : index + 2] != "*/":
                index += 1
            if index + 1 < len(text):
                closed = True
                index += 2
            if not closed:
                raise ValueError("unterminated JSONC block comment")
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "}]":
                index += 1
                continue
        out.append(char)
        index += 1
    return "".join(out)


def _framework_for_module(module: str) -> str | None:
    for framework, spec in _FRAMEWORKS.items():
        if any(
            module == prefix or module.startswith(prefix + ".")
            for prefix in spec.python_modules
        ):
            return framework
    return None


def _python_imports(
    tree: ast.AST,
) -> tuple[dict[str, str], set[tuple[str, str]], set[str]]:
    aliases: dict[str, str] = {}
    frameworks: set[tuple[str, str]] = set()
    providers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                aliases[local] = alias.name
                framework = _framework_for_module(alias.name)
                if framework:
                    frameworks.add((framework, alias.name))
                if any(
                    alias.name == provider or alias.name.startswith(provider + ".")
                    for provider in _PROVIDER_MODULES
                ):
                    providers.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            framework = _framework_for_module(node.module)
            if framework:
                frameworks.add((framework, node.module))
            if any(
                node.module == provider or node.module.startswith(provider + ".")
                for provider in _PROVIDER_MODULES
            ):
                providers.add(node.module)
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases, frameworks, providers


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _resolve_call_name(node: ast.expr, aliases: dict[str, str]) -> str:
    name = _call_name(node)
    if not name:
        return ""
    head, separator, tail = name.partition(".")
    resolved = aliases.get(head, head)
    return f"{resolved}.{tail}" if separator else resolved


def _has_runtime_hint(text: str) -> bool:
    lowered = text.lower()
    names = {
        package
        for spec in _FRAMEWORKS.values()
        for package in (*spec.python_modules, *spec.javascript_packages)
    }
    return any(name in lowered for name in names) or (
        any(provider in lowered for provider in (*_PROVIDER_MODULES, *_PROVIDER_PACKAGES))
        and ("tool_calls" in lowered or "tool_use" in lowered or "function_call" in lowered)
    )


def fingerprint_repository(root: Path) -> FingerprintReport:
    """Classify runtime-agent code and development-agent config under ``root``.

    The root is canonicalised before any file is enumerated.  Symlinks are not
    followed, repository code is never imported, and every reported path is
    relative to the selected root.
    """
    try:
        resolved = root.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ProjectError(
            "fingerprint root does not exist", details={"kind": type(exc).__name__}
        ) from exc
    if not resolved.is_dir():
        raise ProjectError("fingerprint root is not a directory")
    return _Scanner(resolved).scan()
