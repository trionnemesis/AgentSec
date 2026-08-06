"""The rules that turn a surface inventory into risks.

Every rule here is a pure function of file bytes and declared configuration.
There is no model in this path and there will not be one: an LLM judge is
refused for verdicts ([ADR 0002](../../../docs/adr/0002-deterministic-verdict.md))
and the argument does not weaken one level upstream — a risk plane whose output
changed between two runs of the same commit could not be diffed, gated on, or
argued with.

Three properties every rule holds, enforced by ``tests/test_inspect.py``:

**Bounded evidence, never content.** A rule may report that it matched, where,
how often, and which of *its own* named markers fired. It may not carry the
matched text. Discovery pays for the property that its output needs no second
redaction pass by not reading values in the first place; a risk plane that
quoted the offending line would spend that property on the way out.

**Fixed severity.** Severity is a property of the rule, not of the repository.
It answers "how bad if real", and the question of whether it *is* real belongs
to the verification bridge — which is the whole point of keeping the two apart.

**Silence is not a pass.** A file that cannot be read becomes a problem, not an
absence. Every rule that reads bytes goes through :func:`read_text`.

Rule ids are ``ASI-<SURFACE>-<NAME>``: AgentSec Static Inspection, so they never
collide with scenario ids (``AGT-*``) or a third-party scanner's rule ids in the
static posture plane.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsec.models.risk import RepoRisk
from agentsec.project.discovery import Discovery, Surface

#: Per file. A configuration file larger than this is not inspected in full —
#: the rules read the head and say so, rather than reading an unbounded blob
#: into memory because a repository asked them to.
MAX_READ_BYTES = 512 * 1024

#: How many lines a rule reports before it stops enumerating. The count stays
#: exact; only the list of positions is capped.
MAX_REPORTED_LINES = 10


@dataclass
class RuleContext:
    """What every rule gets, and the only place any of them touches the disk."""

    root: Path
    discovery: Discovery
    problems: list[dict[str, str]] = field(default_factory=list)
    _cache: dict[str, str | None] = field(default_factory=dict)

    def note(self, path: str, kind: str, detail: str) -> None:
        self.problems.append({"path": path, "kind": kind, "detail": detail})

    def read_text(self, surface: Surface) -> str | None:
        """Decoded head of a discovered file, or ``None`` with a problem recorded.

        Takes a :class:`Surface` rather than a path because that is the only way
        into this function: the file must already have been discovered, which
        means it already passed the traversal and symlink-containment checks in
        ``project/resolver.py``. No rule composes a path of its own.
        """
        if surface.path in self._cache:
            return self._cache[surface.path]

        result: str | None = None
        target = self.root / surface.path
        try:
            raw = target.read_bytes()[:MAX_READ_BYTES]
            result = raw.decode("utf-8")
        except OSError as exc:
            self.note(surface.path, "unreadable", str(exc))
        except UnicodeDecodeError:
            # Binary, or text in an encoding this version does not read. Either
            # way the rules below cannot speak about it, and saying so beats
            # returning "" and reporting a clean file.
            self.note(surface.path, "undecodable", "not valid UTF-8; rules did not inspect it")

        self._cache[surface.path] = result
        return result

    def read_json(self, surface: Surface) -> dict[str, Any] | None:
        text = self.read_text(surface)
        if text is None:
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            self.note(surface.path, "malformed", f"not valid JSON: {exc}")
            return None
        return data if isinstance(data, dict) else None


Rule = Callable[[RuleContext], Iterator[RepoRisk]]
RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


def _lines(text: str) -> list[str]:
    return text.splitlines()


def _positions(hits: list[int]) -> dict[str, Any]:
    """Line numbers, capped, with the true count kept."""
    return {"occurrences": len(hits), "lines": sorted(hits)[:MAX_REPORTED_LINES]}


# ---------------------------------------------------------------------------
# Instruction-bearing surfaces: skills, agents, project instructions, memory
# ---------------------------------------------------------------------------

#: Characters with no legitimate role in an agent instruction and a direct one
#: in hiding a directive from the human who reviewed the diff. Split by how
#: certain that is: bidi controls and Unicode tag characters have no innocent
#: use in this context, while zero-width joiners appear in real emoji sequences
#: and in several scripts. Two rules rather than one, so the medium-severity
#: false positives never inflate the high-severity count.
_BIDI_AND_TAGS = frozenset(
    [*range(0x202A, 0x202F), *range(0x2066, 0x206A), *range(0xE0000, 0xE0080)]
)
_INVISIBLE = frozenset([0x00AD, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF])

#: Instructions the agent obeys. Skills and agents carry frontmatter and prose;
#: memory files carry retrieved context. All four reach the model as text it
#: treats as authoritative, which is what makes them one class here.
_INSTRUCTION_KINDS = frozenset({"skill", "agent", "instructions", "memory"})


def _instruction_surfaces(ctx: RuleContext) -> list[Surface]:
    return [s for s in ctx.discovery.all_surfaces() if s.kind in _INSTRUCTION_KINDS]


def _codepoint_hits(text: str, wanted: frozenset[int]) -> tuple[list[int], list[str]]:
    """Line numbers and the distinct codepoints found, by name."""
    hits: list[int] = []
    names: set[str] = set()
    for number, line in enumerate(_lines(text), start=1):
        found = {ord(c) for c in line} & wanted
        if found:
            hits.append(number)
            for point in found:
                label = unicodedata.name(chr(point), f"U+{point:04X}")
                names.add(f"U+{point:04X} {label}")
    return hits, sorted(names)


@rule
def hidden_bidi_directives(ctx: RuleContext) -> Iterator[RepoRisk]:
    for surface in _instruction_surfaces(ctx):
        text = ctx.read_text(surface)
        if text is None:
            continue
        hits, names = _codepoint_hits(text, _BIDI_AND_TAGS)
        if not hits:
            continue
        yield RepoRisk(
            rule_id="ASI-INSTR-BIDI-CONTROL",
            severity="high",
            surface_kind=surface.kind,
            surface_id=surface.id,
            file=surface.path,
            title="Instruction text carries bidi or Unicode tag characters",
            detail=(
                "These codepoints reorder or conceal text between what a reviewer "
                "sees in a diff and what the model reads. They have no legitimate "
                "use in an agent instruction."
            ),
            evidence={**_positions(hits), "codepoints": names},
        )


@rule
def invisible_characters(ctx: RuleContext) -> Iterator[RepoRisk]:
    for surface in _instruction_surfaces(ctx):
        text = ctx.read_text(surface)
        if text is None:
            continue
        hits, names = _codepoint_hits(text, _INVISIBLE)
        if not hits:
            continue
        yield RepoRisk(
            rule_id="ASI-INSTR-INVISIBLE-CHARS",
            severity="medium",
            surface_kind=surface.kind,
            surface_id=surface.id,
            file=surface.path,
            title="Instruction text carries zero-width or invisible characters",
            detail=(
                "Zero-width characters can spell a directive a reviewer cannot see. "
                "They also occur legitimately in emoji sequences and in several "
                "scripts, so this is a prompt to look, not a finding on its own."
            ),
            evidence={**_positions(hits), "codepoints": names},
        )


#: Marker vocabularies. What gets reported is the *category* that matched, never
#: the line — so this table is the rule's own language rather than a channel for
#: repository content to reach the output.
_SECRET_MARKERS = {
    "dotenv": (".env",),
    "credential": ("credential", "password", "passwd", "secret", "api key", "api_key",
                   "apikey", "access token", "auth token", "bearer "),
    "key-material": ("private key", "id_rsa", "id_ed25519", ".pem", "keychain", ".npmrc",
                     ".aws/credentials", ".ssh/"),
}
_SINK_MARKERS = {
    "http-client": ("curl ", "wget ", "requests.post", "urllib", "httpx", "fetch(",
                    "http://", "https://"),
    "exfil-verb": ("exfiltrat", "webhook", "upload to", "post to", "send to", "email to",
                   "paste to"),
    "encode": ("base64", "b64encode"),
}
_COVERT_MARKERS = (
    "ignore previous instruction", "ignore all previous", "disregard the above",
    "disregard previous", "do not tell the user", "don't tell the user",
    "without telling the user", "without informing", "do not mention this",
    "keep this secret from", "silently", "do not log", "hide this from",
    "override your instructions", "system prompt override",
)
_IMPERATIVE = (
    "read ", "send ", "post ", "upload ", "fetch ", "run ", "execute ", "cat ",
    "curl ", "wget ", "you must", "always ", "first, ", "before responding",
)

#: How far apart a secret mention and a sink mention may be and still count as
#: one directive. Three lines covers a bulleted instruction; a whole document
#: mentioning both somewhere is not evidence of anything.
_WINDOW = 3


def _marker_categories(haystack: str, table: dict[str, tuple[str, ...]]) -> set[str]:
    return {name for name, needles in table.items() if any(n in haystack for n in needles)}


@rule
def exfiltration_directive(ctx: RuleContext) -> Iterator[RepoRisk]:
    """A secret source and an outbound sink, close together, phrased as an order.

    All three conditions are required. Any two of them describe most security
    documentation, including this repository's own — a rule that fires on prose
    about exfiltration teaches its reader to skip the plane.
    """
    for surface in _instruction_surfaces(ctx):
        text = ctx.read_text(surface)
        if text is None:
            continue
        lines = [line.lower() for line in _lines(text)]
        hits: list[int] = []
        secrets: set[str] = set()
        sinks: set[str] = set()
        for index in range(len(lines)):
            window = "\n".join(lines[index : index + _WINDOW])
            found_secret = _marker_categories(window, _SECRET_MARKERS)
            found_sink = _marker_categories(window, _SINK_MARKERS)
            if not (found_secret and found_sink):
                continue
            if not any(verb in window for verb in _IMPERATIVE):
                continue
            hits.append(index + 1)
            secrets |= found_secret
            sinks |= found_sink
        if not hits:
            continue
        yield RepoRisk(
            rule_id="ASI-INSTR-EXFIL-DIRECTIVE",
            severity="high",
            surface_kind=surface.kind,
            surface_id=surface.id,
            file=surface.path,
            title="Instruction pairs a secret source with an outbound sink",
            detail=(
                "An imperative names both something secret-shaped and a way off the "
                "machine, within a few lines. This is the shape of AGT-CONFIG-001, "
                "and it is a reason to run that scenario rather than a conclusion."
            ),
            evidence={
                **_positions(hits),
                "secret_markers": sorted(secrets),
                "sink_markers": sorted(sinks),
            },
        )


@rule
def covert_directive(ctx: RuleContext) -> Iterator[RepoRisk]:
    for surface in _instruction_surfaces(ctx):
        text = ctx.read_text(surface)
        if text is None:
            continue
        hits: list[int] = []
        matched: set[str] = set()
        for number, line in enumerate(_lines(text), start=1):
            lowered = line.lower()
            found = {marker for marker in _COVERT_MARKERS if marker in lowered}
            if found:
                hits.append(number)
                matched |= found
        if not hits:
            continue
        yield RepoRisk(
            rule_id="ASI-INSTR-COVERT-DIRECTIVE",
            severity="high",
            surface_kind=surface.kind,
            surface_id=surface.id,
            file=surface.path,
            title="Instruction tells the agent to override or conceal",
            detail=(
                "Phrasing that instructs the model to disregard prior instructions or "
                "to withhold an action from the user. Legitimate in a test fixture; "
                "in a live configuration it is the payload."
            ),
            evidence={**_positions(hits), "phrases": sorted(matched)},
        )


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

_SHELL_CONSTRUCTS = {
    "subprocess-shell": re.compile(r"shell\s*=\s*True"),
    "os-system": re.compile(r"\bos\.(system|popen)\s*\("),
    "eval-exec": re.compile(r"\b(eval|exec)\s*\("),
    "shell-eval": re.compile(r"\beval\s+[\"']?\$"),
    "backtick": re.compile(r"`[^`\n]*\$[({]?[A-Za-z_]"),
}
#: A value entering a command string. Together with a shell construct on the
#: same line, this is interpolation; either alone is not.
_INTERPOLATION = re.compile(
    r"""(f["'][^"'\n]*\{)"""          # f-string with a placeholder
    r"""|(%\s*\()"""                   # printf-style formatting
    r"""|(\.format\s*\()"""            # str.format
    r"""|(\+\s*[A-Za-z_][\w.\[\]]*)"""  # concatenation with a name
    r"""|(\$\{?[A-Za-z_])"""           # shell variable expansion
)

_NETWORK_CONSTRUCTS = {
    "python-http": re.compile(r"\b(requests|httpx|urllib|http\.client|aiohttp)\b"),
    "shell-http": re.compile(r"\b(curl|wget|nc|netcat)\b"),
    "socket": re.compile(r"\bsocket\.(socket|create_connection)\b"),
}


def strip_comment(line: str) -> str:
    """The code part of a line in a ``#``- or ``//``-commented language.

    Load-bearing rather than cosmetic. Without it the hook rules match prose:
    this repository's own guard hook carries a comment explaining what a `curl`
    to a proxied host would do, and the network-egress rule fired on it — a
    finding about a sentence. A rule that reports the documentation of a risk as
    the risk is worse than no rule, because the first thing its reader learns is
    to stop reading it.

    Quote tracking is deliberately naive: it follows single and double quotes
    with backslash escapes and nothing else. Being wrong here costs a missed
    match on an exotic line, which is the direction to be wrong in — the
    alternative is parsing every language a hook might be written in.
    """
    in_single = in_double = False
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\":
            index += 2
            continue
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if char == "#":
                return line[:index]
            if char == "/" and line[index : index + 2] == "//":
                return line[:index]
        index += 1
    return line


def _match_lines(text: str, patterns: dict[str, re.Pattern[str]],
                 *, also: re.Pattern[str] | None = None) -> tuple[list[int], set[str]]:
    hits: list[int] = []
    names: set[str] = set()
    for number, raw in enumerate(_lines(text), start=1):
        line = strip_comment(raw)
        if not line.strip():
            continue
        if also is not None and not also.search(line):
            continue
        found = {name for name, pattern in patterns.items() if pattern.search(line)}
        if found:
            hits.append(number)
            names |= found
    return hits, names


@rule
def hook_shell_interpolation(ctx: RuleContext) -> Iterator[RepoRisk]:
    """A hook that builds a shell command out of a value it did not choose.

    The highest-severity rule in the catalogue, because what fails here is not
    disclosure but execution — and a hook runs with the developer's own
    privileges, on every matching tool call, without a turn in the conversation.
    """
    for surface in ctx.discovery.hooks:
        text = ctx.read_text(surface)
        if text is None:
            continue
        hits, names = _match_lines(text, _SHELL_CONSTRUCTS, also=_INTERPOLATION)
        if not hits:
            continue
        yield RepoRisk(
            rule_id="ASI-HOOK-SHELL-INTERPOLATION",
            severity="critical",
            surface_kind="hook",
            surface_id=surface.id,
            file=surface.path,
            title="Hook interpolates a value into a shell command",
            detail=(
                "A shell-invoking construct on the same line as an interpolation. "
                "Whether the interpolated value is attacker-influenced is exactly "
                "what AGT-CONFIG-003 exists to settle."
            ),
            evidence={**_positions(hits), "constructs": sorted(names)},
        )


@rule
def hook_network_egress(ctx: RuleContext) -> Iterator[RepoRisk]:
    for surface in ctx.discovery.hooks:
        text = ctx.read_text(surface)
        if text is None:
            continue
        hits, names = _match_lines(text, _NETWORK_CONSTRUCTS)
        if not hits:
            continue
        yield RepoRisk(
            rule_id="ASI-HOOK-NETWORK-EGRESS",
            severity="medium",
            surface_kind="hook",
            surface_id=surface.id,
            file=surface.path,
            title="Hook performs network I/O",
            detail=(
                "A hook that can reach the network is a path off the machine that "
                "runs before the user sees a tool call. Common and often "
                "legitimate; worth knowing it is there."
            ),
            evidence={**_positions(hits), "constructs": sorted(names)},
        )


# ---------------------------------------------------------------------------
# MCP servers
# ---------------------------------------------------------------------------

_CREDENTIAL_KEY = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|AUTH)",
    re.IGNORECASE,
)


@rule
def mcp_credential_env(ctx: RuleContext) -> Iterator[RepoRisk]:
    """A credential-shaped key in the committed MCP config.

    Reads the key names discovery already collected, never the values — the
    point of the rule is that a value should not be reachable from here at all,
    and a rule that had to read one to say so would be making the case against
    itself.
    """
    for surface in ctx.discovery.mcp_servers:
        keys = [k for k in surface.detail.get("env_keys", []) if _CREDENTIAL_KEY.search(str(k))]
        if not keys:
            continue
        yield RepoRisk(
            rule_id="ASI-MCP-CREDENTIAL-ENV",
            severity="high",
            surface_kind="mcp_server",
            surface_id=surface.id,
            file=surface.path,
            title="MCP server declares a credential-shaped environment key",
            detail=(
                "A committed file naming a credential key is where a credential "
                "value eventually gets committed too. Whether adding such a server "
                "is an auditable event is what AGT-CONFIG-004 asks."
            ),
            evidence={"env_keys": sorted(str(k) for k in keys), "server": surface.name},
        )


@rule
def mcp_remote_transport(ctx: RuleContext) -> Iterator[RepoRisk]:
    for surface in ctx.discovery.mcp_servers:
        transport = str(surface.detail.get("transport", "unknown"))
        if transport not in {"http", "sse", "streamable-http"}:
            continue
        yield RepoRisk(
            rule_id="ASI-MCP-REMOTE-TRANSPORT",
            severity="medium",
            surface_kind="mcp_server",
            surface_id=surface.id,
            file=surface.path,
            title="MCP server is remote",
            detail=(
                "A remote server's tool list is controlled by whoever operates it "
                "and can differ between two sessions of the same commit. Nothing "
                "in this repository pins what it offers."
            ),
            evidence={"transport": transport, "server": surface.name},
        )


# ---------------------------------------------------------------------------
# Tool grants
# ---------------------------------------------------------------------------

#: Tools whose unconstrained grant is arbitrary execution or arbitrary fetch.
_EXECUTION_TOOLS = frozenset({"bash", "shell", "run", "execute", "task"})
_FETCH_TOOLS = frozenset({"webfetch", "websearch", "fetch"})

#: A rule body that constrains nothing: absent, `*`, or a bare wildcard pair.
_UNCONSTRAINED = re.compile(r"^\s*(\*|\*:\*|:\*)?\s*$")


def _grant_body(rule_text: str) -> str:
    if "(" not in rule_text:
        return ""
    return rule_text.split("(", 1)[1].rsplit(")", 1)[0]


@rule
def broad_execution_grant(ctx: RuleContext) -> Iterator[RepoRisk]:
    for surface in ctx.discovery.tool_grants:
        detail = surface.detail
        if detail.get("list") != "allow":
            continue
        rule_text = str(detail.get("rule", ""))
        tool = str(surface.name).lower()
        if not _UNCONSTRAINED.match(_grant_body(rule_text)):
            continue
        if tool in _EXECUTION_TOOLS:
            severity, what = "high", "arbitrary command execution"
        elif tool in _FETCH_TOOLS:
            severity, what = "medium", "arbitrary outbound requests"
        else:
            continue
        yield RepoRisk(
            rule_id="ASI-TOOL-BROAD-GRANT",
            severity=severity,  # type: ignore[arg-type]
            surface_kind="tool_grant",
            surface_id=surface.id,
            file=surface.path,
            title=f"{surface.name} is pre-approved without constraint",
            detail=(
                f"An allow rule with no argument pattern grants {what} for the "
                "whole session, with no prompt at the point of use."
            ),
            evidence={"rule": rule_text, "tool": surface.name},
        )


#: Modes that stop the permission system from asking. `bypassPermissions` is the
#: explicit one; `acceptEdits` narrows the blast radius to writes but still
#: removes the turn where a human would have seen the change.
_BYPASS_MODES = {"bypasspermissions": "critical", "acceptedits": "medium"}


@rule
def permission_mode_bypass(ctx: RuleContext) -> Iterator[RepoRisk]:
    settings = ctx.discovery.settings
    if settings is None:
        return
    mode = str(settings.detail.get("default_mode", "")).strip()
    severity = _BYPASS_MODES.get(mode.lower())
    if severity is None:
        return
    yield RepoRisk(
        rule_id="ASI-TOOL-PERMISSION-BYPASS",
        severity=severity,  # type: ignore[arg-type]
        surface_kind="settings",
        surface_id=settings.id,
        file=settings.path,
        title=f"Permission mode is {mode}",
        detail=(
            "The committed default removes the confirmation step for everyone who "
            "checks this repository out, not only for the author who chose it."
        ),
        evidence={"default_mode": mode},
    )


# ---------------------------------------------------------------------------
# Memory / RAG
# ---------------------------------------------------------------------------

#: `@path` imports in a Claude instruction file. Anchored to the line start so a
#: prose email address or a decorator does not match.
_IMPORT = re.compile(r"^\s*@([^\s#]+)")


@rule
def instruction_import_escapes(ctx: RuleContext) -> Iterator[RepoRisk]:
    """An instruction file that pulls in context from outside the repository.

    This is the memory/RAG inlet in its simplest form: the reviewed file stays
    unchanged while what it imports does not, and nothing in this checkout
    records what the imported file said at review time.
    """
    surfaces = [s for s in ctx.discovery.all_surfaces() if s.kind in {"instructions", "memory"}]
    for surface in surfaces:
        text = ctx.read_text(surface)
        if text is None:
            continue
        hits: list[int] = []
        outside: list[str] = []
        for number, line in enumerate(_lines(text), start=1):
            match = _IMPORT.match(line)
            if not match:
                continue
            target = match.group(1)
            if target.startswith(("/", "~")) or ".." in Path(target).parts:
                hits.append(number)
                # The declared location, not its contents. It is already in a
                # reviewed file, and naming it is the entire finding.
                outside.append(target[:120])
        if not hits:
            continue
        yield RepoRisk(
            rule_id="ASI-MEMORY-EXTERNAL-IMPORT",
            severity="medium",
            surface_kind=surface.kind,
            surface_id=surface.id,
            file=surface.path,
            title="Instruction imports context from outside the repository",
            detail=(
                "The import resolves outside this checkout, so what the model reads "
                "is not what this commit pins. Reviewing the diff does not review "
                "the instruction."
            ),
            evidence={**_positions(hits), "imports": sorted(set(outside))[:MAX_REPORTED_LINES]},
        )


@rule
def unreviewed_memory_store(ctx: RuleContext) -> Iterator[RepoRisk]:
    """A memory store exists and nothing evaluates what is in it.

    Fired once for the store rather than once per file: the risk is the
    retrieval inlet, and a hundred entries is the same inlet as one.
    """
    store = ctx.discovery.memory
    if not store:
        return
    yield RepoRisk(
        rule_id="ASI-MEMORY-UNREVIEWED-STORE",
        severity="medium",
        surface_kind="memory",
        surface_id=store[0].id,
        file=store[0].path,
        title="Repository carries a memory store the agent reads",
        detail=(
            "Retrieved context reaches the model with the same authority as the "
            "reviewed instructions, and no plane here evaluates its contents. "
            "AGT-XPIA-001 is the scenario shape that settles whether that matters."
        ),
        evidence={
            "entries": len(store),
            "total_bytes": sum(int(s.detail.get("bytes", 0)) for s in store),
        },
    )


def evaluate(ctx: RuleContext) -> list[RepoRisk]:
    """Run every rule. Order of the result is the caller's concern, not ours."""
    return [risk for fn in RULES for risk in fn(ctx)]
