"""Statically-observed agent-configuration findings — input, never a verdict.

A rules-based scanner such as AgentShield can say a hook interpolates
untrusted input into a shell command, or that an MCP server's ``env`` block
looks credential-shaped. It cannot say whether an attack that exploits it
would succeed, or whether the blue side would see it happen — that is what an
Attack-Detection Contract answers (ADR 0002), and nothing here may substitute
for one. See issue #25: a :class:`StaticPostureFinding` widens no
``PurpleVerdict``, adds no axis, and grades nothing. It is composed alongside
the purple and Skill Assurance planes, never merged into either.

Deliberately does not carry the matched snippet or any quoted source text: a
scanner can flag a line that contains a real secret, and this is the shape
that reaches ``reporting/publish.py``. ``file`` is a location and ``title`` is
the scanner's own rule description; neither is expected to quote target
output the way an evidence record can.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]

#: Worst -> best, mirroring the scanner's own convention. Used only to order a
#: rendered panel; never compared against a PurpleVerdict or an AxisStatus.
SEVERITY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")

#: Three states a finding's coverage can be in. `not_tested` is the default —
#: see `posture/coverage.py`. A finding is `covered` only once a scenario that
#: exercises its surface has actually produced a verdict, not merely because
#: one exists in the catalogue.
CoverageState = Literal["covered", "not_tested", "n/a"]


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class StaticPostureFinding(_Base):
    """One rule firing from a static scanner."""

    rule_id: str
    severity: Severity
    category: str
    file: str
    title: str
    source_tool: str
    source_version: str | None = None


class PostureReport(_Base):
    """A normalised scan, before correlation against the project's surfaces."""

    source_tool: str
    source_version: str | None = None
    findings: list[StaticPostureFinding] = Field(default_factory=list)
