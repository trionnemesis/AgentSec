"""Error taxonomy.

Every error carries a stable ``code``. The MCP gateway surfaces the code and the
message but never a traceback: stack traces leak paths and internals to whatever
is on the other end of the protocol.
"""

from __future__ import annotations


class AgentSecError(Exception):
    code = "agentsec_error"

    def __init__(self, message: str, *, details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, object]:
        return {"error": self.code, "message": self.message, "details": self.details}


class ScenarioError(AgentSecError):
    code = "scenario_invalid"


class ContractError(AgentSecError):
    """An assertion is malformed in a way that makes it unevaluatable.

    Raised during evaluation rather than returned as "did not occur": a
    ``must_not`` whose assertion is broken would otherwise report a pass, which
    is the most dangerous possible way to be wrong.
    """

    code = "contract_error"


class ScenarioNotFound(AgentSecError):
    code = "scenario_not_found"


class TargetNotFound(AgentSecError):
    code = "target_not_found"


class PolicyViolation(AgentSecError):
    """The request was well-formed but policy declined it."""

    code = "policy_violation"


class ApprovalRequired(AgentSecError):
    code = "approval_required"


class ExecutorUnavailable(AgentSecError):
    """The executor is not installed or not permitted for this target."""

    code = "executor_unavailable"


class ExecutionFailed(AgentSecError):
    code = "execution_failed"


class EvidenceUnavailable(AgentSecError):
    code = "evidence_unavailable"


class RunNotFound(AgentSecError):
    code = "run_not_found"


class FindingNotFound(AgentSecError):
    code = "finding_not_found"


class InvalidTransition(AgentSecError):
    code = "invalid_transition"


class ConfigError(AgentSecError):
    code = "config_error"


class ProjectError(ConfigError):
    """The project manifest is present but does not describe a usable project."""

    code = "project_invalid"


class ProjectNotInitialised(ConfigError):
    """No ``.agentsec/project.yaml``. Run ``agentsec init``.

    Distinct from a malformed manifest on purpose: one is a repository nobody has
    onboarded yet, the other is a repository whose onboarding is wrong, and only
    the second is a reason to distrust what is already there.
    """

    code = "project_not_initialised"


class UnsafePath(ProjectError):
    """A declared location escapes the project root, or is not a location at all.

    Raised before the path is read. A manifest naming ``../../secret`` must be
    refused rather than read and then rejected.
    """

    code = "path_escapes_project"
