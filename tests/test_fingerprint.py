"""Runtime-agent fingerprinting stays distinct from coding-agent config."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agentsec.models.fingerprint import FingerprintReport, RuntimeAgentFingerprint
from agentsec.project import fingerprint_repository


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def runtime(report: FingerprintReport, framework: str) -> RuntimeAgentFingerprint:
    matches = [item for item in report.runtime_agents if item.framework == framework]
    assert len(matches) == 1
    return matches[0]


def test_langgraph_builder_is_confirmed_with_a_relative_entrypoint(tmp_path: Path) -> None:
    write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "graph-app"\nversion = "0.1.0"\n'
        'dependencies = ["langgraph>=0.2"]\n',
    )
    write(
        tmp_path / "src" / "agent" / "graph.py",
        "from langgraph.graph import StateGraph\n\n"
        "builder = StateGraph(dict)\n"
        "app = builder.compile()\n",
    )

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "confirmed"
    assert report.confidence == "high"
    graph = runtime(report, "langgraph")
    assert graph.confidence == "high"
    assert graph.entrypoints == ["src/agent/graph.py"]
    assert {(item.kind, item.value) for item in graph.evidence} >= {
        ("dependency", "langgraph>=0.2"),
        ("import", "langgraph.graph"),
        ("builder_call", "StateGraph"),
    }


def test_a_dependency_without_a_builder_is_likely_not_confirmed(tmp_path: Path) -> None:
    write(tmp_path / "requirements.txt", "crewai==1.2.3\n")

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "likely"
    assert report.confidence == "medium"
    crew = runtime(report, "crewai")
    assert crew.entrypoints == []
    assert crew.confidence == "medium"


@pytest.mark.parametrize(
    ("framework", "dependency", "source"),
    [
        (
            "langchain",
            "langchain",
            "from langchain.agents import create_agent\n"
            "agent = create_agent(model='openai:test', tools=[])\n",
        ),
        (
            "openai_agents",
            "openai-agents",
            "from agents import Agent, Runner\n"
            "agent = Agent(name='triage', instructions='help')\n",
        ),
        (
            "autogen",
            "autogen-agentchat",
            "from autogen_agentchat.agents import AssistantAgent\n"
            "agent = AssistantAgent('triage', model_client=None)\n",
        ),
        (
            "semantic_kernel",
            "semantic-kernel",
            "from semantic_kernel.agents import ChatCompletionAgent\n"
            "agent = ChatCompletionAgent(name='triage')\n",
        ),
    ],
)
def test_current_official_python_builders_are_confirmed(
    tmp_path: Path, framework: str, dependency: str, source: str
) -> None:
    write(tmp_path / "requirements.txt", dependency + "\n")
    write(tmp_path / "src" / "agent.py", source)

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "confirmed"
    item = runtime(report, framework)
    assert item.entrypoints == ["src/agent.py"]


def test_a_local_module_named_agents_is_not_attributed_to_openai(tmp_path: Path) -> None:
    write(tmp_path / "app.py", "from agents import Agent\nagent = Agent()\n")

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "not_detected"
    assert report.runtime_agents == []


def test_development_agent_files_are_configuration_only(tmp_path: Path) -> None:
    write(tmp_path / "CLAUDE.md", "Project instructions.\n")
    write(tmp_path / ".claude" / "skills" / "review" / "SKILL.md", "# Review\n")
    write(
        tmp_path / ".claude" / "skills" / "review" / "examples" / "agent.py",
        "from langgraph.graph import StateGraph\ngraph = StateGraph(dict)\n",
    )
    write(tmp_path / "AGENTS.md", "Codex instructions.\n")
    write(tmp_path / ".mcp.json", json.dumps({"mcpServers": {}}))

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "configuration_only"
    assert report.runtime_agents == []
    configs = {item.platform: item.paths for item in report.development_agent_config}
    assert configs["claude_code"] == [".claude", "CLAUDE.md"]
    assert configs["codex"] == ["AGENTS.md"]
    assert configs["mcp"] == [".mcp.json"]


def test_an_mcp_config_alone_never_claims_a_runtime_agent(tmp_path: Path) -> None:
    write(
        tmp_path / ".mcp.json",
        json.dumps({"mcpServers": {"tools": {"command": "python", "args": ["server.py"]}}}),
    )
    write(tmp_path / "server.py", "def main():\n    return 'ordinary protocol server'\n")

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "configuration_only"
    assert report.runtime_agents == []


def test_an_ordinary_repository_is_not_detected_and_not_called_secure(tmp_path: Path) -> None:
    write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "web"\nversion = "1.0.0"\ndependencies = ["httpx"]\n',
    )
    write(tmp_path / "src" / "web.py", "def health():\n    return {'ok': True}\n")

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "not_detected"
    assert report.confidence == "none"
    assert report.runtime_agents == []
    assert "secure" not in json.dumps(report.to_dict())


def test_custom_python_tool_calling_is_likely_not_framework_confirmed(tmp_path: Path) -> None:
    write(
        tmp_path / "agent.py",
        "from openai import OpenAI\n\n"
        "client = OpenAI()\n"
        "response = client.chat.completions.create(model='x', messages=[], tools=[])\n"
        "for call in response.choices[0].message.tool_calls:\n"
        "    print(call.id)\n",
    )

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "likely"
    custom = runtime(report, "custom_tool_calling")
    assert custom.confidence == "medium"
    assert custom.entrypoints == ["agent.py"]


def test_openai_agents_typescript_builder_is_confirmed(tmp_path: Path) -> None:
    write(
        tmp_path / "package.json",
        json.dumps({"dependencies": {"@openai/agents": "1.0.0"}}),
    )
    write(
        tmp_path / "src" / "agent.ts",
        'import { Agent } from "@openai/agents";\n'
        'const agent = new Agent({ name: "triage", instructions: "help" });\n',
    )

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "confirmed"
    agent = runtime(report, "openai_agents")
    assert agent.language == "typescript"
    assert agent.entrypoints == ["src/agent.ts"]


def test_current_crewai_json_first_project_is_confirmed(tmp_path: Path) -> None:
    write(
        tmp_path / "crew.jsonc",
        "// JSON-first CrewAI project\n"
        "{\n"
        '  "source": "https://example.com/crew//definition",\n'
        '  "agents": ["agents/researcher.jsonc"],\n'
        '  "tasks": [{"agent": "researcher"}],\n'
        "}\n",
    )

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "confirmed"
    crew = runtime(report, "crewai")
    assert crew.entrypoints == ["crew.jsonc"]
    assert any(item.kind == "runtime_config" for item in crew.evidence)


def test_an_unparseable_candidate_manifest_is_unsupported_not_absent(tmp_path: Path) -> None:
    write(tmp_path / "pyproject.toml", "[project\nthis is not TOML\n")

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "unsupported"
    assert report.confidence == "none"
    assert any(problem.kind == "invalid_manifest" for problem in report.problems)


def test_repository_source_is_parsed_but_never_imported(tmp_path: Path) -> None:
    sentinel = tmp_path / "executed.txt"
    write(
        tmp_path / "agent.py",
        "from langgraph.graph import StateGraph\n"
        f"open({str(sentinel)!r}, 'w').write('executed')\n"
        "graph = StateGraph(dict)\n",
    )

    report = fingerprint_repository(tmp_path)

    assert report.agent_presence == "confirmed"
    assert not sentinel.exists()


def test_a_source_symlink_outside_the_repository_is_not_read(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = write(
        tmp_path / "outside.py",
        "from langgraph.graph import StateGraph\ngraph = StateGraph(dict)\n",
    )
    (root / "agent.py").symlink_to(outside)

    report = fingerprint_repository(root)

    assert report.agent_presence == "unsupported"
    assert any(problem.kind == "outside_root_symlink" for problem in report.problems)


def test_entrypoints_are_stable_when_the_checkout_moves(tmp_path: Path) -> None:
    first = tmp_path / "first"
    write(
        first / "src" / "crew.py",
        "from crewai import Crew\ncrew = Crew(agents=[], tasks=[])\n",
    )
    second = tmp_path / "another-location"
    shutil.copytree(first, second)

    first_report = fingerprint_repository(first).to_dict()
    second_report = fingerprint_repository(second).to_dict()

    assert first_report == second_report


def test_evidence_never_contains_source_text(tmp_path: Path) -> None:
    secret = "customer-secret-should-stay-in-source"
    write(
        tmp_path / "agent.py",
        "from langgraph.graph import StateGraph\n"
        f"SECRET = {secret!r}\n"
        "graph = StateGraph(dict)\n",
    )

    report = fingerprint_repository(tmp_path)

    assert secret not in json.dumps(report.to_dict())
