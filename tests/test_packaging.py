"""The Claude Desktop registration, and the page it feeds.

Most of the Desktop smoke test needs a person at the application. Three of its
seven steps do not, and those are the three where being wrong is expensive: that
the registration pins read-only, that a server started that way has no execution
tool to offer, and that the page rendered from it carries no observation the
gateway would have withheld.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agentsec.mcp.contract import TOOLS, published_resources
from agentsec.reporting.html import render_dashboard
from agentsec.reporting.publish import publish
from agentsec.service.harness import HarnessService
from tests.conftest import REPO_ROOT

PACKAGING = REPO_ROOT / "packaging" / "claude-desktop"
MANIFEST = PACKAGING / "manifest.json"
DESKTOP_CONFIG = PACKAGING / "claude_desktop_config.example.json"

#: The order id AGT-TENANT-001 leaks across the tenant boundary. It appears on
#: the page, and correctly so: the page shows it inside the *assertion text*,
#: which quotes a value the scenario author committed. It is declared
#: configuration there and observed data in the transcript, and only the second
#: is withheld — see `docs/deployment.md`. So its presence proves nothing either
#: way, and the tests below assert against the transcript instead.
DECLARED_IN_CONTRACT = "ORD-B-77421"


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _registration_env(config: dict) -> dict[str, str]:
    return config["server"]["mcp_config"]["env"]


# -- the registration ---------------------------------------------------------


def test_the_bundle_registers_the_console_script_this_package_installs() -> None:
    """A rename should break the build rather than a user's install."""
    import tomllib

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = pyproject["project"]["scripts"]

    command = _manifest()["server"]["mcp_config"]["command"]
    assert command in scripts, f"{command!r} is not a console script of this package"
    assert scripts[command] == "agentsec.mcp.server:main"


@pytest.mark.parametrize("path", [MANIFEST, DESKTOP_CONFIG])
def test_every_desktop_registration_pins_read_only(path: Path) -> None:
    """Without this the entry is an execution host with a dashboard attached."""
    config = json.loads(path.read_text(encoding="utf-8"))
    servers = config.get("mcpServers")
    envs = (
        [entry["env"] for entry in servers.values()]
        if servers
        else [_registration_env(config)]
    )
    assert envs
    for env in envs:
        assert env.get("AGENTSEC_MCP_READ_ONLY") == "1", path.name


def test_the_workspace_comes_from_the_user_not_from_a_tool_argument() -> None:
    """Directory selection at the process boundary; no AgentSec tool takes a path."""
    manifest = _manifest()
    assert manifest["user_config"]["workspace"]["type"] == "directory"
    assert manifest["user_config"]["workspace"]["required"] is True
    assert _registration_env(manifest)["AGENTSEC_WORKSPACE"] == "${user_config.workspace}"


def test_the_registered_server_offers_no_way_to_execute(monkeypatch, settings) -> None:  # noqa: ANN001
    """The claim in the README, made against the real registration.

    Skipped without the `mcp` extra, like the rest of the gateway tests; CI runs
    it in the gateway job.
    """
    pytest.importorskip("mcp", reason="needs the 'mcp' extra")
    from agentsec.mcp.server import build_server

    for key, value in _registration_env(_manifest()).items():
        if not value.startswith("${"):
            monkeypatch.setenv(key, value)
    monkeypatch.setenv("AGENTSEC_WORKSPACE", str(settings.workspace))

    server = build_server()
    registered = set(server._tool_manager._tools)  # noqa: SLF001
    assert registered == {t.name for t in TOOLS if t.read_only}
    for absent in ("agentsec_start_run", "agentsec_promote_finding", "agentsec_generate_report"):
        assert absent not in registered

    manager = server._resource_manager  # noqa: SLF001
    served = {str(r.uri_template) for r in manager._templates.values()} | {  # noqa: SLF001
        str(r.uri) for r in manager._resources.values()  # noqa: SLF001
    }
    assert served == {r.uri_template for r in published_resources()}


def test_the_readme_documents_the_steps_a_machine_cannot_check() -> None:
    """The smoke test is a deliverable; a missing row is a step nobody runs."""
    readme = (PACKAGING / "README.md").read_text(encoding="utf-8")
    for step in ("agentsec init", "AGENTSEC_MCP_READ_ONLY", "agentsec://dashboard/latest"):
        assert step in readme
    assert readme.count("|") > 40, "the step table should still be a table"


# -- the page -----------------------------------------------------------------


@pytest.fixture
def rendered(service: HarnessService) -> tuple[str, list[str]]:
    """The page, plus the transcript the runs behind it actually produced."""
    result = service.start_run(target_id="demo-agent-fixture", profile="nightly")
    document = publish("dashboard", service.dashboard())
    findings = publish("findings", service.list_findings())["findings"]

    transcripts: list[str] = []
    for run in result.runs:
        bundle = service.get_run_evidence(run.run_id)
        transcripts += [
            turn["content"]
            for turn in bundle.get("sources", {}).get("transcript", {}).get("turns", [])
        ]
    return render_dashboard(document, findings), transcripts


@pytest.fixture
def page(rendered: tuple[str, list[str]]) -> str:
    return rendered[0]


def test_the_page_is_self_contained(page: str) -> None:
    """No CDN, no font host, no analytics: it opens from a ticket, offline."""
    external = re.findall(r'(?:src|href)\s*=\s*["\'](?!#)([^"\']+)', page)
    assert external == [], f"external references: {external}"
    assert "//" not in re.sub(r"https?://", "", "".join(external))


def test_the_page_carries_no_transcript(rendered: tuple[str, list[str]]) -> None:
    """The transcript is where the leak lives; the page renders none of it.

    `AGT-TENANT-001` gets tenant B's order record into tenant A's transcript, so
    that transcript is both the evidence of the finding and, verbatim, the record
    that leaked. What the page shows instead is the evaluator's account of which
    assertion failed.
    """
    page, transcripts = rendered
    assert transcripts, "the fixture corpus should have produced a transcript"
    for content in transcripts:
        assert content not in page
    assert "evidence_ref" not in page
    assert "apr_" not in page


def test_the_page_still_says_which_assertion_failed(page: str) -> None:
    """Redaction that costs the reader the finding is not worth deploying."""
    assert DECLARED_IN_CONTRACT in page, "the assertion quotes a contract value"
    assert "output_contains" in page


def test_the_page_states_untested_axes_rather_than_omitting_them(page: str) -> None:
    assert "not_tested" in page
    assert "never rounds up" in page
    # The response axis is untested twice in the bundled corpus.
    assert "2 not tested" in page


def test_the_two_planes_are_rendered_apart(page: str) -> None:
    assert "Purple — attack &amp; detection" in page
    assert "Skill Assurance" in page
    assert "not_evaluated" not in page


def test_the_page_offers_every_filter_the_reader_was_promised(page: str) -> None:
    for axis in ('data-verdict="gap"', 'data-severity=', 'data-tested="partial"',
                 'id="scenario-filter"'):
        assert axis in page


def test_the_page_says_what_it_cannot_do(page: str) -> None:
    """A reader should not have to take the read-only claim on trust from a title."""
    assert "start no run" in page
    assert "no language model participates" in page.lower()


def test_an_uninitialised_project_is_visible_on_the_page(service: HarnessService) -> None:
    document = publish("dashboard", service.dashboard())
    page = render_dashboard(document)
    assert "project not initialised" in page
    assert "does not know which repository" in page
