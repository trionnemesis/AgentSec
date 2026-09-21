"""Two real Git repositories; install committed producer code, run from the consumer.

This checks the package/CLI boundary in CI without a second hosted repository.
It does not claim to exercise GitHub's remote workflow_call dispatch.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from tests.conftest import REPO_ROOT


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _commit(root: Path) -> str:
    _git(root, "init", "--quiet")
    _git(root, "add", ".")
    _git(root, "-c", "user.name=AgentSec test", "-c", "user.email=test@example.invalid",
         "commit", "--quiet", "-m", "isolated consumer regression")
    return _git(root, "rev-parse", "HEAD")


def test_install_from_pinned_producer_and_run_from_another_repository(tmp_path):
    producer = tmp_path / "producer"
    consumer = tmp_path / "consumer"
    install = tmp_path / "installed"
    producer.mkdir()
    consumer.mkdir()
    for name in ("pyproject.toml", "README.md"):
        shutil.copyfile(REPO_ROOT / name, producer / name)
    for name in ("src", "schemas", "scenarios"):
        shutil.copytree(REPO_ROOT / name, producer / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "_data"))
    commit = _commit(producer)
    for name in ("policy", "fixtures"):
        shutil.copytree(REPO_ROOT / name, consumer / name)
    _commit(consumer)
    assert not (consumer / "pyproject.toml").exists()
    assert not (consumer / "scenarios").exists()

    env = dict(os.environ)
    for name in ("PYTHONPATH", "AGENTSEC_WORKSPACE", "AGENTSEC_DB",
                 "AGENTSEC_EXPECTED_SHA", "AGENTSEC_CATALOGUE"):
        env.pop(name, None)
    install_result = subprocess.run([
        sys.executable, "-m", "pip", "install", "--no-deps", "--no-build-isolation",
        "--no-cache-dir", "--no-index", "--target", str(install),
        f"git+{producer.as_uri()}@{commit}",
    ], cwd=consumer, env=env, text=True, capture_output=True, timeout=120)
    assert install_result.returncode == 0, install_result.stdout + install_result.stderr
    # Remove the producer: a checkout-relative fallback can no longer rescue the test.
    shutil.rmtree(producer)

    probe = r'''
import json, os, pathlib, sys
from xml.etree import ElementTree as ET
sys.path.insert(0, sys.argv[1])
os.environ['AGENTSEC_EXPECTED_SHA'] = sys.argv[2]
os.environ['AGENTSEC_CATALOGUE'] = 'builtin'
from agentsec import installation
from agentsec.cli import app
from agentsec.errors import ConfigError
from agentsec.service.harness import HarnessService
from agentsec.reporting.publish import publish
from typer.testing import CliRunner
assert pathlib.Path(installation.__file__).is_relative_to(pathlib.Path(sys.argv[1]))
assert installation.package_identity(sys.argv[2])[1] == sys.argv[2]
service = HarnessService()
assert len(service.catalog.ids()) == 8
for entry in service.catalog:
    assert entry.path.is_relative_to(pathlib.Path(sys.argv[1]))
runner = CliRunner()
validation = runner.invoke(app, ['validate', '--strict'])
assert validation.exit_code == 0, validation.output
result = runner.invoke(app, ['run', '--target', 'demo-agent-fixture', '--profile', 'nightly',
                            '--output', 'junit', '--output-file', 'results/agentsec.xml'])
assert result.exit_code == 1, result.output
report = service.generate_report(target_id='demo-agent-fixture', profile='nightly')
batch = json.loads(pathlib.Path(report['written']['json']).read_text())
assert batch['total_runs'] == 4
assert set(batch['blocking_scenarios']) == {'AGT-TENANT-001', 'AGT-MEMPOIS-001'}
assert batch['provenance_counts'] == {'recorded': 4, 'live': 0, 'mixed': 0}
assert any(r['purple_verdict'] == 'secure' for r in batch['runs'])
sources = {r['run_id']: r['source_provenance'] for r in batch['runs']}
for source in sources.values():
    assert source['package_commit'] == sys.argv[2]
    assert source['catalogue_ref'] == sys.argv[2]
    assert source['catalogue_origin'] == 'builtin'
published = publish('report', batch)
assert published['runs'] == batch['runs']
html = pathlib.Path(report['written']['html']).read_text()
assert sys.argv[2] in html
cases = ET.parse('results/agentsec.xml').getroot().findall('testcase')
assert len(cases) == 4
for case in cases:
    props = {p.attrib['name']: p.attrib['value'] for p in case.findall('properties/property')}
    source = sources[props['agentsec.run_id']]
    assert props['agentsec.source.package_commit'] == source['package_commit']
    assert props['agentsec.source.scenario_digest'] == source['scenario_digest']
os.environ['AGENTSEC_EXPECTED_SHA'] = 'b' * 40
try:
    HarnessService().catalog
except ConfigError:
    pass
else:
    raise AssertionError('wrong installed commit was accepted')
assert len(service.list_runs()) == 4
print('跨 repo 安裝與報表驗證通過 / Cross-repository installation and reports verified')
'''
    checked = subprocess.run([sys.executable, "-I", "-c", probe, str(install), commit],
                             cwd=consumer, env=env, text=True, capture_output=True, timeout=120)
    assert checked.returncode == 0, checked.stdout + checked.stderr
