.PHONY: help install test lint types skill-static check demo report clean schemas

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## install with dev extras
	pip install -e '.[dev]'

test:  ## run the test suite
	pytest -q

lint:  ## ruff
	ruff check src tests

types:  ## mypy
	mypy

skill-static:  ## deterministic static Skill Assurance (no model or credentials)
	agentsec skill validate --profile static

check: lint types test skill-static  ## local lint, types, tests and skill integrity

demo:  ## offline pipeline; expected run exit 1 is ignored, so this target succeeds
	agentsec validate --strict
	agentsec preview --target demo-agent-fixture --profile nightly
	-agentsec run --target demo-agent-fixture --profile nightly --html

report:  ## regenerate reports from stored runs
	agentsec report --target demo-agent-fixture --format html --format json --format junit

schemas:  ## regenerate the JSON Schema for output models (Run, Verdict, Finding)
	@mkdir -p schemas/generated
	@python -c "import json,pathlib; \
from agentsec.models.run import Run, Verdict; \
from agentsec.models.finding import Finding; \
[pathlib.Path(f'schemas/generated/{n}.schema.json').write_text(json.dumps(m.model_json_schema(), indent=2)+chr(10)) \
 for n, m in (('run', Run), ('verdict', Verdict), ('finding', Finding))]; \
print('wrote schemas/generated/')"

clean:
	rm -rf results .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
