UV ?= uv
SRC := attack_core tests scripts
LOCKED_RUNTIME_REQUIREMENTS := /tmp/attack-v19-core-runtime-requirements.txt
LOCKED_ALL_REQUIREMENTS := /tmp/attack-v19-core-all-requirements.txt
SBOM := /tmp/attack-v19-core-sbom.json

.PHONY: install data lint format typecheck test build security sbom verify

install:
	$(UV) sync --locked --extra dev --extra security

data:
	$(UV) run python scripts/download_attack_data.py

lint:
	$(UV) run ruff check $(SRC)
	$(UV) run ruff format --check $(SRC)

format:
	$(UV) run ruff format $(SRC)

typecheck:
	$(UV) run pyright attack_core scripts/download_attack_data.py

test: data
	PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 $(UV) run pytest tests -q

build:
	$(UV) build
	$(UV) run check-wheel-contents --toplevel attack_core,attack_v19_core dist/*.whl

security:
	$(UV) run bandit -r attack_core scripts -ll
	$(UV) export --locked --no-dev --no-emit-project --format requirements-txt --output-file $(LOCKED_RUNTIME_REQUIREMENTS)
	$(UV) export --locked --all-extras --no-emit-project --format requirements-txt --output-file $(LOCKED_ALL_REQUIREMENTS)
	$(UV) run pip-audit --requirement $(LOCKED_RUNTIME_REQUIREMENTS)
	$(UV) run pip-audit --requirement $(LOCKED_ALL_REQUIREMENTS)

sbom:
	$(UV) export --locked --no-dev --no-emit-project --format requirements-txt --output-file $(LOCKED_RUNTIME_REQUIREMENTS)
	$(UV) run pip-audit --requirement $(LOCKED_RUNTIME_REQUIREMENTS) --format cyclonedx-json --output $(SBOM)

verify: lint typecheck test security build sbom
