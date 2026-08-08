PYTHON ?= python
PIP ?= $(PYTHON) -m pip
SRC := attack_core tests scripts

.PHONY: install data lint format test build security dashboard verify

install:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install -e .
	$(PIP) install build ruff bandit pip-audit

data:
	$(PYTHON) scripts/download_attack_data.py

lint:
	$(PYTHON) -m ruff check $(SRC)

format:
	$(PYTHON) -m ruff format $(SRC)

test: data
	$(PYTHON) -m pytest tests -q

build:
	$(PYTHON) -m build

security:
	$(PYTHON) -m bandit -r attack_core scripts -ll
	$(PYTHON) -m pip_audit -r requirements.txt

dashboard:
	$(PYTHON) -m http.server 8080 --directory dashboard

verify: lint test build security