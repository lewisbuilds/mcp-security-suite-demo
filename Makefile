SHELL := /bin/bash
PYTHON ?= python3
IMAGE ?= nginx:1.27
VENV  ?= .venv

.PHONY: help
help:
	@echo "Targets:"
	@echo "  venv         - create venv and install server deps"
	@echo "  run-servers  - run all four MCP servers (foreground, each in its own terminal recommended)"
	@echo "  demo         - run end-to-end demo (SBOM->Vuln->Policy->Report)"
	@echo "  docker-build - build all MCP server images"
	@echo "  clean        - remove caches"

$(VENV)/bin/activate: servers/sbom/requirements.txt servers/vuln/requirements.txt servers/policy/requirements.txt servers/report/requirements.txt
	$(PYTHON) -m venv $(VENV)
	source $(VENV)/bin/activate && pip install -U pip
	source $(VENV)/bin/activate && pip install -r servers/sbom/requirements.txt -r servers/vuln/requirements.txt -r servers/policy/requirements.txt -r servers/report/requirements.txt
	touch $(VENV)/bin/activate

venv: $(VENV)/bin/activate

run-servers: venv
	source $(VENV)/bin/activate && \
		($(PYTHON) -m servers.sbom.app &) && \
		($(PYTHON) -m servers.vuln.app &) && \
		($(PYTHON) -m servers.policy.app &) && \
		($(PYTHON) -m servers.report.app &) && \
		echo "Servers started (check logs)."

demo:
	DEMO_IMAGE=$(IMAGE) $(PYTHON) scripts/demo_supplychain.py

docker-build:
	docker build -t mcp-sbom:0.1.0   servers/sbom
	docker build -t mcp-vuln:0.1.0   servers/vuln
	docker build -t mcp-policy:0.1.0 servers/policy
	docker build -t mcp-report:0.1.0 servers/report

clean:
	rm -rf $(VENV) __pycache__ */__pycache__ .pytest_cache demo-report.json

.PHONY: print-report
print-report:
	@python - <<'PY'
import json,sys
from pathlib import Path
p=Path("demo-report.json")
assert p.exists(), "demo-report.json not found. Run 'make demo' first."
d=json.loads(p.read_text())
print("Image:", d.get("image"))
print("Status:", d.get("status"))
v=d.get("vulns",{})
print("Vulns - critical:", v.get("critical"), "high:", v.get("high"), "total:", v.get("total"))
PY

.PHONY: lint
lint:
	@command -v pre-commit >/dev/null 2>&1 && pre-commit run --all-files || echo "pre-commit not installed; skip"
