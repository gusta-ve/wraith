.PHONY: install dev test lab run clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest -q

lab:
	python3 examples/vuln_app.py

run:
	wraith run 127.0.0.1 --sessions examples/sessions.json

clean:
	rm -rf wraith-runs build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
