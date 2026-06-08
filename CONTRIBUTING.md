# Contributing

Thanks for taking a look. wraith is built to be extended — most new capability
is a single file.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The core runs on the standard library; `httpx` is an optional speed-up
(`pip install -e ".[http]"`).

## Ways to contribute

- **A new phase** — see [docs/writing-a-phase.md](docs/writing-a-phase.md).
- **A new template** — see [docs/writing-a-template.md](docs/writing-a-template.md).
  Templates need no Python.
- **Tech-detect signatures** — extend the maps in `wraith/phases/tech_detect.py`.

## Ground rules

- Keep detection low false-positive; add a test that proves it.
- Run `pytest` before opening a PR — CI runs it on Python 3.10–3.12.
- Only test against systems you own or are authorized to test. The `examples/`
  lab is there for exactly this.

## Trying changes against the lab

```bash
python3 examples/vuln_app.py &
wraith run 127.0.0.1
```
