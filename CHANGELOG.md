# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] - 2026-06-09

### Added
- ASCII banner with truecolor gradient and selectable themes
  (`--theme crimson|matrix|ice|amber|mono`), severity-coloured findings and an
  end-of-run severity summary. `--no-color` / `--no-banner` / `WRAITH_THEME`.
- `security-headers` phase — audits security headers, cookie flags and CORS.
- `injection` phase — reflected XSS, error-based SQLi and open redirect on
  discovered query/form parameters.
- `wraith login` — authenticate to a form login and emit a `sessions.json`.
- JSON findings output (`findings.json`) and `--fail-on <severity>` for CI gating.
- `--version`.
- Expanded `examples/vuln_app.py` lab (XSS, SQLi, open redirect, CORS, insecure
  cookie, missing headers, login) and contributor docs under `docs/`.

## [0.1.0]

### Added
- Phase engine: DAG scheduling, async workers, failure isolation, persisted
  workspace, Markdown + dark HTML reports.
- Phases: `resolve`, `tcp-scan`, `http-probe`, `content-discovery`,
  `tech-detect`, `vhost`, `template-checks`, `access-control` (Broken Access
  Control + IDOR).
- `wraith shell` — reverse-shell handler with multi-listener, PTY upgrade and
  payload generation.
- pytest suite and GitHub Actions CI (Python 3.10–3.12).
