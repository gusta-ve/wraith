# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/).

## [0.4.1] - 2026-06-11

### Added
- `-u` / `--url` to give the target like other scanners (`wraith -u https://host`);
  a full URL is normalised to its host, and an explicit port is added to the scan.
- The scan options (`-u`, `-p`, `-s`, `-x`, `-v`, …) now show in `wraith -h`
  itself, not only `wraith run -h`.

### Changed
- Cosmetic flags (`--theme`, `--no-color`, `--no-banner`) work in any position,
  including after the target.

### Fixed
- Ctrl-C during a scan now exits cleanly (`[-] interrupted`, status 130) instead
  of dumping an asyncio `KeyboardInterrupt` traceback.

## [0.4.0] - 2026-06-11

### Added
- `injection` is now a real active-testing engine with two-step confirmation —
  every hit is proven a second way before it's reported:
  - **SQLi (boolean-blind)** — a TRUE condition returns the normal page while a
    FALSE one diverges, confirmed across two injection contexts.
  - **SQLi (time-blind)** — a SLEEP/pg_sleep/WAITFOR payload delays the
    response, confirmed by a second, longer sleep whose delay tracks the time
    injected (rules out network lag).
  - **Command injection** — a `; sleep N` payload delays the response (same
    time-correlation proof); reported Critical.
  - **SSTI** — `{{a*b}}` comes back evaluated (the product, not the
    expression), confirmed with a second random product.
  - **Path traversal / LFI** — `../../etc/passwd` returns a `root:x:0:0:`
    signature absent from the baseline, read twice to confirm.
  - Error-based SQLi now confirms with a *balanced* quote (which must not
    error), so an unrelated 500 can't pass for injection.
- `-v` / `--verbose` — phases narrate the attack: every payload, its oracle
  measurement (similarity ratios, response timings) and the confirmation step.
- `examples/vuln_app.py` gained boolean/time-blind SQLi, command injection,
  SSTI and LFI endpoints (and is now threaded so concurrent timing probes don't
  queue), exercising every new technique.

## [0.3.3] - 2026-06-10

### Changed
- Published to PyPI as `wraith-sec` (the name `wraith` was taken) — install with
  `pipx install wraith-sec`; the command is still `wraith`. Releases now build
  and publish to PyPI automatically via Trusted Publishing.

## [0.3.2] - 2026-06-10

### Added
- `wraith login` now reads the login form on the page: it submits to the form's
  real `action` and carries every hidden field, so anti-CSRF tokens (ASP.NET
  `__RequestVerificationToken`, Django `csrfmiddlewaretoken`, Rails
  `authenticity_token`...) ride along and the login actually succeeds.

### Fixed
- `access-control` no longer reports false bypasses against single-page apps: a
  lower principal redirected away (to login or its own area) is treated as
  denied, static assets and framework files are excluded, and a resource a
  no-cookie request can already read is suppressed as public.

## [0.3.1] - 2026-06-10

### Fixed
- `http-probe` now probes the original hostname instead of the resolved IP, so
  SNI / virtual-hosted sites respond (raw-IP probing fails TLS on modern hosts);
  the IPv4/IPv6 pair of a service collapses to one probe.
- `content-discovery` no longer reports blanket redirects (e.g. HTTP→HTTPS) as
  discovered paths — if a random path is redirected too, it's not a hit.
- `vhost` baselines against a host that can't exist and drops candidates that
  match it, so catch-all servers stop inventing virtual hosts.

## [0.3.0] - 2026-06-10

### Added
- `run` is the default command (`wraith TARGET`, no subcommand needed), short
  flags (`-p -s -w -t -x -c -l`) and a `--help` with copy-paste examples.
- End-of-run vulnerability report — a clean, severity-coloured, deduplicated
  list of everything exploitable (Low and up); Info noise stays in the files.
- `wraith showdown` — a toggleable mode (off by default, sticks between runs)
  that plays a run's catch out: findings called out live, the hooded spectre
  revealed, the kill-chain retold, each finding shown with its evidence, and a
  poker verdict on the target. Flagged in the banner while on.

### Fixed
- `access-control` reports one finding per bypassed resource (was one per
  session), so counts and the report no longer double up.

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
