# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/).

## [0.5.3] - 2026-06-11

### Fixed
- The showdown scoreboard now shows the two black aces (`A♠ A♣`), matching the
  reveal — the old red-heart ace was a leftover from before the dead man's hand.

## [0.5.2] - 2026-06-11

### Changed
- A slow phase now shows a live spinner on a terminal — a little block that
  turns with the running phase and its elapsed time — so you're never left
  staring at a frozen screen, at any verbosity. Piped/CI output keeps the
  every-15s text line instead (no escape-code noise in logs).

## [0.5.1] - 2026-06-11

### Added
- When a run catches a code-execution foothold (command injection, SSTI, …),
  the summary points at hickok with the ready command
  (`hickok hand <findings.json>`) — only when there's actually a hand to play.

### Changed
- The showdown reveal is understated: the wraith lays down the two black aces
  and says nothing more — the dead man's hand is left unspoken.

## [0.5.0] - 2026-06-11

wraith is now a focused recon & vulnerability-detection scanner; landing a shell
moved to its companion, [hickok](https://github.com/gusta-ve/hickok).

### Removed
- The `wraith shell` reverse-shell handler — it now lives as the standalone
  **hickok** (`hickok hand findings.json` reads a wraith run and acts on it).

### Changed
- Tagline is honest now: "offensive recon & vulnerability detection pipeline"
  (it detects and proves; exploitation is hickok's job).
- The showdown reveal is reframed around the dead man's hand: the wraith lays
  down the two black aces (`A♠ A♣`) and teases hickok's eights.
- `-v 1` is now lightweight progress — which parameter is being tested, the
  crawl brackets, the time-based pass — instead of the full payload-by-payload
  trace, which moved to `-v 2`. So `wraith target -v` shows it's working without
  flooding the screen; `-v 2` is the detailed attack play-by-play (every payload
  and request), `-v 3` adds responses.

## [0.4.3] - 2026-06-11

### Added
- A heartbeat: if no phase finishes for 15s, the engine prints which phases are
  still running and for how long (`still working — injection (38s)`). It shows
  at any verbosity (it comes from the scheduler, not a buffered phase), so a
  slow target never looks like a frozen run.

### Changed
- Under `-v`, the crawl and `content-discovery` also report fine-grained
  progress: `-v` brackets the crawl (`crawling… / crawl done: N pages`) and
  `-v 2` prints each request (`crawl [n/total] → GET …`, and every path probed).

## [0.4.2] - 2026-06-11

### Added
- SQLi detection now catches the common "swallowed error" case: a quote that
  breaks the response (often a blank page) which a valid SQL continuation
  (`1''`, `1 AND 1=1`, `1-- -`) restores — covering numeric- and string-context
  injection even when the database error never reaches the page. Boolean-blind
  now probes string, numeric and double-quote contexts (not just one), and the
  error-string signatures were expanded (MSSQL / .NET / JDBC / Npgsql).

### Fixed
- `injection` no longer crawls to a near-halt on slow, real-world targets. It
  skips framework/anti-CSRF parameters (ASP.NET `__VIEWSTATE` & friends), tests
  parameters concurrently instead of one at a time, uses a tighter per-probe
  timeout so a stalled request fails fast, and SSTI now does a single polyglot
  pre-check before escalating. A scan that effectively never finished now
  completes in ~100s.
- Time-based SQLi / command-injection tests are skipped on a high-jitter target
  (sampled up front): when benign latency swings wildly, an injected sleep is
  indistinguishable from random server lag, so timing oracles there only produce
  false positives. They still run on stable targets.

### Changed
- Under `-v`, output now streams live instead of being buffered until each phase
  finishes — a long or stuck phase narrates in real time.

## [0.4.1] - 2026-06-11

### Added
- `-u` / `--url` to give the target like other scanners (`wraith -u https://host`);
  a full URL is normalised to its host, and an explicit port is added to the scan.
- The scan options (`-u`, `-p`, `-s`, `-x`, `-v`, …) now show in `wraith -h`
  itself, not only `wraith run -h`.

### Changed
- Cosmetic flags (`--theme`, `--no-color`, `--no-banner`) work in any position,
  including after the target.

- `-v` is now levelled like other scanners: `-v` / `-v 1` narrates the attack,
  `-v 2` adds every HTTP request, `-v 3` adds the responses. Progress lines were
  added to the longer phases so `-v` shows activity on any scan, not only when
  injection finds parameters.

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
