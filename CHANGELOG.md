# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/).

## [0.7.0] - 2026-06-15

A detection-quality release: the injection oracles are now calibrated to each
target instead of leaning on fixed similarity thresholds, port scanning reaches
beyond a fixed common-port list, and two long-standing detection gaps are closed.
Shaken out by co-evolving against the [deadwood](https://github.com/gusta-ve/deadwood)
range — every web-injection level it ships now resolves to the right vector.

### Added
- **`-P/--ports` — scan any ports, not just the built-in common list.** Takes a
  list and ranges (`80,443,8000-8100`) or a keyword: `top` (the common list,
  default), `web` (a broad HTTP/alt-HTTP sweep), or `all`/`1-65535` (every port —
  the only way to find a service on a genuinely arbitrary port). A `host:port` pin
  is still always added on top. A connect scan can only find a port it probes, so
  an odd one (a dev server, a local range on `:8666`) needs `-P web` or `-P all`.
- The default common-port list grew a clutch of frequently-seen HTTP/alt-HTTP and
  service ports (`81`, `88`, `8008`, `8088`, `8888`, `9090`, `9443`, `10000`, …).

### Changed
- **Boolean-blind SQLi detection is now calibrated to the target instead of fixed
  thresholds.** Two identical baseline requests measure the page's own noise, and
  the TRUE/FALSE comparison runs on just the *reacting core* of the response (common
  chrome stripped) — so a one-line verdict flip (`Welcome` vs `Invalid`) inside
  kilobytes of layout reads as clearly as a whole-table change. The TRUE/FALSE
  payloads now differ by a single character (`=1` vs `=2`) so a reflected echo
  cancels in the core, and the probe set covers `OR`/`AND` pairs in string, numeric
  and double-quote contexts — `OR`-pairs flip row presence on a login/username check
  where the base value matches nothing (the case the old oracle missed entirely).
- The **broken-response** SQLi oracle is calibrated the same way: an odd quote has
  to diverge from the baseline *beyond the page's measured noise* (not a fixed 0.9),
  and a valid continuation restore it — catching a small-but-real break in a big page
  without firing on a dynamic one.
- Injectable points are **prioritised**: cheap GET query params before form bodies,
  narrow forms before wide, and obvious `submit`/`flag`/`captcha` fields last — so
  the capped budgets (and the slow time-based subset) land on real data parameters.
  Crawl/point budgets raised (`MAX_PAGES` 25→60, `MAX_POINTS` 60→80, timing 10→16).

### Fixed
- **SSTI is no longer missed when the app reflects the payload.** A form that
  re-renders your input echoes the raw expression (`{{43*41}}`) back even when the
  engine also evaluated it — the old `expr not in text` guard then rejected the real
  hit. The reflected payload (raw, HTML-escaped, URL-encoded) is now stripped before
  checking for the product, so a genuine evaluation registers regardless of echo.
- **An OS-command-injection point no longer double-reports as blind SQLi.** The
  broken-response oracle now restores only through SQL-*distinctive* continuations
  (`1 AND 1=1`, `1-- -`) — a shell command (`ping … 1''` collapses `''` to nothing)
  satisfied the old balanced-quote restore and was flagged as SQLi on top of the
  real Command Injection finding.

## [0.6.12] - 2026-06-15

### Fixed
- `http-probe` now probes **any open port** the scan found — trying HTTP then
  HTTPS — instead of only a fixed list of web ports. A web service on a
  non-standard port (a dev server, an admin panel, a local range on `:8666`) used
  to be skipped, which made the whole web pipeline report "no HTTP services" and
  find nothing. Now it's scanned like any other.

## [0.6.11] - 2026-06-14

### Changed
- A nod to **Wild Bill Hickok** in the lore: the banner footer and the aces
  reveal now name the gunslinger whose dead man's hand wraith holds half of, and
  the README closes on it.

## [0.6.10] - 2026-06-13

### Changed
- A bare `wraith` now shows the banner and a short quickstart (a few example
  commands) instead of dumping the full help — `wraith -h` still has it all.

## [0.6.9] - 2026-06-13

### Changed
- The reveal's words now centre on the spectre's own column (measured from the
  art), so the text lines up exactly under the figure.

## [0.6.8] - 2026-06-13

### Changed
- The reveal's words now sit centred under the line-art, instead of left-indented.

## [0.6.7] - 2026-06-13

### Changed
- Internal cleanup: the run-output directory resolver now lives in one place
  (`wraith.core.context.runs_dir`) and `Workspace.create()` defaults to it. No
  change to where runs are written.

## [0.6.6] - 2026-06-13

### Changed
- Centred the banner art over the name and tagline (it was sitting too far right).

## [0.6.5] - 2026-06-13

### Changed
- Kept the original hooded-spectre mascot as the full art (the showdown reveal
  and the repo hero); the banner is now a crop of its head, so it's a true
  preview of the reveal.

## [0.6.4] - 2026-06-13

### Changed
- The banner dropped the block wordmark for the hooded spectre's head — cowl
  and cold eyes — drawn in ASCII: the face of the tool, a preview of the full
  mascot the showdown reveals. New full mascot (the spectre holding the dead
  man's hand). The repo hero is the full mascot beside the name, set clean (no
  figlet anywhere).

## [0.6.3] - 2026-06-12

### Changed
- The wordmark is flatter — the same block letters without the heavy 3D drop
  shadow (a lighter, more sober banner; hickok's matches).

## [0.6.2] - 2026-06-12

### Changed
- The foothold handoff now points at `hickok call` (hickok renamed the
  run-acting command; `hickok hand` is now its dead man's hand reveal).

## [0.6.1] - 2026-06-12

### Changed
- Phase descriptions and docs now stand on their own terms — no comparisons to
  other tools. Refreshed the demo to the current version.

## [0.6.0] - 2026-06-11

### Changed
- Runs are written to a fixed per-user directory by default —
  `~/.local/share/wraith/runs/` (XDG) instead of `./wraith-runs/` in the current
  directory — so hickok finds them from anywhere. Set `WRAITH_RUNS` to move it
  (both tools honour it), or `--workdir` for a one-off.

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
