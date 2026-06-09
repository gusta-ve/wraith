# wraith

```text
██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
```

[![CI](https://github.com/gusta-ve/wraith/actions/workflows/ci.yml/badge.svg)](https://github.com/gusta-ve/wraith/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Offensive security orchestration framework — it walks the kill-chain as a pipeline.**

> *A wraith is a ghost that stalks unseen and slips past defences — which is the
> job: enumerate quietly, walk the kill-chain, surface what shouldn't be reachable.*

Most recon tools bolt a handful of scanners together. `wraith` models the whole
engagement as a **directed graph of phases**: recon feeds scanning, scanning
feeds web analysis, web analysis feeds exploitation. Independent phases run
**concurrently**, every phase shares a single persisted **workspace**, and
adding a new attack capability is just dropping in one file.

The core pipeline runs on the **Python standard library alone** — no
dependencies required.

```
                    ┌──────────────────────────────────────────────┐
   target ───►      │   ENGINE  (phase DAG · async workers · ws)     │
                    └──────────────────────────────────────────────┘
                       │        │         │          │          │
                       ▼        ▼         ▼          ▼          ▼
                  ┌────────┐ ┌──────┐ ┌────────┐ ┌────────┐ ┌─────────┐
   kill-chain →   │ recon  │→│ scan │→│  web   │→│ access │→│ post-ex │
                  │resolve │ │ports │ │ probe  │ │ control│ │  shell  │
                  └────────┘ └──────┘ └────────┘ └────────┘ └─────────┘
                       └──────────────► WORKSPACE ──► report (md/json)
```

## Install

**Kali / Debian (recommended — pipx gives you a global `wraith`):**

```bash
sudo apt install -y pipx && pipx ensurepath
pipx install "git+https://github.com/gusta-ve/wraith"
# faster HTTP probing (optional):
pipx install "wraith[http] @ git+https://github.com/gusta-ve/wraith"
wraith --version
```

**From a clone, in a venv:**

```bash
git clone https://github.com/gusta-ve/wraith && cd wraith
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[http]"
wraith run example.com
```

**No install at all (straight from source):**

```bash
PYTHONPATH=src python3 -m wraith run example.com
```

> On Kali, system pip is "externally managed" (PEP 668) — use `pipx` or a venv as
> above rather than `pip install` into the system Python.

## Usage

```bash
wraith run example.com                 # full pipeline
wraith run 10.10.10.5 --phases resolve,tcp-scan
wraith run example.com --concurrency 16
wraith phases                          # list available phases
wraith --theme matrix run example.com  # crimson (default) | matrix | ice | amber | mono
```

Themes and the banner are cosmetic: `--no-banner` and `--no-color` (or the
`NO_COLOR` env var) strip them for logs/CI; set a default with `WRAITH_THEME`.

Each run writes a self-contained workspace:

```
wraith-runs/example.com-<timestamp>/
├── workspace.json   # every host, service, endpoint and finding (resumable)
├── report.md        # human-readable report
├── report.html      # dark, self-contained HTML report
└── findings.json    # machine-readable findings
```

Gate a pipeline on severity:

```bash
wraith run example.com --fail-on high   # exit code 2 if a High+ finding is seen
```

## Access control & IDOR

The `access-control` phase finds the most common web vulnerability class (OWASP
A01) the way a pentester does — by comparing what different users can reach:

1. Crawl the app as the highest-privilege session.
2. Replay every discovered request under the lower-privilege (and anonymous)
   sessions.
3. Flag any request where a lower principal gets content **identical** to the
   privileged one (vertical bypass), suppressing anything an anonymous user can
   also reach (genuinely public).
4. For URLs carrying a numeric id, mutate it (±1) to detect **IDOR** —
   distinguishing a real neighbouring object from the not-found page.

Sessions are described in a small JSON file:

```jsonc
{
  "base_url": "http://target",
  "seeds": ["/", "/account", "/admin"],
  "sessions": [
    { "name": "admin", "role": "high", "cookies": { "session": "..." } },
    { "name": "user",  "role": "low",  "cookies": { "session": "..." } },
    { "name": "anon",  "role": "none" }
  ]
}
```

A self-contained demo (deliberately vulnerable app) ships in `examples/`:

```bash
python3 examples/vuln_app.py &
wraith run 127.0.0.1 --phases access-control --sessions examples/sessions.json
```

```
▸ access-control
  [*] privileged session: 'admin' (role high)
  [+] discovered 5 URL(s) as 'admin'
  [-] BAC   'alice' → /admin
  [-] BAC   'bob'   → /admin
  [-] IDOR  'alice' → /account/orders/2
  [-] IDOR  'bob'   → /account/orders/3
```

It flags the broken `/admin` and the IDOR on `/account/orders/<id>`, while
correctly staying silent on the role-checked `/admin-secure` and on personalized
or public pages.

## Post-exploitation

Recon and exploitation are batch phases; landing and driving a shell is operator
work, so it lives in its own interactive console:

```bash
wraith shell --listen 9001,9002      # bind one or more listeners
```

```
wraith(shell)> payloads               # reverse-shell one-liners for your LHOST
wraith(shell)> sessions               # list connected shells
wraith(shell)> cmd 1 id               # run a single command on session 1
wraith(shell)> upgrade 1              # turn a dumb shell into a full PTY
wraith(shell)> interact 1             # attach (detach with Ctrl-])
```

It catches reverse shells on every listener, tracks each as a numbered session,
generates payloads for `bash`, `python3`, `php`, `perl`, `nc` and `powershell`,
and upgrades a raw shell to a full PTY (`python pty.spawn` + raw local terminal).

## Web vulnerabilities

Two phases test the web layer directly:

- **`injection`** crawls the target, collects parameters from query strings and
  HTML forms, and tests each for **reflected XSS** (a raw `<`/`>`/`"` payload must
  reflect unencoded), **error-based SQLi** (a quote must induce a DB error absent
  from the baseline) and **open redirect** (a redirect param must land in
  `Location`).
- **`security-headers`** audits missing hardening headers (CSP, X-Frame-Options,
  nosniff, HSTS, Referrer-Policy), insecure cookie flags (HttpOnly / Secure /
  SameSite) and dangerous **CORS** reflection.

## Capturing a session

`access-control` needs authenticated sessions. `wraith login` performs a form
login and writes a ready-to-use `sessions.json`:

```bash
wraith login http://target/login -u alice -p secret \
    --user-field user --pass-field password --role low -o sessions.json
```

## The lab

`examples/vuln_app.py` is a deliberately vulnerable app to practise against and
to exercise every web phase (BAC, IDOR, XSS, SQLi, open redirect, CORS, insecure
cookies, missing headers):

```bash
python3 examples/vuln_app.py &
wraith run 127.0.0.1 --sessions examples/sessions.json
```

## Templates

`template-checks` runs declarative templates (a nuclei-lite engine) against every
discovered host. Built-ins ship under `wraith/templates/` (`.git`/`.env`
exposure, `phpinfo`, directory listing, Apache `server-status`, Swagger UI); add
your own with `--templates DIR`.

A template is JSON (or YAML, if `pyyaml` is installed) — one or more requests,
each with matchers combined via `matchers-condition`:

```json
{
  "id": "dotenv-exposure",
  "info": { "name": "Exposed .env file", "severity": "high" },
  "requests": [
    {
      "method": "GET",
      "path": "/.env",
      "matchers-condition": "and",
      "matchers": [
        { "type": "status", "status": [200] },
        { "type": "regex", "part": "body", "regex": ["DB_(HOST|PASSWORD)", "APP_KEY="] }
      ]
    }
  ]
}
```

Matcher types: `status`, `word`, `regex` and `header`.

## How it works

- **Phase** — one stage of the kill-chain. Declares a unique `name`, the phases
  it `requires`, and an async `run()`. Phases only ever touch the shared
  `Workspace`, so they stay decoupled.
- **Engine** — resolves the dependency DAG and schedules every ready phase
  concurrently (bounded by `--concurrency`). A failing phase is isolated: it
  never takes the pipeline down, and dependents are skipped cleanly.
- **Workspace** — the single source of truth (hosts, services, endpoints,
  sessions, findings). Persisted to disk after every phase, so runs are
  inspectable and resumable.

Writing a new phase:

```python
from wraith.core.phase import Phase, register

@register
class MyPhase(Phase):
    name = "my-phase"
    requires = frozenset({"http-probe"})
    description = "What it does."

    async def run(self, ws, console):
        for ep in ws.endpoints:
            ...  # add findings to the workspace
```

## Roadmap

Built:

- [x] Phase engine — DAG scheduling, async workers, failure isolation
- [x] Persisted workspace + Markdown reporting
- [x] `resolve` — DNS resolution
- [x] `tcp-scan` — async TCP connect scan
- [x] `http-probe` — status / server / title
- [x] `access-control` — authenticated crawl + multi-session replay to detect
      **Broken Access Control (OWASP A01)** and **IDOR**
- [x] `content-discovery` — wordlist path/file discovery with soft-404 filtering
- [x] `tech-detect` — fingerprint server / language / framework / CMS
- [x] `vhost` — virtual-host discovery via Host-header fuzzing
- [x] `template-checks` — declarative vulnerability templates (nuclei-lite)
- [x] `security-headers` — security headers, cookie flags and CORS audit
- [x] `injection` — reflected XSS, error-based SQLi and open redirect
- [x] `shell` — post-exploitation handler: multi-listener, session management,
      automatic PTY upgrade and reverse-shell payload generation
- [x] `wraith login` — capture an authenticated session to `sessions.json`
- [x] Markdown + dark HTML + JSON reporting, `--fail-on` for CI gating
- [x] CI (GitHub Actions) running the test suite on Python 3.10–3.12

Next:

- [ ] request throttling / rate control
- [ ] authenticated re-crawl feeding the injection phase

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite covers the engine's DAG scheduling and failure handling, payload
generation, technology fingerprinting, the IDOR id-mutation logic, the injection
and security-header detectors, web parsing, workspace persistence and reporting.

Extending wraith:

- [docs/writing-a-phase.md](docs/writing-a-phase.md) — add a kill-chain stage
- [docs/writing-a-template.md](docs/writing-a-template.md) — add a check without code
- [CONTRIBUTING.md](CONTRIBUTING.md)

## Legal

`wraith` is built for authorized security testing, CTFs, and research **only**.
Run it exclusively against systems you own or have explicit written permission
to test. You are responsible for how you use it.

## License

MIT © Gustavo Almeida
