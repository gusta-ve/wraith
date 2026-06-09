# wraith

```text
██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
```

An offensive security scanner that runs the recon-to-exploitation workflow as a
pipeline of small composable phases. Point it at a target; it resolves hosts,
scans ports, maps the web surface, tests it and reports what it finds. The core
has no third-party dependencies.

[![CI](https://github.com/gusta-ve/wraith/actions/workflows/ci.yml/badge.svg)](https://github.com/gusta-ve/wraith/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![MIT](https://img.shields.io/badge/license-MIT-green)

A wraith is something that moves unseen and gets past the wards — which is the
job: enumerate quietly, follow the chain, and reach what shouldn't be reachable.

- [Install](#install)
- [Usage](#usage)
- [Phases](#phases)
- [Web testing](#web-testing)
- [Post-exploitation](#post-exploitation)
- [Extending](#extending)
- [Lab](#lab)

## Install

pipx gives you a global `wraith` (the right call on Kali, which blocks system
pip via PEP 668):

```bash
sudo apt install -y pipx && pipx ensurepath
pipx install "git+https://github.com/gusta-ve/wraith"
pipx install "wraith[http] @ git+https://github.com/gusta-ve/wraith"   # + httpx, faster probing
```

From a clone:

```bash
git clone https://github.com/gusta-ve/wraith && cd wraith
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[http]"
```

Or without installing anything: `PYTHONPATH=src python3 -m wraith run target`.

## Usage

```bash
wraith run target.com                          # full pipeline
wraith run 10.10.10.5 --phases resolve,tcp-scan,http-probe
wraith run target.com --sessions sessions.json # adds access-control / IDOR
wraith run target.com --fail-on high           # exit code 2 on a High+ finding
wraith --theme matrix run target.com           # crimson (default) | matrix | ice | amber | mono
wraith phases                                  # list phases and their dependencies
```

A run writes a self-contained directory:

```
wraith-runs/target.com-<ts>/
  workspace.json   every host, service, endpoint and finding (resumable)
  report.md
  report.html      dark, self-contained
  findings.json
```

```
▸ injection  Reflected XSS, error-based SQLi and open redirect on parameters.
  [*] http://target.com: testing 14 parameter(s)
  [HIGH] Reflected XSS  GET http://target.com/search [q]
  [HIGH] SQL Injection (error-based)  GET http://target.com/item [id]
  [MED ] Open Redirect  GET http://target.com/go [url]

── summary ─────────────────────────────────────────────
  [+] hosts 1 · services 3 · endpoints 21 · findings 9
  findings  High 3  Medium 2  Low 3  Info 1
```

`--no-banner` and `--no-color` (or `NO_COLOR`) strip the cosmetics for logs and
CI; `WRAITH_THEME` sets a default theme.

## Phases

Each phase declares the phases it depends on. The engine resolves that graph and
runs independent phases concurrently; a failing phase is isolated and its
dependents are skipped. Everything is shared through one persisted workspace.

```
resolve            DNS resolution
tcp-scan           async TCP connect scan of common ports
http-probe         status, Server header and title
content-discovery  path/file wordlist with soft-404 filtering
tech-detect        server / language / framework / CMS fingerprint
vhost              virtual-host discovery via Host-header fuzzing
template-checks    declarative JSON/YAML checks (nuclei-style)
security-headers   security headers, cookie flags and CORS
injection          reflected XSS, error-based SQLi, open redirect
access-control     Broken Access Control and IDOR (needs sessions)
```

## Web testing

`injection` crawls the target, pulls parameters from query strings and forms,
and tests each: reflected XSS needs a raw `<`/`>`/`"` payload to come back
unencoded, SQLi needs a single quote to raise a database error the baseline
didn't, and open redirect needs a redirect param to land in `Location`.

`security-headers` reports missing CSP/HSTS/X-Frame-Options/nosniff, weak cookie
flags and CORS that reflects an arbitrary origin.

`access-control` needs authenticated sessions. It crawls as the privileged
session and replays every request as the lower-privilege and anonymous ones; a
lower principal getting identical content is a vertical bypass, and mutating
numeric ids surfaces IDOR. Grab a session with:

```bash
wraith login http://target/login -u alice -p secret \
    --user-field user --pass-field password -o sessions.json
```

## Post-exploitation

`wraith shell` is a separate interactive console — recon is batch work, landing
a shell isn't:

```
wraith shell -l 9001,9002
  payloads          reverse-shell one-liners for your LHOST
  sessions          list connected shells
  cmd 1 id          run a command on session 1
  upgrade 1         turn a dumb shell into a PTY
  interact 1        attach (detach with Ctrl-])
```

## Extending

A phase is one file; a check can be pure data. See
[docs/writing-a-phase.md](docs/writing-a-phase.md) and
[docs/writing-a-template.md](docs/writing-a-template.md).

```python
from wraith.core.phase import Phase, register

@register
class MyPhase(Phase):
    name = "my-phase"
    requires = frozenset({"http-probe"})

    async def run(self, ws, console):
        for ep in ws.endpoints:
            ...  # ws.add_finding(...)
```

## Lab

`examples/vuln_app.py` is a deliberately vulnerable app to practise against and
to exercise every web phase (BAC, IDOR, XSS, SQLi, open redirect, CORS, insecure
cookies, missing headers):

```bash
python3 examples/vuln_app.py &
wraith run 127.0.0.1 --sessions examples/sessions.json
```

## Tests

```bash
pip install -e ".[dev]" && pytest
```

## Legal

For authorized testing only — systems you own or have written permission to
assess. What you do with it is on you.

## License

MIT.
