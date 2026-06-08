# wraith

**Offensive security orchestration framework — it walks the kill-chain as a pipeline.**

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

```bash
git clone https://github.com/gusta-ve/wraith
cd wraith
pip install -e .            # core, zero third-party deps
pip install -e ".[http]"    # optional: httpx for faster HTTP probing
```

Or run straight from source without installing:

```bash
PYTHONPATH=src python3 -m wraith run example.com
```

## Usage

```bash
wraith run example.com                 # full pipeline
wraith run 10.10.10.5 --phases resolve,tcp-scan
wraith run example.com --concurrency 16
wraith phases                          # list available phases
```

Each run writes a self-contained workspace:

```
wraith-runs/example.com-<timestamp>/
├── workspace.json   # every host, service, endpoint and finding (resumable)
└── report.md        # human-readable report
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
- [x] `shell` — post-exploitation handler: multi-listener, session management,
      automatic PTY upgrade and reverse-shell payload generation

Next:

- [ ] `content-discovery` — directory & vhost enumeration
- [ ] `tech-detect` — fingerprint frameworks / CMS / versions
- [ ] HTML reporting

## Legal

`wraith` is built for authorized security testing, CTFs, and research **only**.
Run it exclusively against systems you own or have explicit written permission
to test. You are responsible for how you use it.

## License

MIT © Gustavo Almeida
