# Writing a phase

A phase is one stage of the kill-chain. Phases are decoupled: they only read and
write the shared `Workspace`, and declare which other phases must run first. The
engine resolves the dependency graph and runs independent phases concurrently.

## Anatomy

```python
from wraith.core.phase import Phase, register


@register
class MyPhase(Phase):
    name = "my-phase"                       # unique, used by --phases
    requires = frozenset({"http-probe"})    # phases that must run first
    description = "What it does."

    async def run(self, ws, console):
        for endpoint in ws.endpoints:       # read prior results
            ...
            ws.add_finding(                 # write results
                title="Something interesting",
                severity=Severity.MEDIUM,
                phase=self.name,
                target=endpoint.url,
                evidence="why we think so",
                description="impact / remediation",
            )
```

Register the module in `wraith/phases/__init__.py` so importing the package
registers the phase.

## The Workspace

Everything flows through `ws` (`wraith/core/context.py`):

| Helper | Adds |
|--------|------|
| `ws.add_host(value, kind, source)` | a host/IP |
| `ws.add_service(host, port, ...)` | an open service |
| `ws.add_endpoint(url, ...)` | a web endpoint |
| `ws.add_finding(title, severity, ...)` | a finding |
| `ws.sessions`, `ws.meta` | auth sessions / run options |

All `add_*` helpers de-duplicate, so phases stay idempotent on re-runs. The
workspace is persisted to `workspace.json` after every phase.

## Networking

Use the shared client in `wraith/core/http.py`:

```python
from wraith.core.http import fetch

r = await fetch(url, cookies=..., headers=..., method="GET", allow_redirects=False)
if r and r.status == 200:
    ...
```

For crawling, forms and parameter extraction, reuse `wraith/core/web.py`.

## Guidelines

- Keep detection **low false-positive** — prefer a baseline/differential over a
  single signal (see `access-control` and `injection`).
- Bound your work (page/probe caps, a semaphore for concurrency).
- Never let an exception escape silently — the engine isolates a failing phase,
  but a clear `console.warn`/`console.bad` helps the operator.
