"""Web — virtual-host discovery via Host-header fuzzing.

Sends candidate Host headers to each HTTP service and compares the response to a
baseline (the target's own Host). A markedly different response points to a
separate virtual host served from the same address.
"""

from __future__ import annotations

import asyncio
import difflib
import socket
from urllib.parse import urlsplit

from wraith.core.http import fetch
from wraith.core.models import Severity
from wraith.core.phase import Phase, register

COMMON_VHOSTS = [
    "www", "admin", "dev", "staging", "stage", "test", "api", "portal",
    "intranet", "internal", "beta", "app", "mail", "webmail", "vpn", "git",
    "jenkins", "grafana", "kibana", "dashboard", "secret", "backup", "old",
    "new", "demo", "mobile", "static", "cdn", "assets", "blog", "shop",
]


def _is_ip(value: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except OSError:
            continue
    return False


@register
class VhostPhase(Phase):
    name = "vhost"
    requires = frozenset({"http-probe"})
    description = "Virtual-host discovery via Host-header fuzzing."

    CONCURRENCY = 20

    async def run(self, ws, console) -> None:
        bases = self._bases(ws)
        if not bases:
            console.warn("no HTTP endpoints for vhost fuzzing")
            return
        target = ws.target
        domain = None if _is_ip(target) else (target if "." in target else None)
        candidates = [f"{p}.{domain}" for p in COMMON_VHOSTS] if domain else COMMON_VHOSTS
        for base in bases:
            await self._fuzz(ws, console, base, target, candidates)

    @staticmethod
    def _bases(ws) -> list:
        seen, out = set(), []
        for e in ws.endpoints:
            p = urlsplit(e.url)
            base = f"{p.scheme}://{p.netloc}"
            if base not in seen:
                seen.add(base)
                out.append(base)
        return out

    async def _fuzz(self, ws, console, base, target, candidates) -> None:
        baseline = await fetch(base, headers={"Host": target}, allow_redirects=False)
        if baseline is None:
            console.warn(f"{base}: no baseline response")
            return
        sem = asyncio.Semaphore(self.CONCURRENCY)

        async def probe(vhost: str) -> None:
            async with sem:
                r = await fetch(base, headers={"Host": vhost}, allow_redirects=False)
                if r is None or not self._distinct(r, baseline):
                    return
                console.good(f"vhost  {vhost}  ({r.status}, {len(r.text)}b)")
                ws.add_finding(
                    title=f"Virtual host responds differently: {vhost}",
                    severity=Severity.INFO,
                    phase=self.name,
                    target=base,
                    evidence=f"Host: {vhost} -> HTTP {r.status}, {len(r.text)} bytes",
                    description="The server returns distinct content for this Host header, "
                                "indicating a separate virtual host on the same address.",
                )

        await asyncio.gather(*(probe(v) for v in candidates))

    @staticmethod
    def _distinct(resp, baseline) -> bool:
        if resp.status in (400, 404, 421):  # bad request / misdirected -> not a real vhost
            return False
        if resp.status != baseline.status:
            return True
        ratio = difflib.SequenceMatcher(None, resp.text[:3000], baseline.text[:3000]).ratio()
        return ratio < 0.85
