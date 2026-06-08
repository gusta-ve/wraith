"""Web — probe HTTP(S) services for status, server and title.

Uses httpx when available; otherwise falls back to the standard library so the
core pipeline runs with zero third-party dependencies.
"""

from __future__ import annotations

import asyncio
import re

from wraith.core.models import Severity
from wraith.core.phase import Phase, register

HTTP_PORTS = {
    80: "http", 3000: "http", 5000: "http", 8000: "http",
    8080: "http", 8081: "http", 9000: "http",
    443: "https", 8443: "https",
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


@register
class HttpProbePhase(Phase):
    name = "http-probe"
    requires = frozenset({"tcp-scan"})
    description = "Probe HTTP(S) services for status, server and title."

    async def run(self, ws, console) -> None:
        targets = [(s.host, s.port, HTTP_PORTS[s.port]) for s in ws.services if s.port in HTTP_PORTS]
        if not targets:
            console.warn("no HTTP(S) services found")
            return

        for host, port, scheme in targets:
            url = f"{scheme}://{host}:{port}/"
            result = await self._fetch(url)
            if result is None:
                console.warn(f"{url} no response")
                continue
            status, server, title = result
            ws.add_endpoint(url, "GET", status, title=title, server=server)
            console.good(
                f"{url} → {status}"
                + (f"  [{server}]" if server else "")
                + (f"  {title}" if title else "")
            )
            if server:
                ws.add_finding(
                    title=f"Server banner disclosed: {server}",
                    severity=Severity.INFO,
                    phase=self.name,
                    target=url,
                    evidence=f"Server: {server}",
                    description="The HTTP Server header discloses software/version information.",
                )

    async def _fetch(self, url: str):
        try:
            import httpx
        except ImportError:
            return await self._fetch_stdlib(url)
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True) as client:
                r = await client.get(url, headers={"User-Agent": "wraith/0.1"})
                return r.status_code, r.headers.get("server", ""), self._title(r.text)
        except Exception:
            return None

    async def _fetch_stdlib(self, url: str):
        import ssl
        import urllib.request

        def _sync():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "wraith/0.1"})
            with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                body = resp.read(20000).decode("utf-8", "ignore")
                status = getattr(resp, "status", None) or resp.getcode()
                return status, resp.headers.get("Server", ""), self._title(body)

        try:
            return await asyncio.to_thread(_sync)
        except Exception:
            return None

    @staticmethod
    def _title(html: str) -> str:
        match = _TITLE_RE.search(html or "")
        return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""
