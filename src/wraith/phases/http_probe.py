"""Web — probe HTTP(S) services for status, server and title.

Uses httpx when available; otherwise falls back to the standard library so the
core pipeline runs with zero third-party dependencies.
"""

from __future__ import annotations

import re

from wraith.core.http import fetch
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

    @staticmethod
    def _schemes_for(port: int) -> list:
        """A known web port uses its scheme; any other open port is tried as HTTP
        then HTTPS — web services run on non-standard ports all the time."""
        return [HTTP_PORTS[port]] if port in HTTP_PORTS else ["http", "https"]

    async def run(self, ws, console) -> None:
        # tcp-scan finds services keyed by IP, but real sites virtual-host on a
        # name (SNI + Host header). If we know the original hostname, probe by
        # that instead — probing the raw IP fails TLS on every modern host. This
        # also dedupes the IPv4/IPv6 pair of the same service down to one probe.
        hostname = next((h.value for h in ws.hosts if h.kind == "hostname"), None)
        # A known web port uses its scheme; any *other* open port the scan found is
        # tried as HTTP then HTTPS — web services live on non-standard ports all the
        # time (dev servers, admin panels, ranges), so we don't skip a port just
        # because it isn't 80/443.
        probes, seen = [], set()
        for s in ws.services:
            host = hostname or s.host
            key = (host, s.port)
            if key in seen:
                continue
            seen.add(key)
            probes.append((host, s.port, self._schemes_for(s.port)))

        found = False
        for host, port, schemes in probes:
            for scheme in schemes:
                url = f"{scheme}://{host}:{port}/"
                result = await self._fetch(url)
                if result is None:
                    continue
                status, server, title = result
                found = True
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
                break               # got HTTP on this port; don't try the other scheme
        if not found:
            console.warn("no HTTP(S) services found")

    async def _fetch(self, url: str):
        # Through the shared client so the opsec profile (UA/proxy/throttle) applies.
        r = await fetch(url, timeout=6.0, allow_redirects=True, max_bytes=20000)
        if r is None:
            return None
        return r.status, r.headers.get("server", ""), self._title(r.text)

    @staticmethod
    def _title(html: str) -> str:
        match = _TITLE_RE.search(html or "")
        return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""
