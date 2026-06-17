"""Recon — resolve the target to IP addresses."""

from __future__ import annotations

import asyncio
import socket

from wraith.core import web
from wraith.core.phase import Phase, register


@register
class ResolvePhase(Phase):
    name = "resolve"
    requires = frozenset()
    description = "Resolve the target to one or more IP addresses (DNS)."

    async def run(self, ws, console) -> None:
        target = ws.target
        if web.is_ip(target):
            ws.add_host(target, "ip", "input")
            console.good(f"target is an IP: {target}")
            return

        ws.add_host(target, "hostname", "input")
        loop = asyncio.get_event_loop()
        try:
            infos = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            console.warn(f"could not resolve {target}: {exc}")
            return

        for ip in sorted({info[4][0] for info in infos}):
            ws.add_host(ip, "ip", "resolve")
            console.good(f"{target} → {ip}")
