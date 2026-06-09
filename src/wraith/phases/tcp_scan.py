"""Scanning — async TCP connect scan of common ports.

A *connect* scan (full three-way handshake) rather than a SYN scan: it needs no
raw sockets and no root, so it runs anywhere Python does. We fan out across all
host/port pairs at once and cap concurrency with a semaphore so we probe fast
without opening thousands of sockets simultaneously.
"""

from __future__ import annotations

import asyncio

from wraith.core.phase import Phase, register

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 587, 993, 995,
    1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5900, 6379,
    8000, 8080, 8081, 8443, 9000, 9200, 9300, 11211, 27017,
]

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 587: "smtp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3000: "http",
    3306: "mysql", 3389: "rdp", 5000: "http", 5432: "postgres", 5601: "kibana",
    5900: "vnc", 6379: "redis", 8000: "http", 8080: "http", 8081: "http",
    8443: "https", 9000: "http", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


@register
class TcpScanPhase(Phase):
    name = "tcp-scan"
    requires = frozenset({"resolve"})
    description = "Async TCP connect scan of common ports."

    async def run(self, ws, console) -> None:
        ips = [h.value for h in ws.hosts if h.kind == "ip"]
        if not ips:
            console.warn("no resolved IPs to scan")
            return

        sem = asyncio.Semaphore(300)

        async def probe(ip: str, port: int):
            async with sem:
                try:
                    fut = asyncio.open_connection(ip, port)
                    _, writer = await asyncio.wait_for(fut, timeout=2.0)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return ip, port
                except Exception:
                    return None

        tasks = [probe(ip, port) for ip in ips for port in COMMON_PORTS]
        for coro in asyncio.as_completed(tasks):
            res = await coro
            if res is None:
                continue
            ip, port = res
            name = SERVICE_NAMES.get(port, "")
            ws.add_service(ip, port, "tcp", name=name, source="tcp-scan")
            console.good(f"{ip}:{port} open" + (f"  {name}" if name else ""))
