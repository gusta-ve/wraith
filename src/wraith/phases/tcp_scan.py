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
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 587,
    993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5900,
    6379, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9300, 9443,
    10000, 11211, 27017,
]

# A broader set of HTTP / alt-HTTP / dev-server ports for `--ports web`. A web app
# can live almost anywhere; the common list stays lean for speed, while `web`
# sweeps the ports a non-standard service (a dev server, an admin panel, a local
# range like deadwood on 8666) actually tends to land on.
WEB_PORTS = sorted(set(COMMON_PORTS) | {
    591, 2082, 2083, 2086, 2087, 3001, 3128, 4000, 4200, 4443, 4567, 5001, 5002,
    5601, 7000, 7001, 7070, 7080, 7443, 7547, 8001, 8009, 8010, 8011, 8082, 8083,
    8085, 8090, 8091, 8118, 8161, 8180, 8181, 8200, 8222, 8280, 8333, 8400, 8444,
    8500, 8530, 8666, 8765, 8787, 8800, 8834, 8880, 8983, 9001, 9002, 9043, 9060,
    9080, 9091, 9200, 9800, 9981, 9999, 12443, 16080, 18080, 28017,
})

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    81: "http", 88: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 587: "smtp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3000: "http",
    3128: "http", 3306: "mysql", 3389: "rdp", 5000: "http", 5432: "postgres",
    5601: "kibana", 5900: "vnc", 6379: "redis", 8000: "http", 8008: "http",
    8080: "http", 8081: "http", 8088: "http", 8443: "https", 8888: "http",
    9000: "http", 9090: "http", 9200: "elasticsearch", 9300: "elasticsearch",
    9443: "https", 10000: "http", 11211: "memcached", 27017: "mongodb",
}


def parse_ports(spec: str) -> list[int]:
    """Expand a port spec into a sorted, de-duplicated, in-range list.

    Accepts comma-separated ports and ranges (`80,443,8000-8100`) mixed with the
    keywords `top` (the common list), `web` (the broader HTTP/alt-HTTP set) and
    `all`/`full`/`-` (every port, 1-65535 — the only way to find a service on a
    genuinely arbitrary port). `top,8666` adds a single port to the default; a
    connect scan can only ever find a port it actually probes."""
    if not spec:
        return []
    out: set[int] = set()
    for tok in spec.replace(" ", "").split(","):
        if not tok:
            continue
        low = tok.lower()
        if low in ("all", "full", "-", "1-65535"):
            return list(range(1, 65536))
        if low == "top":
            out.update(COMMON_PORTS)
        elif low == "web":
            out.update(WEB_PORTS)
        elif "-" in tok:
            a, b = tok.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(tok))
    return sorted(p for p in out if 1 <= p <= 65535)


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

        # `--ports` (resolved into ws.meta["ports"]) replaces the default list;
        # a URL/host:port pin is always added on top so it's never missed.
        base_ports = ws.meta.get("ports") or COMMON_PORTS
        seen = set(base_ports)
        extra = [p for p in ws.meta.get("extra_ports", []) if p not in seen]
        ports = list(base_ports) + extra
        console.trace(f"scanning {len(ports)} port(s) across {len(ips)} host(s)", level=1)
        tasks = [probe(ip, port) for ip in ips for port in ports]
        for coro in asyncio.as_completed(tasks):
            res = await coro
            if res is None:
                continue
            ip, port = res
            name = SERVICE_NAMES.get(port, "")
            ws.add_service(ip, port, "tcp", name=name, source="tcp-scan")
            console.good(f"{ip}:{port} open" + (f"  {name}" if name else ""))
