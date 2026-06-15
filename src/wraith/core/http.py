"""Small async HTTP client. Uses httpx when present, stdlib otherwise.

Keeps wraith dependency-free at the core while still giving phases a single,
session-aware request primitive (cookies + headers).

It also carries wraith's **opsec layer**: one process-wide config (`configure`)
that every phase request honours — a controlled User-Agent, extra headers, a
cookie, an HTTP/SOCKS proxy (Tor included), and a throttle that paces requests so
a run can be made quiet instead of a flood that lights up every WAF and log.

Tor / SOCKS is spoken natively (a tiny RFC 1928 client below) — no PySocks, no
torsocks — and resolves DNS remotely (socks5h) so the target host never leaks to
the local resolver. When a proxy is set, requests go through the stdlib path so
SOCKS needs no extra httpx dependency.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import random
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_DEFAULT_UA = "wraith/0.1"

# A few current, common browser User-Agents (public values) for --random-agent.
_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]


def random_agent() -> str:
    return random.choice(_AGENTS)


class TorError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


@dataclass
class Response:
    status: int
    url: str
    text: str = ""
    headers: dict = field(default_factory=dict)

    @property
    def is_html(self) -> bool:
        return "text/html" in self.headers.get("content-type", "").lower()


# ============================== opsec config ===============================
@dataclass
class _Opsec:
    user_agent: str = _DEFAULT_UA
    extra_headers: dict = field(default_factory=dict)
    cookie: str = ""
    proxy: str = ""           # http(s)://… or socks5(h)://…  ("" = direct)
    delay: float = 0.0        # minimum seconds between request starts
    jitter: float = 0.0       # extra random 0..jitter seconds on top of delay


_OPSEC = _Opsec()
_gate_lock: asyncio.Lock | None = None
_last_request = 0.0


def configure(*, user_agent=None, headers=None, cookie=None, proxy=None,
              tor=False, delay=0.0, jitter=0.0) -> _Opsec:
    """Set the process-wide opsec profile every request will honour. With `tor`
    and no explicit proxy, auto-detect Tor's SOCKS port (raises TorError if it
    can't be reached)."""
    global _OPSEC, _last_request
    p = proxy
    if tor and not p:
        p = tor_proxy()
    _OPSEC = _Opsec(
        user_agent=user_agent or _DEFAULT_UA,
        extra_headers=dict(headers or {}),
        cookie=cookie or "",
        proxy=p or "",
        delay=max(0.0, float(delay or 0)),
        jitter=max(0.0, float(jitter or 0)),
    )
    _last_request = 0.0
    return _OPSEC


def opsec() -> _Opsec:
    return _OPSEC


def _merge_headers(headers) -> dict:
    """Opsec defaults first (UA, extra headers, cookie), per-call headers on top
    (so a phase's Host/Origin still wins)."""
    h = {"User-Agent": _OPSEC.user_agent}
    h.update(_OPSEC.extra_headers)
    if _OPSEC.cookie:
        h["Cookie"] = _OPSEC.cookie
    h.update(headers or {})
    return h


def _gate() -> asyncio.Lock:
    global _gate_lock
    if _gate_lock is None:
        _gate_lock = asyncio.Lock()
    return _gate_lock


async def _throttle() -> None:
    """Space request *starts* by delay (+ random jitter). Serialised through one
    lock so concurrent phases still respect the pace."""
    if _OPSEC.delay <= 0 and _OPSEC.jitter <= 0:
        return
    global _last_request
    async with _gate():
        wait = _OPSEC.delay + (random.uniform(0, _OPSEC.jitter) if _OPSEC.jitter else 0.0)
        gap = _last_request + wait - time.monotonic()
        if gap > 0:
            await asyncio.sleep(gap)
        _last_request = time.monotonic()


# ============================ SOCKS5 / Tor =================================
# Minimal RFC 1928 client, pure stdlib — so --proxy socks5h:// and --tor need no
# PySocks. The destination is sent as a domain name, so the proxy resolves DNS.
def _recvn(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("SOCKS proxy closed the connection")
        buf += chunk
    return buf


def _socks5_connect(proxy_host, proxy_port, dst_host, dst_port, timeout):
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")                       # VER, 1 method, NO-AUTH
        if _recvn(s, 2) != b"\x05\x00":
            raise OSError("SOCKS5 proxy refused no-auth")
        host = dst_host.encode("idna") if any(ord(ch) > 127 for ch in dst_host) else dst_host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", dst_port))
        rep = _recvn(s, 4)                                # VER, REP, RSV, ATYP
        if rep[1] != 0x00:
            raise OSError(f"SOCKS5 connect failed (code {rep[1]})")
        atyp = rep[3]                                     # drain the bound address
        if atyp == 0x01:
            _recvn(s, 4)
        elif atyp == 0x04:
            _recvn(s, 16)
        elif atyp == 0x03:
            _recvn(s, _recvn(s, 1)[0])
        _recvn(s, 2)                                      # bound port
        return s
    except Exception:
        s.close()
        raise


def _socks_handlers(proxy_host, proxy_port, ctx):
    class _HTTPSConn(http.client.HTTPSConnection):
        def connect(self):
            raw = _socks5_connect(proxy_host, proxy_port, self.host, self.port, self.timeout)
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)

    class _HTTPConn(http.client.HTTPConnection):
        def connect(self):
            self.sock = _socks5_connect(proxy_host, proxy_port, self.host, self.port, self.timeout)

    class _HTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_HTTPSConn, req)

    class _HTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(_HTTPConn, req)

    return [_HTTPHandler(), _HTTPSHandler()]


def tor_proxy() -> str:
    """Find a running Tor SOCKS port (daemon 9050, Tor Browser 9150)."""
    for port in (9050, 9150):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=3).close()
            return f"socks5h://127.0.0.1:{port}"
        except OSError:
            continue
    raise TorError("can't reach the Tor SOCKS proxy on 127.0.0.1:9050 or :9150 — "
                   "is Tor running? (`sudo systemctl start tor`)")


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()       # offensive targets often have bad certs
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _proxy_handlers(ctx, extra=None):
    proxy = _OPSEC.proxy
    if proxy and proxy.startswith("socks"):
        u = urlsplit(proxy)                  # our SOCKS client always resolves DNS remotely
        handlers = _socks_handlers(u.hostname or "127.0.0.1", u.port or 9050, ctx)
    elif proxy:
        handlers = [urllib.request.HTTPSHandler(context=ctx),
                    urllib.request.ProxyHandler({"http": proxy, "https": proxy})]
    else:
        handlers = [urllib.request.HTTPSHandler(context=ctx)]
    return handlers + list(extra or [])


def check_tor(timeout: float = 12.0) -> bool:
    """Confirm traffic actually exits through Tor/the proxy (fail closed if not).
    Synchronous — call it from the CLI before any attack traffic."""
    if not _OPSEC.proxy:
        return False
    opener = urllib.request.build_opener(*_proxy_handlers(_ctx()))
    req = urllib.request.Request("https://check.torproject.org/api/ip",
                                 headers={"User-Agent": _OPSEC.user_agent})
    try:
        with opener.open(req, timeout=timeout) as r:
            return bool(json.loads(r.read(100_000).decode("utf-8", "ignore")).get("IsTor"))
    except Exception:
        return False


# =============================== requests ==================================
async def fetch(url, cookies=None, headers=None, method="GET", timeout=8.0,
                allow_redirects=True, max_bytes=200_000, data=None):
    """Perform a request and return a Response, or None on transport error.

    Honours the opsec profile (UA/headers/cookie/proxy/throttle). ``data`` (a
    dict) sends a urlencoded form body."""
    await _throttle()

    if _OPSEC.proxy:                         # SOCKS/HTTP proxy → stdlib path (no httpx[socks] needed)
        return await _fetch_stdlib(url, cookies, headers, method, timeout, allow_redirects, max_bytes, data)

    try:
        import httpx
    except ImportError:
        return await _fetch_stdlib(url, cookies, headers, method, timeout, allow_redirects, max_bytes, data)

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=allow_redirects, cookies=cookies or {}
        ) as client:
            r = await client.request(method, url, headers=_merge_headers(headers), data=data)
            return Response(
                status=r.status_code,
                url=str(r.url),
                text=r.text[:max_bytes],
                headers={k.lower(): v for k, v in r.headers.items()},
            )
    except Exception:
        return None


async def _fetch_stdlib(url, cookies, headers, method, timeout, allow_redirects, max_bytes, data=None):
    from urllib.parse import urlencode

    hdrs = _merge_headers(headers)
    if cookies:                              # per-call session cookies win over an opsec --cookie
        hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    body = None
    if data is not None:
        body = urlencode(data).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")

    def _sync():
        handlers = _proxy_handlers(_ctx(), extra=([] if allow_redirects else [_NoRedirect()]))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, headers=hdrs, method=method, data=body)
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:  # 4xx/5xx (and 3xx when redirects off) are responses too
            resp = exc
        text = resp.read(max_bytes).decode("utf-8", "ignore")
        status = getattr(resp, "status", None) or resp.getcode()
        return Response(
            status=status,
            url=resp.geturl(),
            text=text,
            headers={k.lower(): v for k, v in resp.headers.items()},
        )

    try:
        return await asyncio.to_thread(_sync)
    except Exception:
        return None
