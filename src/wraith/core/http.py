"""Small async HTTP client. Uses httpx when present, stdlib otherwise.

Keeps wraith dependency-free at the core while still giving phases a single,
session-aware request primitive (cookies + headers).
"""

from __future__ import annotations

import asyncio
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field


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


async def fetch(url, cookies=None, headers=None, method="GET", timeout=8.0,
                allow_redirects=True, max_bytes=200_000):
    """Perform a request and return a Response, or None on transport error."""
    try:
        import httpx
    except ImportError:
        return await _fetch_stdlib(url, cookies, headers, method, timeout, allow_redirects, max_bytes)

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=allow_redirects, cookies=cookies or {}
        ) as client:
            r = await client.request(method, url, headers=headers or {})
            return Response(
                status=r.status_code,
                url=str(r.url),
                text=r.text[:max_bytes],
                headers={k.lower(): v for k, v in r.headers.items()},
            )
    except Exception:
        return None


async def _fetch_stdlib(url, cookies, headers, method, timeout, allow_redirects, max_bytes):
    hdrs = dict(headers or {})
    if cookies:
        hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    hdrs.setdefault("User-Agent", "wraith/0.1")

    def _sync():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers = [urllib.request.HTTPSHandler(context=ctx)]
        if not allow_redirects:
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, headers=hdrs, method=method)
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:  # 4xx/5xx (and 3xx when redirects off) are responses too
            resp = exc
        body = resp.read(max_bytes).decode("utf-8", "ignore")
        status = getattr(resp, "status", None) or resp.getcode()
        return Response(
            status=status,
            url=resp.geturl(),
            text=body,
            headers={k.lower(): v for k, v in resp.headers.items()},
        )

    try:
        return await asyncio.to_thread(_sync)
    except Exception:
        return None
