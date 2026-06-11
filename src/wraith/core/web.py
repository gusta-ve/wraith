"""Shared web helpers: link/form/parameter extraction and a small crawler."""

from __future__ import annotations

import re
import socket
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin, urlsplit

_LINK_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)', re.I)
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)', re.I)
_METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']*)', re.I)
_INPUT_RE = re.compile(r'<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["\']([^"\']+)', re.I)


@dataclass
class Point:
    """An injectable parameter: where it lives and how to submit it."""
    method: str            # GET | POST
    action: str            # absolute URL
    values: dict = field(default_factory=dict)
    param: str = ""
    location: str = "query"  # query | body


def is_ip(value: str) -> bool:
    """True if value is already a literal IPv4/IPv6 address — i.e. there's
    nothing to resolve, so the resolve phase can just record it and move on."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except OSError:
            continue
    return False


def extract_links(base: str, html: str, host: str) -> list:
    """Same-host http(s) links found in a page, resolved to absolute URLs.

    We deliberately stay on the target host and drop logout links: the first
    keeps the crawler in scope, the second stops it from logging itself out
    mid-crawl and losing the session we're testing with.
    """
    links = []
    for m in _LINK_RE.finditer(html or ""):
        href = m.group(1).strip()
        if href.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue  # not navigable URLs — nothing to crawl or test
        absu = urljoin(base, href).split("#")[0]  # make absolute, drop the #fragment
        parts = urlsplit(absu)
        if parts.scheme not in ("http", "https") or parts.netloc != host:
            continue  # off-host or non-web — out of scope
        if any(x in absu.lower() for x in ("logout", "signout", "sign-out")):
            continue
        links.append(absu)
    return links


def extract_forms(base: str, html: str) -> list:
    """Every <form> on the page as {action, method, inputs}. These become the
    POST/GET injection points — a form is just a parameter set with an address."""
    forms = []
    for m in _FORM_RE.finditer(html or ""):
        attrs, inner = m.group(1), m.group(2)
        action_m = _ACTION_RE.search(attrs)
        method_m = _METHOD_RE.search(attrs)
        action = urljoin(base, action_m.group(1)) if action_m and action_m.group(1) else base
        method = "POST" if (method_m and method_m.group(1).upper() == "POST") else "GET"
        names = list(dict.fromkeys(_INPUT_RE.findall(inner)))
        if names:
            forms.append({"action": action, "method": method, "inputs": names})
    return forms


def params_from_url(url: str) -> dict:
    """Query-string parameters as a flat dict (first value wins if repeated)."""
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def build_points(url: str, html: str) -> list:
    """Injection points from a page's own query string and its HTML forms."""
    points = []
    query = params_from_url(url)
    base = url.split("?")[0]
    for name in query:
        points.append(Point("GET", base, dict(query), name, "query"))
    for form in extract_forms(url, html):
        values = {n: "1" for n in form["inputs"]}
        location = "query" if form["method"] == "GET" else "body"
        for name in form["inputs"]:
            points.append(Point(form["method"], form["action"], dict(values), name, location))
    return points


async def crawl(seeds: list, host: str, fetch, max_pages: int = 25,
                cookies=None, headers=None, timeout: float = 8.0, on_fetch=None) -> dict:
    """Breadth-first, same-host crawl returning {url: Response}.

    Bounded by max_pages so a big site can't make a run drag on forever; we
    only follow links out of HTML 2xx pages (an error or a binary download has
    nothing worth queueing). Pass cookies/headers to crawl as a logged-in user;
    ``timeout`` caps each request so a stalling host can't drag the crawl out.
    ``on_fetch(url, n, total)`` is called before each request for live progress.
    """
    seen: set = set()
    out: dict = {}
    queue = deque(seeds)
    while queue and len(out) < max_pages:
        url = queue.popleft().split("#")[0]
        if url in seen:
            continue
        seen.add(url)
        if on_fetch is not None:
            on_fetch(url, len(out) + 1, max_pages)
        r = await fetch(url, cookies=cookies, headers=headers, timeout=timeout)
        if r is None:
            continue
        out[url] = r
        if 200 <= r.status < 300 and r.is_html:
            for link in extract_links(url, r.text, host):
                if link not in seen:
                    queue.append(link)
    return out
