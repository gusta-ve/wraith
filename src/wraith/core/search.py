"""Search-engine backends for ``wraith dork`` — a query in, result URLs out.

``wraith dork`` turns a search query (a *dork* — a query using operators like
``inurl:``, ``intitle:``, ``ext:``) into a list of result URLs, and stops there.
It is a **discovery** command: it never sends a single request to the URLs it
finds. What you do with the list afterwards — and whether you're authorized to —
is a separate, deliberate step (``wraith <target>``), never something this module
does for you. There is, by design, no function here that touches a result.

Scraping a search page directly is blocked by every major engine now (this is why
sqlmap's ``-g`` rots), so wraith talks to a real search *API*. Pick one by
configuring it (env var or flag); ``--engine`` forces a choice:

  * ``searxng``  a SearXNG instance's JSON API   ``WRAITH_SEARXNG_URL``  (no API key)
  * ``google``   Google Programmable Search      ``WRAITH_GOOGLE_API_KEY`` + ``WRAITH_GOOGLE_CX``
  * ``brave``    Brave Search API                ``WRAITH_BRAVE_API_KEY``

Each engine's JSON shape is parsed by a small pure function (tested); the async
``search()`` pages until it has enough, honouring wraith's opsec profile
(UA/proxy/throttle) on the API calls.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from wraith.core.http import fetch

ENGINES = ("searxng", "google", "brave")

# Dork presets — public, GHDB-style discovery categories. They only shape the
# search query; the results are URLs the engine already indexed. `params` finds
# the parametric URLs that are classic SQLi/IDOR *candidates* (not confirmed
# anything — the dork sees the shape of a parameter, never whether it's exploitable).
PRESETS = {
    "params":  '(inurl:"id=" OR inurl:"page=" OR inurl:"cat=" OR inurl:"item=" OR inurl:"pid=" OR inurl:"sid=")',
    "files":   "(ext:env OR ext:bak OR ext:sql OR ext:log OR ext:ini OR ext:old OR ext:conf)",
    "panels":  '(intitle:"login" OR inurl:admin OR inurl:signin OR inurl:portal)',
    "listing": 'intitle:"index of"',
}


@dataclass
class SearchResult:
    url: str
    title: str = ""
    source: str = ""          # which engine returned it


class SearchError(RuntimeError):
    pass


# --------------------------------------------------------------- query
def build_query(query: str = "", presets=(), site: str = "") -> str:
    """Compose the final dork from a raw query, any enabled presets and an
    optional ``site:`` scope, joined with spaces (the engine's implicit AND).

    A single preset contributes its fragment as-is; several are OR-ed together
    (`--params --files` means "parametric URLs *or* exposed files", not the empty
    intersection of the two). Raises ValueError on an unknown preset name."""
    parts = []
    if site:
        parts.append(f"site:{site}")
    frags = []
    for name in presets:
        if name not in PRESETS:
            raise ValueError(f"unknown preset: {name} (have: {', '.join(PRESETS)})")
        frags.append(PRESETS[name])
    if len(frags) == 1:
        parts.append(frags[0])
    elif len(frags) > 1:
        parts.append("(" + " OR ".join(frags) + ")")
    if query:
        parts.append(query)
    return " ".join(parts).strip()


# ----------------------------------------------------- pure parsers (per engine)
def parse_searxng(data: dict) -> list:
    out = []
    for r in (data or {}).get("results", []):
        url = r.get("url")
        if url:
            out.append(SearchResult(url, r.get("title", ""), "searxng"))
    return out


def parse_google_cse(data: dict) -> list:
    out = []
    for r in (data or {}).get("items", []):
        url = r.get("link")
        if url:
            out.append(SearchResult(url, r.get("title", ""), "google"))
    return out


def parse_brave(data: dict) -> list:
    out = []
    for r in ((data or {}).get("web") or {}).get("results", []):
        url = r.get("url")
        if url:
            out.append(SearchResult(url, r.get("title", ""), "brave"))
    return out


_PARSERS = {"searxng": parse_searxng, "google": parse_google_cse, "brave": parse_brave}
_PAGE_SIZE = {"searxng": 10, "google": 10, "brave": 20}


# ------------------------------------------------------------- result hygiene
def dedupe(results) -> list:
    seen, out = set(), []
    for r in results:
        if r.url not in seen:
            seen.add(r.url)
            out.append(r)
    return out


def in_scope(results, site: str) -> list:
    """Keep only results whose host is ``site`` or a subdomain of it — a post-hoc
    guard for when an engine doesn't fully honour the ``site:`` operator."""
    if not site:
        return list(results)
    site = site.lower().strip().lstrip(".")
    kept = []
    for r in results:
        host = (urlsplit(r.url).hostname or "").lower()
        if host == site or host.endswith("." + site):
            kept.append(r)
    return kept


# --------------------------------------------------------- backend selection
def _first(*values) -> str:
    for v in values:
        if v:
            return v
    return ""


def resolve_engine(engine="", *, searx_url="", google_key="", google_cx="", brave_key=""):
    """Pick the engine and its config: an explicit ``engine`` if given, else the
    first one that's actually configured. Returns ``(engine_name, config)`` with
    ``engine_name`` empty when nothing is configured."""
    cfg = {
        "searx_url": _first(searx_url, os.environ.get("WRAITH_SEARXNG_URL")),
        "google_key": _first(google_key, os.environ.get("WRAITH_GOOGLE_API_KEY")),
        "google_cx": _first(google_cx, os.environ.get("WRAITH_GOOGLE_CX")),
        "brave_key": _first(brave_key, os.environ.get("WRAITH_BRAVE_API_KEY")),
    }
    if engine:
        return engine, cfg
    if cfg["searx_url"]:
        return "searxng", cfg
    if cfg["google_key"] and cfg["google_cx"]:
        return "google", cfg
    if cfg["brave_key"]:
        return "brave", cfg
    return "", cfg


def _page_request(engine, query, page, cfg):
    """Build the (url, headers) for one page of results from ``engine``."""
    if engine == "searxng":
        base = (cfg["searx_url"] or "").rstrip("/")
        if not base:
            raise SearchError("searxng needs --searx-url or WRAITH_SEARXNG_URL")
        qs = urlencode({"q": query, "format": "json", "pageno": page + 1})
        return f"{base}/search?{qs}", {}
    if engine == "google":
        if not (cfg["google_key"] and cfg["google_cx"]):
            raise SearchError("google needs WRAITH_GOOGLE_API_KEY and WRAITH_GOOGLE_CX")
        qs = urlencode({"key": cfg["google_key"], "cx": cfg["google_cx"], "q": query,
                        "num": _PAGE_SIZE["google"], "start": page * _PAGE_SIZE["google"] + 1})
        return f"https://www.googleapis.com/customsearch/v1?{qs}", {}
    if engine == "brave":
        if not cfg["brave_key"]:
            raise SearchError("brave needs WRAITH_BRAVE_API_KEY")
        qs = urlencode({"q": query, "count": _PAGE_SIZE["brave"], "offset": page})
        return (f"https://api.search.brave.com/res/v1/web/search?{qs}",
                {"X-Subscription-Token": cfg["brave_key"], "Accept": "application/json"})
    raise SearchError(f"unknown engine: {engine!r} (choose from {', '.join(ENGINES)})")


# ----------------------------------------------------------------- the search
async def search(query, *, engine="", max_results=30, site="", on_page=None,
                 searx_url="", google_key="", google_cx="", brave_key="") -> tuple:
    """Run ``query`` against a search backend; return ``(results, engine_name)``.

    Results are de-duplicated, kept in ``site`` scope when given, and capped at
    ``max_results``. Discovery only — the URLs are returned, never contacted.
    Raises SearchError when no backend is configured or one is misconfigured."""
    eng, cfg = resolve_engine(engine, searx_url=searx_url, google_key=google_key,
                              google_cx=google_cx, brave_key=brave_key)
    if not eng:
        raise SearchError(
            "no search backend configured — set one of:\n"
            "  WRAITH_SEARXNG_URL=https://searx.example     (a SearXNG instance, no API key)\n"
            "  WRAITH_GOOGLE_API_KEY=… and WRAITH_GOOGLE_CX=…  (Google Programmable Search)\n"
            "  WRAITH_BRAVE_API_KEY=…                        (Brave Search API)\n"
            "or pass --engine with its --searx-url / keys")
    if eng not in _PARSERS:
        raise SearchError(f"unknown engine: {eng!r} (choose from {', '.join(ENGINES)})")

    parser = _PARSERS[eng]
    results, page, max_pages = [], 0, 10
    while len(results) < max_results and page < max_pages:
        url, headers = _page_request(eng, query, page, cfg)
        r = await fetch(url, headers=headers, timeout=15.0)
        if r is None or not (200 <= r.status < 300):
            break
        try:
            batch = parser(json.loads(r.text))
        except ValueError:
            break
        if on_page is not None:
            on_page(eng, page + 1, len(batch))
        if not batch:
            break
        results.extend(batch)
        page += 1

    return in_scope(dedupe(results), site)[:max_results], eng
