"""Search-engine backends for ``wraith dork`` — a query in, result URLs out.

``wraith dork`` turns a search query (a *dork* — a query using operators like
``inurl:``, ``intitle:``, ``ext:``) into a list of result URLs, and stops there.
It is a **discovery** command: it never sends a single request to the URLs it
finds. What you do with the list afterwards — and whether you're authorized to —
is a separate, deliberate step (``wraith <target>``), never something this module
does for you. There is, by design, no function here that touches a result.

By default ``wraith dork`` needs **no setup**: it scrapes DuckDuckGo's HTML
endpoint with no API key required. Configure an API backend for heavier or steadier
use and wraith prefers it automatically;
``--engine`` forces a specific one:

  * ``duckduckgo``  DuckDuckGo HTML endpoint        (default — no key)
  * ``searxng``     a SearXNG instance's JSON API   ``WRAITH_SEARXNG_URL``  (no key)
  * ``google``      Google Programmable Search      ``WRAITH_GOOGLE_API_KEY`` + ``WRAITH_GOOGLE_CX``
  * ``brave``       Brave Search API                ``WRAITH_BRAVE_API_KEY``

Each engine's response (JSON for the APIs, HTML for DuckDuckGo) is turned into
results by a small pure function (tested); the async ``search()`` pages until it
has enough, honouring wraith's opsec profile (UA/proxy/throttle) on the calls.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit

from wraith.core.http import fetch, random_agent

ENGINES = ("duckduckgo", "searxng", "google", "brave")

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


# DuckDuckGo's HTML endpoint wraps each result link as
# `//duckduckgo.com/l/?uddg=<urlencoded-target>&rut=…`; the real URL is the uddg
# param. Match the result anchors regardless of attribute order, decode uddg, and
# drop DDG's own internal links.
_DDG_ANCHOR = re.compile(r"<a\b([^>]*\bresult__a\b[^>]*)>", re.I)
_HREF = re.compile(r'href="([^"]+)"', re.I)


def parse_duckduckgo(html: str) -> list:
    out, seen = [], set()
    for a in _DDG_ANCHOR.finditer(html or ""):
        hm = _HREF.search(a.group(1))
        if not hm:
            continue
        href = hm.group(1).replace("&amp;", "&")
        url = (parse_qs(urlsplit(href).query).get("uddg") or [href])[0] if "uddg=" in href else href
        if not url.startswith(("http://", "https://")):
            continue
        host = (urlsplit(url).hostname or "").lower()
        if host and not host.endswith("duckduckgo.com") and url not in seen:
            seen.add(url)
            out.append(SearchResult(url, "", "duckduckgo"))
    return out


def _json_extractor(parser):
    """Wrap a JSON parser so the search loop can treat every engine the same —
    raw response text in, results out (an unparseable body yields nothing)."""
    def extract(text):
        try:
            return parser(json.loads(text))
        except ValueError:
            return []
    return extract


# response text -> results, per engine (JSON for the APIs, HTML for DuckDuckGo)
_EXTRACTORS = {
    "duckduckgo": parse_duckduckgo,
    "searxng": _json_extractor(parse_searxng),
    "google": _json_extractor(parse_google_cse),
    "brave": _json_extractor(parse_brave),
}
_PAGE_SIZE = {"searxng": 10, "google": 10, "brave": 20}
_SINGLE_PAGE = {"duckduckgo"}   # HTML scrape: one page, no reliable result offset


# ------------------------------------------------------------- result hygiene
def dedupe(results) -> list:
    seen, out = set(), []
    for r in results:
        if r.url not in seen:
            seen.add(r.url)
            out.append(r)
    return out


def has_query_params(url: str) -> bool:
    """True if the URL carries a ``?key=value`` query parameter — the parametric
    URLs worth injection-testing. Filters out the blog posts and cheat-sheets
    *about* dorking that a search engine surfaces next to real targets."""
    query = urlsplit(url).query
    return any("=" in pair and pair.split("=", 1)[0].strip() for pair in query.split("&"))


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
    first configured API backend, else ``duckduckgo`` (the no-key default, so a
    bare ``wraith dork`` just works). Returns ``(engine_name, config)``."""
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
    return "duckduckgo", cfg


def _page_request(engine, query, page, cfg):
    """Build the (url, headers) for one page of results from ``engine``."""
    if engine == "duckduckgo":
        qs = urlencode({"q": query})
        # the HTML endpoint is the scrape-friendly, no-key one; DDG expects a
        # browser-looking UA, so override just this call's User-Agent.
        return f"https://html.duckduckgo.com/html/?{qs}", {"User-Agent": random_agent()}
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
async def search(query, *, engine="", max_results=30, site="", with_params=False,
                 on_page=None, searx_url="", google_key="", google_cx="", brave_key="") -> tuple:
    """Run ``query`` against a search backend; return ``(results, engine_name)``.

    Results are de-duplicated, kept in ``site`` scope when given, optionally
    filtered to parametric URLs (``with_params``), and capped at ``max_results``.
    Discovery only — the URLs are returned, never contacted. Raises SearchError if
    a chosen backend (e.g. ``--engine google`` without its keys) is misconfigured."""
    eng, cfg = resolve_engine(engine, searx_url=searx_url, google_key=google_key,
                              google_cx=google_cx, brave_key=brave_key)
    if eng not in _EXTRACTORS:
        raise SearchError(f"unknown engine: {eng!r} (choose from {', '.join(ENGINES)})")

    extract = _EXTRACTORS[eng]
    results, page, max_pages = [], 0, 10
    while len(results) < max_results and page < max_pages:
        url, headers = _page_request(eng, query, page, cfg)
        r = await fetch(url, headers=headers, timeout=15.0)
        if r is None or not (200 <= r.status < 300):
            break
        batch = extract(r.text)
        if on_page is not None:
            on_page(eng, page + 1, len(batch))
        if not batch:
            break
        results.extend(batch)
        if eng in _SINGLE_PAGE:          # HTML scrape: one page, no reliable result offset
            break
        page += 1

    final = in_scope(dedupe(results), site)
    if with_params:
        final = [r for r in final if has_query_params(r.url)]
    return final[:max_results], eng
