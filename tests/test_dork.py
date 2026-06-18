import asyncio

import pytest

from wraith.core import search
from wraith.core.http import Response
from wraith.core.search import (
    PRESETS,
    SearchResult,
    build_query,
    dedupe,
    has_query_params,
    in_scope,
    parse_brave,
    parse_duckduckgo,
    parse_google_cse,
    parse_searxng,
    resolve_engine,
)


def test_build_query_composes_site_preset_and_raw():
    # a single preset is used as-is, AND-ed with the site scope and the raw query
    q = build_query("inurl:.php", ["params"], "target.com")
    assert q.startswith("site:target.com ")
    assert PRESETS["params"] in q
    assert q.endswith("inurl:.php")


def test_build_query_ors_multiple_presets():
    q = build_query("", ["params", "files"], "")
    assert q == f'({PRESETS["params"]} OR {PRESETS["files"]})'


def test_build_query_preset_alone_and_raw_alone():
    assert build_query("", ["params"], "") == PRESETS["params"]
    assert build_query("intitle:admin", [], "") == "intitle:admin"


def test_build_query_unknown_preset_raises():
    with pytest.raises(ValueError):
        build_query("", ["nope"], "")


def test_parse_searxng():
    data = {"results": [{"url": "http://a/1", "title": "A"}, {"url": "http://b/2"}, {"title": "no url"}]}
    res = parse_searxng(data)
    assert [r.url for r in res] == ["http://a/1", "http://b/2"]
    assert res[0].title == "A" and res[0].source == "searxng"
    assert parse_searxng({}) == []


def test_parse_google_cse():
    data = {"items": [{"link": "http://a/1", "title": "A"}, {"title": "no link"}]}
    assert [r.url for r in parse_google_cse(data)] == ["http://a/1"]
    assert parse_google_cse({}) == []


def test_parse_brave():
    data = {"web": {"results": [{"url": "http://a/1", "title": "A"}]}}
    assert [r.url for r in parse_brave(data)] == ["http://a/1"]
    assert parse_brave({"web": {}}) == [] and parse_brave({}) == []


def test_dedupe_keeps_first_occurrence():
    res = [SearchResult("http://x/1"), SearchResult("http://x/1"), SearchResult("http://x/2")]
    assert [r.url for r in dedupe(res)] == ["http://x/1", "http://x/2"]


def test_in_scope_filters_to_domain_and_subdomains():
    res = [SearchResult("http://target.com/a"), SearchResult("http://api.target.com/b"),
           SearchResult("http://evil.com/c"), SearchResult("http://nottarget.com/d")]
    assert {r.url for r in in_scope(res, "target.com")} == {"http://target.com/a", "http://api.target.com/b"}
    assert len(in_scope(res, "")) == 4          # no scope -> everything passes through


def test_has_query_params():
    assert has_query_params("http://h/facility.php?id=5") is True
    assert has_query_params("http://h/x?a=1&b=2") is True
    assert has_query_params("http://h/dorks/") is False          # a blog/listing page
    assert has_query_params("https://gist.github.com/abc/123") is False
    assert has_query_params("http://h/x?flag") is False          # no key=value


def test_search_with_params_drops_non_parametric(monkeypatch):
    for var in ("WRAITH_SEARXNG_URL", "WRAITH_GOOGLE_API_KEY", "WRAITH_GOOGLE_CX", "WRAITH_BRAVE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    html = (
        '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fblog.test%2Fdorks-list">B</a>'
        '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Ftarget.test%2Fitem.php%3Fid%3D5">T</a>'
    )

    async def fake_fetch(url, **kw):
        return Response(200, url, html, {})

    monkeypatch.setattr(search, "fetch", fake_fetch)
    everything, _ = asyncio.run(search.search("x", with_params=False))
    parametric, _ = asyncio.run(search.search("x", with_params=True))
    assert [r.url for r in everything] == ["https://blog.test/dorks-list", "https://target.test/item.php?id=5"]
    assert [r.url for r in parametric] == ["https://target.test/item.php?id=5"]


def test_resolve_engine_prefers_explicit_then_configured(monkeypatch):
    for var in ("WRAITH_SEARXNG_URL", "WRAITH_GOOGLE_API_KEY", "WRAITH_GOOGLE_CX", "WRAITH_BRAVE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert resolve_engine()[0] == "duckduckgo"             # no config -> the no-key default
    assert resolve_engine(searx_url="http://s")[0] == "searxng"
    monkeypatch.setenv("WRAITH_GOOGLE_API_KEY", "k")
    monkeypatch.setenv("WRAITH_GOOGLE_CX", "cx")
    assert resolve_engine()[0] == "google"                 # first configured backend
    assert resolve_engine("brave")[0] == "brave"           # explicit choice wins


def test_search_lists_urls_and_never_touches_them(monkeypatch):
    # search() must hit only the search API and return parsed URLs — it never
    # fetches a result URL itself (that's the whole point of "discovery only").
    calls = []

    async def fake_fetch(url, **kw):
        calls.append(url)
        if "pageno=1" in url:                  # first page has results; the next is empty -> stop
            body = ('{"results":[{"url":"http://found.test/a?id=1","title":"A"},'
                    '{"url":"http://found.test/b?id=2","title":"B"}]}')
        else:
            body = '{"results":[]}'
        return Response(200, url, body, {"content-type": "application/json"})

    monkeypatch.setattr(search, "fetch", fake_fetch)
    results, engine = asyncio.run(
        search.search("inurl:id", searx_url="http://searx.local", max_results=10))
    assert engine == "searxng"
    assert [r.url for r in results] == ["http://found.test/a?id=1", "http://found.test/b?id=2"]
    assert all("searx.local" in u for u in calls)          # every request went to the backend
    assert not any("found.test" in u for u in calls)       # never to a discovered URL


def test_parse_duckduckgo_decodes_uddg_and_drops_internal():
    html = (
        '<a rel="nofollow" class="result__a" '
        'href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fshop.test%2Fitem.php%3Fid%3D5&amp;rut=x">Shop</a>'
        '<a class="result__a" href="//duckduckgo.com/l/?uddg=http%3A%2F%2Fblog.test%2Fp.php%3Fid%3D2">Blog</a>'
        '<a class="result__a" href="https://direct.test/x?id=1">Direct</a>'
        '<a class="header__logo" href="//duckduckgo.com/about">internal</a>'
    )
    urls = [r.url for r in parse_duckduckgo(html)]
    # uddg redirects are decoded, a direct link is kept, DDG's own nav is dropped
    assert urls == ["https://shop.test/item.php?id=5", "http://blog.test/p.php?id=2", "https://direct.test/x?id=1"]
    assert parse_duckduckgo("") == []


def test_search_uses_duckduckgo_by_default(monkeypatch):
    # with nothing configured, `search()` works out of the box via DuckDuckGo,
    # parses its HTML, hits one page, and contacts only the engine.
    for var in ("WRAITH_SEARXNG_URL", "WRAITH_GOOGLE_API_KEY", "WRAITH_GOOGLE_CX", "WRAITH_BRAVE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    calls = []
    ddg_html = (
        '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fa.test%2Fp.php%3Fid%3D1">A</a>'
        '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fb.test%2Fp.php%3Fid%3D2">B</a>'
    )

    async def fake_fetch(url, **kw):
        calls.append(url)
        return Response(200, url, ddg_html, {"content-type": "text/html"})

    monkeypatch.setattr(search, "fetch", fake_fetch)
    results, engine = asyncio.run(search.search("inurl:php?id=", max_results=30))
    assert engine == "duckduckgo"
    assert [r.url for r in results] == ["https://a.test/p.php?id=1", "https://b.test/p.php?id=2"]
    assert len(calls) == 1                                  # single page — no pointless re-fetch
    assert all("duckduckgo.com" in u for u in calls)       # only the search engine was contacted


def test_search_misconfigured_engine_raises(monkeypatch):
    # an explicitly chosen API backend without its keys is an error — and it's
    # caught before any network call (the default DuckDuckGo needs no config)
    for var in ("WRAITH_GOOGLE_API_KEY", "WRAITH_GOOGLE_CX"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(search.SearchError):
        asyncio.run(search.search("inurl:id", engine="google"))
