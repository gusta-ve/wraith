"""Web exploitation — Broken Access Control (OWASP A01) & IDOR.

Two complementary tests, driven by a set of authenticated sessions:

  1. Vertical BAC (differential replay)
     Crawl the app as the highest-privilege session, then replay every request
     under the lower-privilege sessions. If a lower principal receives a 2xx
     response whose body matches the privileged one, access control is bypassed.
     Resources that an anonymous session can also reach are treated as public
     and suppressed.

  2. IDOR (sequential object probing)
     For URLs that carry a numeric object id, mutate the id (±1) under the same
     session. If a neighbouring id returns a *different valid* object (not the
     not-found page, not the same record), object references are unprotected.

Sessions are supplied via `--sessions FILE` (see examples/sessions.json).
"""

from __future__ import annotations

import difflib
import re
from collections import deque
from urllib.parse import urljoin, urlsplit, urlunsplit

from wraith.core import web
from wraith.core.http import fetch
from wraith.core.models import Severity
from wraith.core.phase import Phase, register

ROLE_RANK = {
    "none": 0, "anon": 0, "guest": 0,
    "low": 1, "user": 1, "member": 1,
    "med": 2, "medium": 2, "staff": 2,
    "high": 3, "admin": 3, "root": 3,
}

_INT_RE = re.compile(r"(?<!\d)(\d{1,9})(?!\d)")
_LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "sso")
_STATIC_EXT = (".css", ".js", ".mjs", ".map", ".svg", ".png", ".jpg", ".jpeg",
               ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot")


@register
class AccessControlPhase(Phase):
    name = "access-control"
    requires = frozenset()
    description = "Broken Access Control & IDOR via multi-session differential replay."

    # A vertical bypass means a lower principal sees content *identical* to the
    # privileged one (the same protected resource) — not a personalized view of
    # the same template. The high threshold separates those two cases and
    # absorbs trivial whitespace noise.
    SIMILAR = 0.98
    MAX_PAGES = 40

    async def run(self, ws, console) -> None:
        sessions = list(ws.sessions)
        if len(sessions) < 2:
            console.warn("access-control needs >=2 sessions (use --sessions FILE); skipping")
            return

        base_url = ws.meta.get("base_url") or f"http://{ws.target}"
        seeds = ws.meta.get("seeds") or ["/"]
        host = urlsplit(base_url).netloc
        seed_urls = [urljoin(base_url, s) for s in seeds]

        rank = lambda s: ROLE_RANK.get((s.role or "low").lower(), 1)
        priv = max(sessions, key=rank)
        console.info(f"privileged session: '{priv.name}' (role {priv.role})")

        # Crawl as every non-anonymous session (anon only hits login walls).
        discovered: dict[str, dict] = {}
        for s in sessions:
            if rank(s) == 0:
                continue
            discovered[s.name] = await self._crawl(seed_urls, host, s)
        console.good(f"discovered {len(discovered.get(priv.name, {}))} URL(s) as '{priv.name}'")

        for url, resp in discovered.get(priv.name, {}).items():
            ws.add_endpoint(url, "GET", resp.status, server=resp.headers.get("server", ""))

        await self._test_vertical_bac(ws, console, sessions, priv, rank, discovered.get(priv.name, {}))
        await self._test_idor(ws, console, sessions, rank, discovered)

    # ------------------------------------------------------------------ BAC
    async def _test_vertical_bac(self, ws, console, sessions, priv, rank, priv_map) -> None:
        for url, rp in priv_map.items():
            if not self._ok(rp) or self._is_static(url):
                continue
            # A resource a no-cookie request can already read is public, not a
            # bypass — verify this ourselves even when no anon session was given.
            anon = await fetch(url, None, None)
            if (anon is not None and self._ok(anon) and not self._redirected(anon, url)
                    and self._similar(anon.text, rp.text) >= self.SIMILAR):
                continue
            public = False
            bypassers = []
            for s in sessions:
                if s.name == priv.name:
                    continue
                rs = await fetch(url, s.cookies, s.headers)
                if rs is None or not self._ok(rs):
                    continue
                # If the server sent them somewhere else (login, their own area),
                # they were *denied* — a redirect is access control working, not a
                # bypass. Single-page apps serve a near-identical shell on every
                # route, so without this the shells read as a false bypass.
                if self._redirected(rs, url):
                    continue
                if self._similar(rs.text, rp.text) >= self.SIMILAR:
                    if rank(s) == 0:
                        public = True       # anon sees the same content -> it's public
                    else:
                        bypassers.append(s)
            if public or not bypassers:
                continue
            # One finding per protected resource, not one per session. A principal
            # ranked below the privileged one reaching it is a real vertical bypass
            # (High); a same-rank principal is a weaker horizontal issue (Medium).
            sev = Severity.HIGH if any(rank(s) < rank(priv) for s in bypassers) else Severity.MEDIUM
            who = ", ".join(s.name for s in bypassers)
            path = urlsplit(url).path
            console.finding(sev.label, f"BAC  {path}  ← {who}")
            ws.add_finding(
                title=f"Broken Access Control at {path}",
                severity=sev,
                phase=self.name,
                target=url,
                evidence=f"session(s) {who} received 2xx matching privileged '{priv.name}'",
                description="A lower-privilege principal received the same protected content as a "
                            "privileged one (differential replay across sessions).",
            )

    # ----------------------------------------------------------------- IDOR
    async def _test_idor(self, ws, console, sessions, rank, discovered) -> None:
        by_name = {s.name: s for s in sessions}
        flagged: set = set()
        for name, dmap in discovered.items():
            s = by_name[name]
            for url, r in dmap.items():
                if not self._ok(r) or self._is_static(url):
                    continue
                _, pq = self._pq(url)
                if self._id_span(pq) is None:        # no object-id to mutate (skip ?page=/?hint=)
                    continue
                path = urlsplit(url).path
                if (name, path) in flagged:
                    continue
                oid = self._first_id(url)
                not_found = await fetch(self._with_id(url, 999_999_999), s.cookies, s.headers)
                for delta in (1, -1):
                    nid = oid + delta
                    if nid < 0:
                        continue
                    probe_url = self._with_id(url, nid)
                    if not probe_url or probe_url == url:
                        continue
                    pr = await fetch(probe_url, s.cookies, s.headers)
                    if pr is None or not self._ok(pr):
                        continue
                    if not_found and self._similar(pr.text, not_found.text) >= 0.9:
                        continue                         # it's just the not-found page
                    if self._similar(pr.text, r.text) >= 0.98:
                        continue                         # identical to our own object
                    flagged.add((name, path))
                    console.finding("High", f"IDOR  '{name}' → {urlsplit(probe_url).path}")
                    ws.add_finding(
                        title=f"IDOR at {path}",
                        severity=Severity.HIGH,
                        phase=self.name,
                        target=probe_url,
                        evidence=f"session '{name}' read a different valid object by changing the id ({url} -> {probe_url})",
                        description="A numeric object reference is served without an ownership check; "
                                    "incrementing the id exposes other principals' objects.",
                    )
                    break

    # -------------------------------------------------------------- crawler
    async def _crawl(self, seed_urls, host, session) -> dict:
        seen: set = set()
        out: dict = {}
        queue = deque(seed_urls)
        while queue and len(out) < self.MAX_PAGES:
            url = queue.popleft().split("#")[0]
            if url in seen:
                continue
            seen.add(url)
            r = await fetch(url, session.cookies, session.headers)
            if r is None:
                continue
            out[url] = r
            if self._ok(r) and r.is_html:
                for link in web.extract_links(url, r.text, host):
                    if link not in seen:
                        queue.append(link)
        return out

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _similar(a, b) -> float:
        return difflib.SequenceMatcher(None, (a or "")[:4000], (b or "")[:4000]).ratio()

    @staticmethod
    def _ok(resp) -> bool:
        if resp is None or not (200 <= resp.status < 300):
            return False
        path = urlsplit(resp.url).path.lower()
        if any(h in path for h in _LOGIN_HINTS):
            return False
        if 'type="password"' in resp.text.lower():
            return False
        return True

    @staticmethod
    def _redirected(resp, requested_url) -> bool:
        # True if the response settled on a different path than asked for —
        # i.e. the server bounced the principal somewhere else.
        return urlsplit(resp.url).path.rstrip("/") != urlsplit(requested_url).path.rstrip("/")

    @staticmethod
    def _is_static(url) -> bool:
        # Static assets (css/js/images/fonts, framework files) are public by
        # design — never an access-control finding.
        p = urlsplit(url).path.lower()
        return p.endswith(_STATIC_EXT) or p.startswith(("/_framework", "/_content"))

    @staticmethod
    def _pq(url):
        """(urlsplit parts, ``path?query`` string) — the addressable part an id
        lives in. The port sits in netloc, so it's never seen as an id here."""
        parts = urlsplit(url)
        return parts, parts.path + (("?" + parts.query) if parts.query else "")

    @staticmethod
    def _id_span(pq):
        """(start, end) of the integer to treat as the object id inside ``pq``
        (``path?query``), or None when there's no object-id candidate.

        Prefer the value of an id-like query parameter (name ``id`` or ending in
        ``id``: ``user_id``, ``pid``…); otherwise the **last** integer in the path.
        A number that lives only in a *non*-id query parameter — ``?page=2``,
        ``?hint=3``, ``?limit=10`` — is paging/UI state, not an object reference:
        mutating it is an IDOR false positive, so it is deliberately not a
        candidate (returns None). Taking the last path integer, never the first,
        keeps a version or date segment (``/api/v1/``, ``/2024/``) from being
        mistaken for the id."""
        path, sep, query = pq.partition("?")
        if query:
            offset = len(path) + len(sep)
            for m in re.finditer(r"([^&=]+)=([^&]*)", query):
                if m.group(1).lower().endswith("id"):
                    vm = _INT_RE.search(m.group(2))
                    if vm:
                        start = offset + m.start(2) + vm.start()
                        return start, start + (vm.end() - vm.start())
        path_ints = list(_INT_RE.finditer(path))
        if path_ints:
            return path_ints[-1].start(), path_ints[-1].end()
        return None

    @classmethod
    def _first_id(cls, url) -> int:
        _, pq = cls._pq(url)
        start, end = cls._id_span(pq)              # callers gate on _id_span() not being None
        return int(pq[start:end])

    @classmethod
    def _with_id(cls, url, new_value) -> str | None:
        parts, pq = cls._pq(url)
        span = cls._id_span(pq)
        if span is None:
            return None
        new_pq = pq[: span[0]] + str(new_value) + pq[span[1]:]
        path, _, query = new_pq.partition("?")
        return urlunsplit((parts.scheme, parts.netloc, path, query, ""))
