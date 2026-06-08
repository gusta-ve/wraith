"""Web — reflected XSS, error-based SQLi and open redirect.

Crawls the target, collects injectable parameters (query strings + HTML forms)
and tests each one. Detection is designed to be low false-positive:

  * XSS   — a marker payload with raw <, >, " must reflect *unencoded*.
  * SQLi  — a single quote must induce a database error absent from the baseline.
  * Open redirect — a redirect-style param must land in the Location header.
"""

from __future__ import annotations

import random
import re
import string
from urllib.parse import urlencode, urlsplit

from wraith.core import web
from wraith.core.http import fetch
from wraith.core.models import Severity
from wraith.core.phase import Phase, register

_SQL_ERRORS = re.compile(
    r"(you have an error in your sql syntax|warning: mysqli?_|mysql_fetch|"
    r"valid mysql result|ORA-\d{5}|quoted string not properly terminated|"
    r"PostgreSQL.*ERROR|pg_query\(\)|syntax error at or near|SQLite3?::|"
    r"sqlite3.OperationalError|Microsoft OLE DB Provider|"
    r"Unclosed quotation mark|SQLSTATE\[)",
    re.I,
)

REDIRECT_PARAMS = {
    "url", "next", "redirect", "redirect_url", "redirecturl", "return", "returnurl",
    "return_url", "dest", "destination", "continue", "r", "u", "go", "to", "target",
    "link", "out", "view", "image_url",
}


def looks_like_sql_error(text: str) -> bool:
    return bool(_SQL_ERRORS.search(text or ""))


@register
class InjectionPhase(Phase):
    name = "injection"
    requires = frozenset({"http-probe"})
    description = "Reflected XSS, error-based SQLi and open redirect on parameters."

    MAX_PAGES = 25
    MAX_POINTS = 80

    async def run(self, ws, console) -> None:
        for base in self._bases(ws):
            host = urlsplit(base).netloc
            seeds = [base + "/"] + [e.url for e in ws.endpoints if e.url.startswith(base)]
            pages = await web.crawl(seeds, host, fetch, self.MAX_PAGES)

            points, seen = [], set()
            for url, resp in pages.items():
                for pt in web.build_points(url, resp.text):
                    key = (pt.method, pt.action, pt.param, pt.location)
                    if key not in seen:
                        seen.add(key)
                        points.append(pt)
            points = points[: self.MAX_POINTS]
            if not points:
                console.warn(f"{base}: no injectable parameters found")
                continue

            console.info(f"{base}: testing {len(points)} parameter(s)")
            for pt in points:
                await self._test_xss(ws, console, pt)
                await self._test_sqli(ws, console, pt)
                if pt.param.lower() in REDIRECT_PARAMS and pt.location == "query":
                    await self._test_open_redirect(ws, console, pt)

    async def _send(self, pt, value):
        values = dict(pt.values)
        values[pt.param] = value
        if pt.location == "query":
            return await fetch(f"{pt.action}?{urlencode(values)}", method="GET", allow_redirects=False)
        return await fetch(pt.action, method="POST", data=values, allow_redirects=False)

    async def _test_xss(self, ws, console, pt) -> None:
        probe = "wx" + "".join(random.choice(string.ascii_lowercase) for _ in range(6))
        payload = f'{probe}"><svg/onload=alert(1)>'
        r = await self._send(pt, payload)
        if r and payload in r.text:
            self._report(ws, console, "Reflected XSS", Severity.HIGH, pt, payload,
                         "Input is reflected without output encoding, allowing script injection.")

    async def _test_sqli(self, ws, console, pt) -> None:
        baseline = await self._send(pt, "1")
        injected = await self._send(pt, "1'")
        base_error = bool(baseline and looks_like_sql_error(baseline.text))
        if injected and looks_like_sql_error(injected.text) and not base_error:
            self._report(ws, console, "SQL Injection (error-based)", Severity.HIGH, pt, "1'",
                         "A single quote triggers a database error, indicating unsanitized SQL.")

    async def _test_open_redirect(self, ws, console, pt) -> None:
        r = await self._send(pt, "https://wraith.example/")
        if r is None:
            return
        location = r.headers.get("location", "")
        if r.status in (301, 302, 303, 307, 308) and "wraith.example" in location:
            self._report(ws, console, "Open Redirect", Severity.MEDIUM, pt, "https://wraith.example/",
                         "The redirect target is taken from user input without validation.")

    def _report(self, ws, console, title, sev, pt, payload, desc) -> None:
        where = f"{pt.method} {pt.action} [{pt.param}]"
        console.bad(f"{sev.label.upper():5} {title}  {where}")
        ws.add_finding(title=f"{title} in '{pt.param}'", severity=sev, phase=self.name,
                       target=pt.action, evidence=f"{where} payload={payload!r}", description=desc)

    @staticmethod
    def _bases(ws) -> list:
        seen, out = set(), []
        for e in ws.endpoints:
            p = urlsplit(e.url)
            base = f"{p.scheme}://{p.netloc}"
            if base not in seen:
                seen.add(base)
                out.append(base)
        return out
