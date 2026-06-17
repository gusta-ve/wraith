"""Web — audit security headers, cookie flags and CORS configuration.

Low-noise, high-signal checks: presence of standard hardening headers, secure
cookie attributes, and dangerous CORS reflection.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from wraith.core import web
from wraith.core.http import fetch
from wraith.core.models import Severity
from wraith.core.phase import Phase, register

# (header key, label, severity, description)
REQUIRED = [
    ("content-security-policy", "Content-Security-Policy", Severity.MEDIUM,
     "No CSP: injected scripts and resources are not restricted."),
    ("x-frame-options", "X-Frame-Options", Severity.LOW,
     "No clickjacking protection (X-Frame-Options or CSP frame-ancestors)."),
    ("x-content-type-options", "X-Content-Type-Options", Severity.LOW,
     "No nosniff: browsers may MIME-sniff responses."),
    ("referrer-policy", "Referrer-Policy", Severity.INFO,
     "No Referrer-Policy: full URLs may leak to third parties."),
    ("strict-transport-security", "Strict-Transport-Security", Severity.MEDIUM,
     "No HSTS: connections can be downgraded to HTTP."),
]


def missing_headers(headers: dict, scheme: str) -> list:
    present = {k.lower() for k in headers}
    out = []
    for key, label, sev, desc in REQUIRED:
        if key == "strict-transport-security" and scheme != "https":
            continue
        if key == "x-frame-options":
            csp = headers.get("content-security-policy", "").lower()
            if key not in present and "frame-ancestors" not in csp:
                out.append((label, sev, desc))
            continue
        if key not in present:
            out.append((label, sev, desc))
    return out


def cookie_issues(set_cookie: str, scheme: str) -> list:
    if not set_cookie:
        return []
    low = set_cookie.lower()
    missing = []
    if "httponly" not in low:
        missing.append("HttpOnly")
    if scheme == "https" and "secure" not in low:
        missing.append("Secure")
    if "samesite" not in low:
        missing.append("SameSite")
    return missing


def cors_issue(acao: str, acac: str, origin: str):
    """Judge a CORS response to our forged Origin.

    acao/acac are the Access-Control-Allow-Origin / -Allow-Credentials headers.
    The dangerous case is a server that echoes back whatever Origin we sent: it
    means any website can read this one's responses. With credentials allowed on
    top of that, those reads happen as the logged-in victim — hence High.
    """
    acao = acao or ""
    if acao == "*":
        return ("allows any origin (*)", Severity.LOW)
    if origin and origin in acao:                       # our fake origin came back reflected
        if (acac or "").lower() == "true":
            return (f"reflects arbitrary origin with credentials ({acao})", Severity.HIGH)
        return (f"reflects arbitrary origin ({acao})", Severity.MEDIUM)
    return None


@register
class SecurityHeadersPhase(Phase):
    name = "security-headers"
    requires = frozenset({"http-probe"})
    description = "Audit security headers, cookie flags and CORS per host."

    EVIL_ORIGIN = "https://wraith.evil"

    async def run(self, ws, console) -> None:
        bases = web.http_bases(ws)
        if not bases:
            console.warn("no HTTP endpoints to audit")
            return
        for base in bases:
            scheme = urlsplit(base).scheme
            r = await fetch(base + "/")
            if r is None:
                continue

            for label, sev, desc in missing_headers(r.headers, scheme):
                console.warn(f"missing header  {label}  ({base})")
                ws.add_finding(title=f"Missing security header: {label}", severity=sev,
                               phase=self.name, target=base, evidence=f"{label} not set", description=desc)

            missing_flags = cookie_issues(r.headers.get("set-cookie", ""), scheme)
            if missing_flags:
                console.warn(f"cookie flags missing  {', '.join(missing_flags)}  ({base})")
                ws.add_finding(title=f"Cookie missing flags: {', '.join(missing_flags)}",
                               severity=Severity.LOW, phase=self.name, target=base,
                               evidence=r.headers.get("set-cookie", ""),
                               description="Session/tracking cookies lack hardening attributes.")

            cr = await fetch(base + "/", headers={"Origin": self.EVIL_ORIGIN})
            if cr is not None:
                issue = cors_issue(cr.headers.get("access-control-allow-origin", ""),
                                   cr.headers.get("access-control-allow-credentials", ""),
                                   self.EVIL_ORIGIN)
                if issue:
                    desc, sev = issue
                    console.bad(f"CORS  {desc}  ({base})")
                    ws.add_finding(title=f"CORS misconfiguration: {desc}", severity=sev,
                                   phase=self.name, target=base,
                                   evidence=f"Origin: {self.EVIL_ORIGIN} -> ACAO: "
                                            f"{cr.headers.get('access-control-allow-origin', '')}",
                                   description="Cross-origin resource sharing trusts untrusted origins.")
