"""Web — fingerprint server software, languages and frameworks/CMS.

Combines header, cookie and body signals into a per-host technology profile.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from wraith.core.http import fetch
from wraith.core.models import Severity
from wraith.core.phase import Phase, register

_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
_NG_RE = re.compile(r'ng-version=["\']([^"\']+)', re.I)
_SERVER_PRODUCTS = ("nginx", "apache", "microsoft-iis", "openresty", "litespeed",
                    "caddy", "python", "werkzeug", "gunicorn", "tomcat", "jetty")

# cookie name (lowercased substring) -> technology
_COOKIE_TECH = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "wordpress_": "WordPress",
    "wp-settings": "WordPress",
    "csrftoken": "Django",
    "sessionid": "Django",
    "_rails": "Ruby on Rails",
    "ci_session": "CodeIgniter",
}

# body substring (lowercased) -> technology
_BODY_TECH = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "/sites/all/": "Drupal",
    "drupal.settings": "Drupal",
    "/media/jui/": "Joomla",
    "__next_data__": "Next.js",
    "/_nuxt/": "Nuxt.js",
    "data-reactroot": "React",
    "react-dom": "React",
    "__vue__": "Vue.js",
    "laravel": "Laravel",
}


def _server_products(server: str) -> dict:
    found = {}
    low = server.lower()
    for product in _SERVER_PRODUCTS:
        if product in low:
            m = re.search(re.escape(product) + r"[/ ]([\d.]+)", low)
            label = "IIS" if product == "microsoft-iis" else product.capitalize()
            found[label] = m.group(1) if m else ""
    return found


def detect(headers: dict, body: str) -> dict:
    found: dict[str, str] = {}
    found.update(_server_products(headers.get("server", "")))

    xpb = headers.get("x-powered-by", "")
    for token in xpb.split(","):
        token = token.strip()
        if not token:
            continue
        m = re.match(r"([A-Za-z.\- ]+)[/ ]?([\d.]+)?", token)
        if m:
            found[m.group(1).strip()] = (m.group(2) or "").strip()

    if headers.get("x-aspnet-version"):
        found["ASP.NET"] = headers["x-aspnet-version"]
    if headers.get("x-drupal-cache") or headers.get("x-generator", "").lower().startswith("drupal"):
        found.setdefault("Drupal", "")

    cookies = headers.get("set-cookie", "").lower()
    for marker, tech in _COOKIE_TECH.items():
        if marker in cookies:
            found.setdefault(tech, "")

    low_body = (body or "").lower()
    for marker, tech in _BODY_TECH.items():
        if marker in low_body:
            found.setdefault(tech, "")

    m = _GENERATOR_RE.search(body or "")
    if m:
        gen = m.group(1).strip()
        parts = gen.split()
        found[parts[0]] = parts[1] if len(parts) > 1 else ""
    m = _NG_RE.search(body or "")
    if m:
        found["Angular"] = m.group(1)

    return found


@register
class TechDetectPhase(Phase):
    name = "tech-detect"
    requires = frozenset({"http-probe"})
    description = "Fingerprint server, language and framework/CMS per host."

    MAX_ENDPOINTS = 25

    async def run(self, ws, console) -> None:
        endpoints = ws.endpoints[: self.MAX_ENDPOINTS]
        if not endpoints:
            console.warn("no endpoints to fingerprint")
            return

        host_tech: dict[str, dict] = {}
        for ep in endpoints:
            r = await fetch(ep.url)
            if r is None:
                continue
            techs = detect(r.headers, r.text)
            if not techs:
                continue
            ep.tech = [f"{name} {ver}".strip() for name, ver in techs.items()]
            host = urlsplit(ep.url).netloc
            host_tech.setdefault(host, {}).update(techs)
            console.good(f"{ep.url}  {', '.join(ep.tech)}")

        for host, techs in host_tech.items():
            labels = ", ".join(f"{n} {v}".strip() for n, v in techs.items())
            ws.add_finding(
                title=f"Technology fingerprint: {host}",
                severity=Severity.INFO,
                phase=self.name,
                target=host,
                evidence=labels,
                description="Software and frameworks identified from HTTP responses.",
            )
