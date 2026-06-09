"""Web — discover hidden paths and files via wordlist probing.

Detects soft-404 / wildcard responses with a random-path baseline so a site that
returns 200 for everything doesn't drown the output in false hits.
"""

from __future__ import annotations

import asyncio
import difflib
import random
import string
from urllib.parse import urlsplit

from wraith.core.http import fetch
from wraith.core.models import Severity
from wraith.core.phase import Phase, register

DEFAULT_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "config", "config.php",
    ".env", ".git/HEAD", ".git/config", "backup", "backup.zip", "backup.sql",
    "db.sql", "dump.sql", "robots.txt", "sitemap.xml", ".htaccess",
    "server-status", "phpinfo.php", "info.php", "test", "dev", "old", "tmp",
    "uploads", "files", "api", "api/v1", "swagger", "swagger.json",
    "openapi.json", "graphql", "wp-login.php", "wp-admin", "wp-config.php.bak",
    "user", "users", "account", "private", "secret", "credentials", "id_rsa",
    ".ssh/id_rsa", "console", "actuator", "actuator/health", "metrics",
    "status", "debug", ".vscode", ".idea", "composer.json", "package.json",
    "docker-compose.yml", "Dockerfile", "README.md", "CHANGELOG.md",
]

SENSITIVE = (".env", ".git", ".sql", ".bak", "id_rsa", "wp-config", "credential",
             "secret", "backup", ".ssh", "composer.json", "package.json",
             "phpinfo", "actuator", "swagger", "openapi", ".htaccess")

INTERESTING = {200, 204, 301, 302, 307, 308, 401, 403, 500}


@register
class ContentDiscoveryPhase(Phase):
    name = "content-discovery"
    requires = frozenset({"http-probe"})
    description = "Probe common paths/files to discover hidden content."

    CONCURRENCY = 40

    async def run(self, ws, console) -> None:
        bases = self._bases(ws)
        if not bases:
            console.warn("no HTTP endpoints to enumerate")
            return
        words = self._wordlist(ws, console)
        for base in bases:
            await self._enumerate(ws, console, base, words)

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

    @staticmethod
    def _wordlist(ws, console) -> list:
        path = ws.meta.get("wordlist")
        if path:
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    words = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
                console.info(f"wordlist: {len(words)} entries from {path}")
                return words
            except OSError as exc:
                console.warn(f"cannot read wordlist ({exc}); using built-in")
        return DEFAULT_WORDLIST

    async def _enumerate(self, ws, console, base, words) -> None:
        # Ask for a path that almost certainly doesn't exist. Whatever comes
        # back is this site's "nothing here" response — if a real word later
        # returns a 200 that looks just like it, it's a soft-404, not a hit.
        rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
        baseline = await fetch(f"{base}/{rnd}", allow_redirects=False)
        sem = asyncio.Semaphore(self.CONCURRENCY)

        async def probe(word: str) -> None:
            async with sem:
                url = f"{base}/{word}"
                r = await fetch(url, allow_redirects=False)
                if r is None or r.status not in INTERESTING:
                    return
                if (r.status == 200 and baseline and baseline.status == 200
                        and self._similar(r.text, baseline.text) >= 0.9):
                    return  # wildcard / soft-404
                ws.add_endpoint(url, "GET", r.status, server=r.headers.get("server", ""))
                console.good(f"{r.status}  {url}")
                if r.status in (200, 401, 403) and any(s in word.lower() for s in SENSITIVE):
                    sev = Severity.HIGH if r.status == 200 else Severity.MEDIUM
                    console.bad(f"sensitive  /{word}  ({r.status})")
                    ws.add_finding(
                        title=f"Sensitive path exposed: /{word}",
                        severity=sev,
                        phase=self.name,
                        target=url,
                        evidence=f"HTTP {r.status}",
                        description="A sensitive file or path is reachable and may leak secrets or source.",
                    )

        await asyncio.gather(*(probe(w) for w in words))

    @staticmethod
    def _similar(a, b) -> float:
        return difflib.SequenceMatcher(None, (a or "")[:2000], (b or "")[:2000]).ratio()
