"""Web — declarative vulnerability templates (a lightweight matcher engine).

A template is a JSON (or YAML, if pyyaml is installed) document describing one or
more requests and the matchers that decide whether the response indicates a
vulnerability/exposure. Built-in templates ship under ``wraith/templates`` and
extra directories can be added with ``--templates``.

Matcher types: ``status``, ``word``, ``regex``, ``header`` — combined per request
with ``matchers-condition`` (and/or).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from wraith.core.http import fetch
from wraith.core.models import Severity
from wraith.core.phase import Phase, register

BUILTIN_DIR = Path(__file__).resolve().parent.parent / "templates"

_SEV = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


def _headers_text(resp) -> str:
    return "\n".join(f"{k}: {v}" for k, v in resp.headers.items())


def _part_text(resp, part: str) -> str:
    if part == "header":
        return _headers_text(resp)
    if part == "all":
        return resp.text + "\n" + _headers_text(resp)
    return resp.text


def match_one(matcher: dict, resp) -> bool:
    kind = matcher.get("type")
    if kind == "status":
        return resp.status in matcher.get("status", [])

    if kind == "header":
        key = matcher.get("key", "").lower()
        return matcher.get("value", "").lower() in resp.headers.get(key, "").lower()

    text = _part_text(resp, matcher.get("part", "body"))
    condition = matcher.get("condition", "or")

    if kind == "word":
        words = matcher.get("words", [])
        hits = [w for w in words if w.lower() in text.lower()]
        return len(hits) == len(words) if condition == "and" else bool(hits)

    if kind == "regex":
        patterns = matcher.get("regex", [])
        hits = [p for p in patterns if re.search(p, text, re.I)]
        return len(hits) == len(patterns) if condition == "and" else bool(hits)

    return False


def evaluate(matchers: list, condition: str, resp) -> bool:
    if not matchers:
        return False
    results = [match_one(m, resp) for m in matchers]
    return all(results) if condition == "and" else any(results)


def load_templates(directory) -> list:
    out: list = []
    path = Path(directory)
    if not path.is_dir():
        return out
    for f in sorted(path.glob("*.json")):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    try:
        import yaml  # optional
        for pattern in ("*.yaml", "*.yml"):
            for f in sorted(path.glob(pattern)):
                try:
                    out.append(yaml.safe_load(f.read_text(encoding="utf-8")))
                except Exception:
                    pass
    except ImportError:
        pass
    return out


@register
class TemplateChecksPhase(Phase):
    name = "template-checks"
    requires = frozenset({"http-probe"})
    description = "Run declarative vulnerability templates against discovered endpoints."

    async def run(self, ws, console) -> None:
        templates = load_templates(BUILTIN_DIR)
        extra = ws.meta.get("templates")
        if extra:
            templates += load_templates(extra)
        if not templates:
            console.warn("no templates loaded")
            return
        bases = self._bases(ws)
        if not bases:
            console.warn("no HTTP endpoints to test")
            return
        console.info(f"loaded {len(templates)} template(s)")
        for base in bases:
            for tpl in templates:
                await self._run_template(ws, console, base, tpl)

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

    async def _run_template(self, ws, console, base, tpl) -> None:
        for req in tpl.get("requests", []):
            url = base.rstrip("/") + req.get("path", "/")
            r = await fetch(url, method=req.get("method", "GET"), allow_redirects=False)
            if r is None:
                continue
            if evaluate(req.get("matchers", []), req.get("matchers-condition", "and"), r):
                info = tpl.get("info", {})
                sev = _SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
                name = info.get("name", tpl.get("id", "template"))
                console.finding(sev.label, f"{name}  → {url}")
                ws.add_finding(
                    title=name,
                    severity=sev,
                    phase=self.name,
                    target=url,
                    evidence=f"template '{tpl.get('id')}' matched",
                    description=info.get("description", ""),
                )
                return  # one match per template per host
