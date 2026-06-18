"""Render a Workspace into a human-readable Markdown report."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path

_SEV_COLOR = {
    "Critical": "#ff4d4d",
    "High": "#ff7b72",
    "Medium": "#d29922",
    "Low": "#58a6ff",
    "Info": "#8b949e",
}


def _md_cell(value) -> str:
    """Escape a value for a Markdown table cell: an unescaped ``|`` would open a
    new column and a newline would break the row. Evidence and titles carry
    payloads (a `cmdi` probe like ``1| sleep 3`` has both), so this matters."""
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _md_row(*cells) -> str:
    return "| " + " | ".join(_md_cell(c) for c in cells) + " |"


def write_markdown(ws, results, path=None) -> Path:
    path = Path(path) if path else ws.workdir / "report.md"
    lines: list[str] = []

    lines.append(f"# wraith report — {ws.target}")
    lines.append("")
    lines.append(f"- Target: `{ws.target}`")
    lines.append(
        f"- Hosts: {len(ws.hosts)} · Services: {len(ws.services)} · "
        f"Endpoints: {len(ws.endpoints)} · Findings: {len(ws.findings)}"
    )
    lines.append("")

    if ws.services:
        lines += ["## Services", "", "| Host | Port | Service | Product |", "|------|------|---------|---------|"]
        for s in sorted(ws.services, key=lambda x: (x.host, x.port)):
            lines.append(_md_row(s.host, f"{s.port}/{s.proto}", s.name or "-", s.product or "-"))
        lines.append("")

    if ws.endpoints:
        lines += ["## Web endpoints", "", "| URL | Status | Server | Title |", "|-----|--------|--------|-------|"]
        for e in ws.endpoints:
            lines.append(_md_row(e.url, e.status, e.server or "-", (e.title or "-")[:60]))
        lines.append("")

    if ws.findings:
        lines += ["## Findings", "", "| Severity | Title | Target | Phase |", "|----------|-------|--------|-------|"]
        for f in sorted(ws.findings, key=lambda x: int(x.severity), reverse=True):
            lines.append(_md_row(f.severity.label, f.title, f.target or "-", f.phase or "-"))
        lines.append("")

    lines += ["## Pipeline", "", "| Phase | Status | Findings | Time (s) |", "|-------|--------|----------|----------|"]
    for r in results:
        lines.append(_md_row(r.name, r.status, r.findings_added, f"{r.duration:.2f}"))
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_json(ws, path=None) -> Path:
    path = Path(path) if path else ws.workdir / "findings.json"
    data = [
        {
            "title": f.title,
            "severity": f.severity.label,
            "phase": f.phase,
            "target": f.target,
            "evidence": f.evidence,
            "description": f.description,
            # structured handoff for hickok: the injectable point (param/method) and
            # the SQLi technique/dbms — so it reads fields instead of string-parsing
            # the title, and runs the matching oracle instead of brute-forcing all.
            "param": f.meta.get("param", ""),
            "method": f.meta.get("method", ""),
            "technique": f.meta.get("technique", ""),
            "dbms": f.meta.get("dbms", ""),
        }
        for f in sorted(ws.findings, key=lambda x: int(x.severity), reverse=True)
    ]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def write_html(ws, results, path=None) -> Path:
    path = Path(path) if path else ws.workdir / "report.html"
    e = html.escape

    def table(headers, rows):
        head = "".join(f"<th>{e(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    sections = []

    if ws.findings:
        rows = []
        for f in sorted(ws.findings, key=lambda x: int(x.severity), reverse=True):
            color = _SEV_COLOR.get(f.severity.label, "#8b949e")
            badge = f'<span class="sev" style="background:{color}">{e(f.severity.label)}</span>'
            rows.append([badge, e(f.title), e(f.target or "-"), e(f.evidence or "-"), e(f.phase or "-")])
        sections.append("<h2>Findings</h2>" + table(["Severity", "Title", "Target", "Evidence", "Phase"], rows))

    if ws.services:
        rows = [[e(s.host), f"{s.port}/{s.proto}", e(s.name or '-'), e(s.product or '-')]
                for s in sorted(ws.services, key=lambda x: (x.host, x.port))]
        sections.append("<h2>Services</h2>" + table(["Host", "Port", "Service", "Product"], rows))

    if ws.endpoints:
        rows = []
        for ep in ws.endpoints:
            tech = ", ".join(ep.tech) if ep.tech else "-"
            rows.append([f'<a href="{e(ep.url)}">{e(ep.url)}</a>', str(ep.status),
                         e(ep.server or '-'), e((ep.title or '-')[:60]), e(tech)])
        sections.append("<h2>Web endpoints</h2>" + table(["URL", "Status", "Server", "Title", "Tech"], rows))

    rows = [[e(r.name), e(r.status), str(r.findings_added), f"{r.duration:.2f}"] for r in results]
    sections.append("<h2>Pipeline</h2>" + table(["Phase", "Status", "Findings", "Time (s)"], rows))

    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wraith — {e(ws.target)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0a0a0a; color:#e6edf3; font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; margin:0; padding:2.5rem; }}
  .wrap {{ max-width:1100px; margin:0 auto; }}
  h1 {{ font-size:1.4rem; letter-spacing:.06em; margin:0 0 .25rem; }}
  h1 span {{ color:#8b949e; font-weight:400; }}
  h2 {{ font-size:1rem; text-transform:uppercase; letter-spacing:.08em; color:#8b949e;
        border-bottom:1px solid #21262d; padding-bottom:.35rem; margin:2rem 0 .75rem; }}
  .meta {{ color:#8b949e; margin-bottom:.5rem; }}
  .counts span {{ display:inline-block; margin-right:1.25rem; }}
  .counts b {{ color:#e6edf3; }}
  table {{ width:100%; border-collapse:collapse; margin-top:.25rem; }}
  th,td {{ text-align:left; padding:.5rem .6rem; border-bottom:1px solid #21262d; vertical-align:top;
           word-break:break-word; }}
  th {{ color:#8b949e; font-weight:600; text-transform:uppercase; font-size:.72rem; letter-spacing:.06em; }}
  tr:hover td {{ background:#0f1115; }}
  a {{ color:#58a6ff; text-decoration:none; }}
  .sev {{ display:inline-block; min-width:62px; text-align:center; padding:.1rem .5rem; border-radius:3px;
          color:#0a0a0a; font-weight:700; font-size:.72rem; }}
  footer {{ color:#30363d; margin-top:2.5rem; font-size:.75rem; }}
</style></head>
<body><div class="wrap">
  <h1>wraith <span>// {e(ws.target)}</span></h1>
  <div class="meta">offensive recon &amp; exploitation pipeline</div>
  <div class="counts">
    <span>hosts <b>{len(ws.hosts)}</b></span>
    <span>services <b>{len(ws.services)}</b></span>
    <span>endpoints <b>{len(ws.endpoints)}</b></span>
    <span>findings <b>{len(ws.findings)}</b></span>
  </div>
  {''.join(sections)}
  <footer>generated {generated} · wraith</footer>
</div></body></html>"""
    path.write_text(doc, encoding="utf-8")
    return path
