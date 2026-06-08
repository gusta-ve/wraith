"""Render a Workspace into a human-readable Markdown report."""

from __future__ import annotations

from pathlib import Path


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
            lines.append(f"| {s.host} | {s.port}/{s.proto} | {s.name or '-'} | {s.product or '-'} |")
        lines.append("")

    if ws.endpoints:
        lines += ["## Web endpoints", "", "| URL | Status | Server | Title |", "|-----|--------|--------|-------|"]
        for e in ws.endpoints:
            lines.append(f"| {e.url} | {e.status} | {e.server or '-'} | {(e.title or '-')[:60]} |")
        lines.append("")

    if ws.findings:
        lines += ["## Findings", "", "| Severity | Title | Target | Phase |", "|----------|-------|--------|-------|"]
        for f in sorted(ws.findings, key=lambda x: int(x.severity), reverse=True):
            lines.append(f"| {f.severity.label} | {f.title} | {f.target or '-'} | {f.phase or '-'} |")
        lines.append("")

    lines += ["## Pipeline", "", "| Phase | Status | Findings | Time (s) |", "|-------|--------|----------|----------|"]
    for r in results:
        lines.append(f"| {r.name} | {r.status} | {r.findings_added} | {r.duration:.2f} |")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path
