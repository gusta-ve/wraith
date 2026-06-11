#!/usr/bin/env python3
"""Regenerate docs/demo.svg — a styled, dependency-free SVG of a wraith run.

The lines below mirror a real run against examples/vuln_app.py (every finding it
shows, wraith actually catches). The version is read live from the package, so
the demo never drifts. Run from the repo root:

    python3 docs/make_demo.py
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = re.search(r'__version__ = "(.+?)"',
                    (ROOT / "src/wraith/__init__.py").read_text()).group(1)

# Colours (GitHub dark).
BG, CHROME, STROKE = "#0d1117", "#161b22", "#21262d"
TEXT, DIM = "#c9d1d9", "#6e7681"
ACCENT = "#ff5b5b"
MARK = {"+": "#3fb950", "*": "#58a6ff", "!": "#d29922", "-": "#f85149"}
SEV = {"CRIT": "#ff3c3c", "HIGH": "#ff6e5f", "MED": "#e1a52d", "LOW": "#5aa0ff"}

# A curated run (resolve → injection) against the bundled lab.
LINES = [
    "  [*] target   127.0.0.1",
    "  [*] phases   resolve · tcp-scan · http-probe · security-headers · injection",
    "",
    "▸ resolve  resolve the target to IP addresses",
    "  [+] target is an IP: 127.0.0.1",
    "",
    "▸ tcp-scan  async TCP connect scan of common ports",
    "  [+] 127.0.0.1:8080 open  http",
    "",
    "▸ http-probe  status, Server header and title",
    "  [+] http://127.0.0.1:8080/ → 200  [BaseHTTP/0.6 Python/3.12.3]  shop",
    "",
    "▸ security-headers  security headers, cookie flags and CORS",
    "  [!] missing  Content-Security-Policy",
    "  [!] cookie flags missing  HttpOnly, SameSite",
    "",
    "▸ injection  XSS · SQLi (error/boolean/time) · cmd injection · SSTI · LFI · open redirect",
    "  [*] testing 10 parameter(s)",
    "",
    "── vulnerabilities ──",
    "  [CRIT] Command Injection in 'host'  /ping",
    "  [HIGH] SQL Injection (time-based blind) in 'token'  /lookup",
    "  [HIGH] SQL Injection (error-based) in 'id'  /product",
    "  [HIGH] SQL Injection (boolean blind) in 'id'  /items",
    "  [HIGH] Server-Side Template Injection in 'name'  /render",
    "  [HIGH] Path Traversal / Local File Inclusion in 'file'  /download",
    "  [HIGH] Reflected XSS in 'q'  /search",
    "  [MED ] Open Redirect in 'url'  /go",
    "",
    "  [*] a way in — deal the hand to hickok:  hickok hand findings.json",
]

PAD, CHARW, LINEH = 24, 8.55, 21
TOP = 156   # where the run output starts, below the header block


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def spans(line: str) -> list[tuple[str, str, bool]]:
    """Split a line into (text, colour, bold) segments by wraith's line shapes."""
    if line.startswith("▸ "):
        name, _, desc = line.partition("  ")
        return [(name, ACCENT, True), ("  " + desc, DIM, False)]
    if line.startswith("── "):
        return [(line, DIM, False)]
    m = re.match(r"(\s*)\[(CRIT|HIGH|MED|LOW)\s*\](.*)", line)
    if m:
        indent, sev, rest = m.groups()
        title, _, target = rest.rpartition("  ")
        out = [(f"{indent}[{sev}]", SEV[sev], True), (title or rest, TEXT, False)]
        if target:
            out.append(("  " + target, DIM, False))
        return out
    m = re.match(r"(\s*)\[([+*!-])\](.*)", line)
    if m:
        indent, k, rest = m.groups()
        return [(f"{indent}[{k}]", MARK[k], True), (rest, TEXT, False)]
    return [(line, TEXT, False)]


def render() -> str:
    width = int(PAD * 2 + max(len(s) for s in LINES) * CHARW)
    height = int(TOP + len(LINES) * LINEH + PAD)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="ui-monospace,SFMono-Regular,Menlo,'
        f'Consolas,monospace" font-size="15">',
        '<defs><linearGradient id="wm" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0" stop-color="#ff5b5b"/><stop offset="1" stop-color="#8a0014"/>'
        '</linearGradient></defs>',
        f'<rect width="{width}" height="{height}" rx="10" fill="{BG}" stroke="{STROKE}"/>',
        f'<rect width="{width}" height="34" rx="10" fill="{CHROME}"/>'
        f'<rect y="24" width="{width}" height="10" fill="{CHROME}"/>',
        '<circle cx="20" cy="17" r="6" fill="#ff5f56"/>',
        '<circle cx="40" cy="17" r="6" fill="#ffbd2e"/>',
        '<circle cx="60" cy="17" r="6" fill="#27c93f"/>',
        f'<text x="{width / 2}" y="22" fill="{DIM}" text-anchor="middle" font-size="13">'
        'wraith — run</text>',
        f'<text x="24" y="84" font-size="44" font-weight="800" letter-spacing="3" '
        f'fill="url(#wm)">wraith</text>',
        f'<text x="246" y="84" font-size="14" fill="{DIM}">v{VERSION}</text>',
        f'<text x="24" y="112" font-size="14" fill="{DIM}">offensive recon &amp; '
        'vulnerability detection pipeline</text>',
        f'<text x="24" y="132" font-size="13" fill="{DIM}">gusta-ve · '
        'github.com/gusta-ve/wraith</text>',
    ]
    y = TOP + 8
    for line in LINES:
        if line.strip():
            segs = "".join(
                f'<tspan fill="{c}"{" font-weight=\"700\"" if b else ""}>{esc(t)}</tspan>'
                for t, c, b in spans(line)
            )
            out.append(f'<text x="{PAD}" y="{y}" xml:space="preserve">{segs}</text>')
        y += LINEH
    out.append("</svg>")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    (ROOT / "docs/demo.svg").write_text(render(), encoding="utf-8")
    print(f"wrote docs/demo.svg  (v{VERSION}, {len(LINES)} lines)")
