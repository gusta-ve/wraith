#!/usr/bin/env python3
"""Generate docs/hero.svg — the name beside the hooded-spectre line-art.

Reads the same art the CLI draws (src/wraith/art/wraith.txt), so the repo banner
and the terminal reveal never drift. No block wordmark — just the name set clean
and the mascot. Run after changing the art:

    python3 docs/make_hero.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = (ROOT / "src/wraith/art/wraith.txt").read_text(encoding="utf-8").rstrip("\n").split("\n")

NAME = "wraith"
TAGLINE = "offensive recon & vulnerability detection pipeline"
SIG = "gusta-ve · you never saw it coming"

# ---- layout -----------------------------------------------------------------
# Tall card so the full mascot can be set big enough to stay crisp (a small
# font is what made the line-art fringe).
W, H = 1080, 560

NAME_X, NAME_FS = 50, 80            # the name, set large and clean (no figlet)
NAME_Y = H // 2 + 8

# the full mascot, right column, set large
ART_FS, ART_LH = 12.0, 12.6
ART_X = 1080 - round(max(len(l) for l in ART) * ART_FS * 0.6) - 36
ART_Y0 = (H - len(ART) * ART_LH) / 2 + ART_FS


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def main() -> None:
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="ui-monospace,Menlo,Consolas,monospace">',
        '<defs>'
        '<linearGradient id="g" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0" stop-color="#ff6a6a"/><stop offset="1" stop-color="#8a0012"/>'
        '</linearGradient>'
        '<linearGradient id="a" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0" stop-color="#e9eef5"/><stop offset="1" stop-color="#7f95b5"/>'
        '</linearGradient>'
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="12" fill="#0b0d10" stroke="#1c2128"/>',
    ]
    out.append(f'<text x="{NAME_X}" y="{NAME_Y}" font-size="{NAME_FS}" font-weight="700" '
               f'fill="url(#g)" letter-spacing="2">{esc(NAME)}</text>')
    out.append(f'<text x="{NAME_X + 4}" y="{NAME_Y + 34}" font-size="15" '
               f'fill="#8b949e">{esc(TAGLINE)}</text>')
    for i, line in enumerate(ART):
        y = round(ART_Y0 + i * ART_LH, 1)
        out.append(f'<text x="{ART_X}" y="{y}" font-size="{ART_FS}" fill="url(#a)" '
                   f'xml:space="preserve">{esc(line)}</text>')
    out.append(f'<text x="{NAME_X + 4}" y="{H - 26}" font-size="13" fill="#6e7681" '
               f'xml:space="preserve">{esc(SIG)}</text>')
    out.append('</svg>')
    dst = ROOT / "docs/hero.svg"
    dst.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {dst.relative_to(ROOT)}  ({len(ART)} art rows)")


if __name__ == "__main__":
    main()
