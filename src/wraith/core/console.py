"""Console output: ASCII banner, colour themes and severity-aware printing.

Dependency-free (ANSI / truecolor). Colour auto-enables on a TTY and honours
NO_COLOR; force it anywhere with WRAITH_COLOR=1. Pick a theme with --theme or
WRAITH_THEME (crimson | matrix | ice | amber | mono).

All output is routed through ``_emit`` so a phase's lines can be buffered and
flushed as one block (see BufferedConsole), keeping concurrent phases readable.
"""

from __future__ import annotations

import os
import sys

from wraith import __version__

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

THEMES = {
    "crimson": {"grad": ((255, 80, 80), (110, 0, 12)), "accent": (255, 85, 85)},
    "matrix":  {"grad": ((150, 255, 150), (0, 80, 25)), "accent": (70, 255, 130)},
    "ice":     {"grad": ((160, 215, 255), (20, 70, 150)), "accent": (115, 185, 255)},
    "amber":   {"grad": ((255, 205, 95), (150, 70, 0)), "accent": (255, 185, 70)},
    "mono":    {"grad": ((235, 235, 235), (120, 120, 120)), "accent": (220, 220, 220)},
}
DEFAULT_THEME = "crimson"

WORDMARK = [
    r"██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗",
    r"██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║",
    r"██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║",
    r"██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║",
    r"╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║",
    r" ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝",
]

SEVERITY_RGB = {
    "Critical": (255, 60, 60),
    "High": (255, 110, 95),
    "Medium": (225, 165, 45),
    "Low": (90, 160, 255),
    "Info": (150, 150, 150),
}


def _supports_color(force=None) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("WRAITH_COLOR") == "1":
        return True
    return sys.stdout.isatty()


def _fg(rgb) -> str:
    return f"\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"


def _lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


class Console:
    _ABBR = {"Critical": "CRIT", "High": "HIGH", "Medium": "MED", "Low": "LOW", "Info": "INFO"}

    def __init__(self, theme=None, color=None, banner=True):
        name = theme or os.environ.get("WRAITH_THEME") or DEFAULT_THEME
        self.theme = THEMES.get(name, THEMES[DEFAULT_THEME])
        self.color = _supports_color(color)
        self.show_banner = banner

    # All printing goes through here so subclasses can buffer it.
    def _emit(self, text: str = "") -> None:
        print(text)

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def _accent(self, text: str) -> str:
        return self._c(_fg(self.theme["accent"]), text)

    def banner(self) -> None:
        if not self.show_banner:
            return
        self._emit()
        c0, c1 = self.theme["grad"]
        for i, line in enumerate(WORDMARK):
            if self.color:
                shade = _lerp(c0, c1, i / (len(WORDMARK) - 1))
                self._emit("  " + BOLD + _fg(shade) + line + RESET)
            else:
                self._emit("  " + line)
        self._emit()
        self._emit("  " + self._accent("» ")
                   + self._c(DIM, "offensive recon & exploitation pipeline")
                   + "   " + self._c(DIM, f"v{__version__}"))
        self._emit("  " + self._c(DIM, "gusta-ve · github.com/gusta-ve/wraith · authorized use only"))
        self._emit()

    def rule(self, title: str = "") -> None:
        if title:
            self._emit(self._c(DIM, f"── {title} " + "─" * max(0, 52 - len(title))))
        else:
            self._emit(self._c(DIM, "─" * 56))

    def phase(self, name: str, description: str = "") -> None:
        self._emit()
        self._emit(self._accent("▸ ") + self._c(BOLD, name)
                   + (self._c(DIM, f"  {description}") if description else ""))

    def info(self, msg) -> None:
        self._emit(self._c("\033[36m", "  [*] ") + str(msg))

    def good(self, msg) -> None:
        self._emit(self._c("\033[32m", "  [+] ") + str(msg))

    def warn(self, msg) -> None:
        self._emit(self._c("\033[33m", "  [!] ") + str(msg))

    def bad(self, msg) -> None:
        self._emit(self._c("\033[31m", "  [-] ") + str(msg))

    def plain(self, msg: str = "") -> None:
        self._emit(msg)

    def finding(self, severity_label: str, msg) -> None:
        rgb = SEVERITY_RGB.get(severity_label, (150, 150, 150))
        abbr = self._ABBR.get(severity_label, severity_label.upper()[:4])
        tag = f"[{abbr:<4}]"
        self._emit("  " + self._c(_fg(rgb) + BOLD, tag) + " " + str(msg))

    def severity_summary(self, counts: dict) -> None:
        parts = []
        for label in ("Critical", "High", "Medium", "Low", "Info"):
            n = counts.get(label, 0)
            if n:
                parts.append(self._c(_fg(SEVERITY_RGB[label]) + BOLD, f"{label} {n}"))
        if parts:
            self._emit("  " + self._c(DIM, "findings  ") + "  ".join(parts))


class BufferedConsole(Console):
    """Captures a phase's output and replays it as one block on flush(), so
    phases running concurrently don't interleave their lines."""

    def __init__(self, parent: Console):
        self.theme = parent.theme
        self.color = parent.color
        self.show_banner = parent.show_banner
        self._parent = parent
        self._lines: list[str] = []

    def _emit(self, text: str = "") -> None:
        self._lines.append(text)

    def flush(self) -> None:
        for line in self._lines:
            self._parent._emit(line)
        self._lines.clear()
