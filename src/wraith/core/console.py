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
import time
from pathlib import Path

from wraith import __version__

_ART_DIR = Path(__file__).resolve().parent.parent / "art"
_RAMP = " .:-=+*#%@"

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
    "██     ██ ██████   █████  ██ ████████ ██   ██",
    "██     ██ ██   ██ ██   ██ ██    ██    ██   ██",
    "██  █  ██ ██████  ███████ ██    ██    ███████",
    "██ ███ ██ ██   ██ ██   ██ ██    ██    ██   ██",
    " ███ ███  ██   ██ ██   ██ ██    ██    ██   ██",
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

    def __init__(self, theme=None, color=None, banner=True, verbose=0):
        name = theme or os.environ.get("WRAITH_THEME") or DEFAULT_THEME
        self.theme = THEMES.get(name, THEMES[DEFAULT_THEME])
        self.color = _supports_color(color)
        self.show_banner = banner
        # -v level: 1 progress · 2 attack detail (payloads & requests) · 3 + responses
        self.verbose = int(verbose or 0)
        self.showdown = None  # a Showdown (see core/showdown.py) when the mode is on, else None
        self._spinning = False  # a working-spinner line is currently drawn (TTY)

    # All printing goes through here so subclasses can buffer it.
    def _emit(self, text: str = "") -> None:
        if self._spinning:            # wipe the spinner line before real output lands
            sys.stdout.write("\r\033[K")
            self._spinning = False
        print(text, flush=True)

    def spinner(self, frame: str, label: str) -> None:
        """Draw one frame of a 'still working' spinner — a single rewritten line,
        TTY only, auto-cleared by _emit before any real output. No newline."""
        if not sys.stdout.isatty():
            return
        sys.stdout.write("\r\033[K" + self._accent(frame) + " " + self._c(DIM, label))
        sys.stdout.flush()
        self._spinning = True

    def spin_clear(self) -> None:
        if self._spinning:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
            self._spinning = False

    def flush(self) -> None:
        """No-op on the live console; BufferedConsole overrides it to replay.
        Lets the engine treat a live (verbose) console like a buffered one."""

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def _accent(self, text: str) -> str:
        return self._c(_fg(self.theme["accent"]), text)

    def banner(self) -> None:
        if not self.show_banner:
            return
        c0, c1 = self.theme["grad"]
        self._emit()
        for i, line in enumerate(WORDMARK):
            shade = _lerp(c0, c1, i / (len(WORDMARK) - 1))
            self._emit("  " + ((BOLD + _fg(shade) + line + RESET) if self.color else line))
        self._emit()
        self._emit("  " + self._accent("» ")
                   + self._c(DIM, "offensive recon & vulnerability detection pipeline")
                   + "   " + self._c(DIM, f"v{__version__}"))
        self._emit("  " + self._c(DIM, "gusta-ve · github.com/gusta-ve/wraith · authorized use only"))
        if self.showdown:
            self._emit("  " + self._accent("◆ ") + self._c(BOLD, "showdown mode")
                       + self._c(DIM, " — the wraith plays the catch out"))
        self._emit()

    def _reaper(self) -> None:
        """Render the hooded-wraith line-art with a pale-blue -> bright-white glow.

        On a real terminal the lines are drawn one at a time, so the spectre
        appears to descend into view. Piped or non-interactive output (logs, CI,
        tests) gets the whole thing at once — no artificial delay.
        """
        try:
            art = (_ART_DIR / "wraith.txt").read_text(encoding="utf-8").rstrip("\n").split("\n")
        except OSError:
            return
        live = self.color and sys.stdout.isatty()
        lo, hi = (150, 175, 215), (240, 245, 255)  # pale blue -> bright white
        for line in art:
            if not self.color:
                self._emit("  " + line)
                continue
            out, run, idx = "  ", "", -1
            for ch in line:
                i = _RAMP.find(ch)
                if i < 0:
                    i = 0
                if i != idx:
                    out += self._tint(run, idx, lo, hi)
                    run, idx = "", i
                run += ch
            out += self._tint(run, idx, lo, hi)
            self._emit(out)
            if live:
                sys.stdout.flush()
                time.sleep(0.03)  # the descent

    def _reveal(self, hand: str) -> None:
        """The wraith's line-art + the showdown phrase, with whatever it was holding."""
        self._emit()
        self._reaper()
        self._emit()
        self._emit("                 the wraith reveals its hand —  " + hand)
        self._emit()
        self._emit("        " + self._c(DIM, "you never saw it coming — the wraith was already holding aces."))
        self._emit()

    def aces(self) -> None:
        """The reveal — the spectre laying down the two black aces.

        The aces are deliberately the black pair (spades & clubs): half of a
        dead man's hand, left unspoken. Used on demand (the `wraith aces`
        easter egg) and as the end-of-run showdown when wraith catches a
        vulnerability; the findings it caught are listed right after.
        """
        white = _fg((235, 235, 235))     # the black aces — spades & clubs
        self._reveal(self._c(BOLD + white, "A♠") + "  " + self._c(BOLD + white, "A♣"))

    @staticmethod
    def _tint(run, idx, lo, hi) -> str:
        if not run:
            return ""
        if idx <= 0:
            return run
        bold = BOLD if idx >= 6 else ""
        return bold + _fg(_lerp(lo, hi, (idx - 1) / 8)) + run + RESET

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

    def trace(self, msg, level: int = 1) -> None:
        """Verbose play-by-play. Emits only when -v is at or above `level`
        (1 progress · 2 attack detail · 3 raw HTTP)."""
        if self.verbose >= level:
            self._emit(self._c(DIM, "      · ") + str(msg))

    def finding(self, severity_label: str, msg) -> None:
        if self.showdown is not None:        # showdown mode dresses each catch up
            self.showdown.live_finding(self, severity_label, str(msg))
            return
        rgb = SEVERITY_RGB.get(severity_label, (150, 150, 150))
        abbr = self._ABBR.get(severity_label, severity_label.upper()[:4])
        tag = f"[{abbr:<4}]"
        self._emit("  " + self._c(_fg(rgb) + BOLD, tag) + " " + str(msg))

    _SEV_ORDER = ("Critical", "High", "Medium", "Low", "Info")

    def findings_report(self, findings) -> None:
        """Final, at-a-glance list of what's actually exploitable — worst first.

        Only real issues (Low and up); Info noise like a server banner stays in
        the files, not on screen. Colour does the heavy lifting, no ASCII boxes.
        """
        rank = {label: i for i, label in enumerate(self._SEV_ORDER)}
        vulns = sorted(
            (f for f in findings if rank.get(f.severity.label, 99) <= rank["Low"]),
            key=lambda f: (rank.get(f.severity.label, 99), f.severity.label),
        )
        self.rule("vulnerabilities")
        if not vulns:
            self._emit("  " + self._c(DIM, "no vulnerabilities surfaced"))
            return
        seen = set()
        for f in vulns:
            # The same issue can be logged more than once (e.g. one BAC finding
            # per bypassing session). Collapse it here; the per-session detail
            # still lives in the saved reports.
            key = (f.severity.label, f.title, f.target)
            if key in seen:
                continue
            seen.add(key)
            rgb = SEVERITY_RGB.get(f.severity.label, (150, 150, 150))
            abbr = self._ABBR.get(f.severity.label, f.severity.label.upper()[:4])
            tag = self._c(_fg(rgb) + BOLD, f"[{abbr:<4}]")
            target = self._c(DIM, f"  {f.target}") if f.target else ""
            self._emit(f"  {tag} {self._c(BOLD, f.title)}{target}")

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
        self.verbose = parent.verbose
        self.showdown = parent.showdown   # so per-phase findings get the live treatment
        self._spinning = False
        self._parent = parent
        self._lines: list[str] = []

    def _emit(self, text: str = "") -> None:
        self._lines.append(text)

    def flush(self) -> None:
        for line in self._lines:
            self._parent._emit(line)
        self._lines.clear()
