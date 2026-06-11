"""Showdown mode — everything wraith does on top of a plain run.

`wraith run` finds things and reports them. Turn the mode on with `wraith
showdown` and a run plays the catch out:

  * live catches   — each finding is called out with weight as it lands
  * the reveal     — the hooded spectre descends, holding its pocket aces
  * the kill-chain — how the wraith actually walked in, step by step
  * the receipts   — every finding with the proof behind it
  * the verdict    — the target's hand vs the wraith's, poker-style

The whole mode lives in this one file. To grow it, add a step to ``close()`` (or
a new method) — nothing else needs to change. The plain run path never imports
this module, so `wraith run` stays lean.

The console is the renderer (colours, the spectre art); Showdown decides *what*
to draw and *when*. ``live_finding`` takes the console that's printing because
during a scan that's a buffered one, per phase.
"""

from __future__ import annotations

from wraith.core.console import BOLD, DIM, SEVERITY_RGB, _fg
from wraith.core.models import Severity

# Worst first — used to sort and to read the target's "hand".
_ORDER = ("Critical", "High", "Medium", "Low", "Info")

# Phases in the order an attacker walks them, and how each reads in the story.
# Only phases whose findings are worth narrating appear here.
_CHAIN = [
    ("tech-detect", "fingerprinted the stack"),
    ("content-discovery", "dug up hidden paths"),
    ("vhost", "uncovered virtual hosts"),
    ("template-checks", "matched known exposures"),
    ("security-headers", "found the doors unlocked"),
    ("injection", "slipped past input handling"),
    ("access-control", "walked past authorization"),
]

# Map a finding's title to a short tag for the kill-chain summary.
_KINDS = [
    ("xss", "XSS"),
    ("sql", "SQLi"),
    ("idor", "IDOR"),
    ("access control", "BAC"),
    ("open redirect", "Open Redirect"),
    ("security header", "missing headers"),
    ("cors", "CORS"),
    ("cookie", "weak cookies"),
    ("sensitive", "exposed path"),
]


def _kinds(findings) -> list:
    """Short, deduplicated tags for a group of findings (for the chain line)."""
    out = []
    for f in findings:
        title = f.title.lower()
        tag = next((tag for key, tag in _KINDS if key in title), f.title)
        if tag not in out:
            out.append(tag)
    return out


class Showdown:
    """The showdown mode. Hand it the console; it lights the run up."""

    def __init__(self, console):
        self.c = console

    # ---- during the scan -------------------------------------------------
    def live_finding(self, console, severity_label: str, msg) -> None:
        """A single catch, announced with weight (replaces the quiet `[HIGH]`).

        Uses the console that's printing — during a phase that's a buffered one,
        so concurrent phases still don't interleave.
        """
        rgb = SEVERITY_RGB.get(severity_label, (150, 150, 150))
        bar = console._c(_fg(rgb) + BOLD, "┃")
        sev = console._c(_fg(rgb) + BOLD, f" {severity_label.upper():<8}")
        console._emit(f"  {bar}{sev}{msg}")

    # ---- the end of the run ---------------------------------------------
    def close(self, ws) -> None:
        """Play out the ending: reveal, kill-chain, receipts, verdict."""
        vulns = [f for f in ws.findings if f.severity >= Severity.LOW]
        if vulns and self.c.show_banner:
            self.c.aces()            # the spectre descends, holding its aces
        if vulns:
            self._kill_chain(vulns)
            self._receipts(vulns)
        self._verdict(ws.findings)   # always — even a clean table gets a call

    def _kill_chain(self, vulns) -> None:
        """Retell the catch as the path the wraith walked, in kill-chain order."""
        by_phase = {}
        for f in vulns:
            by_phase.setdefault(f.phase, []).append(f)
        steps = [(phase, story) for phase, story in _CHAIN if phase in by_phase]
        if not steps:
            return
        self.c.rule("how the wraith walked in")
        for i, (phase, story) in enumerate(steps, 1):
            tags = " · ".join(_kinds(by_phase[phase]))
            tail = self.c._c(DIM, f"  {tags}") if tags else ""
            self.c._emit(f"  {self.c._accent(f'{i}.')} {story:<28}{tail}")

    def _receipts(self, vulns) -> None:
        """Every vulnerability with the evidence behind it — the proof."""
        rank = {label: i for i, label in enumerate(_ORDER)}
        ordered = sorted(vulns, key=lambda f: rank.get(f.severity.label, 99))
        self.c.rule("vulnerabilities")
        seen = set()
        for f in ordered:
            key = (f.severity.label, f.title, f.target)   # collapse duplicates
            if key in seen:
                continue
            seen.add(key)
            rgb = SEVERITY_RGB.get(f.severity.label, (150, 150, 150))
            abbr = self.c._ABBR.get(f.severity.label, f.severity.label.upper()[:4])
            tag = self.c._c(_fg(rgb) + BOLD, f"[{abbr:<4}]")
            target = self.c._c(DIM, f"  {f.target}") if f.target else ""
            self.c._emit(f"  {tag} {self.c._c(BOLD, f.title)}{target}")
            if f.evidence:
                proof = f.evidence if len(f.evidence) <= 88 else f.evidence[:87] + "…"
                self.c._emit("       " + self.c._c(DIM, f"↳ {proof}"))

    def _verdict(self, findings) -> None:
        """The showdown call: the target's hand against the wraith's pocket aces."""
        counts = {}
        for f in findings:
            counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
        worst = max((f.severity for f in findings), default=Severity.INFO)

        white = _fg((235, 235, 235))     # the two black aces — half a dead man's hand
        aces = self.c._c(BOLD + white, "A♠") + " " + self.c._c(BOLD + white, "A♣")
        held = [f"{counts[label]} {label}" for label in ("Critical", "High", "Medium", "Low")
                if counts.get(label)]
        target_hand = " · ".join(held) if held else "a busted hand"

        self.c._emit()
        self.c.rule("showdown")
        self.c._emit(f"  {self.c._c(DIM, 'wraith')}   {aces}   {self.c._c(DIM, 'pocket aces')}")
        self.c._emit(f"  {self.c._c(DIM, 'target')}   {self.c._c(BOLD, target_hand)}")
        self.c._emit()
        self.c._emit("  " + self.c._c(BOLD, self._call(worst)))
        self.c._emit()

    @staticmethod
    def _call(worst) -> str:
        """The closing line, dealt by how badly the target was beaten."""
        if worst >= Severity.CRITICAL:
            return "the house was buried."
        if worst == Severity.HIGH:
            return "the house never had the cards."
        if worst == Severity.MEDIUM:
            return "the house was drawing dead."
        if worst == Severity.LOW:
            return "a short stack — the wraith still took it."
        return "an empty table — the wraith folds, this time."
