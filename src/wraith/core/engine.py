"""The scheduler: resolves the phase DAG and runs ready phases concurrently."""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass

from wraith.core.console import BufferedConsole

_SPINNER = "⣾⣽⣻⢿⡿⣟⣯⣷"   # a little block that turns while phases work


@dataclass
class PhaseResult:
    name: str
    status: str           # "done" | "failed" | "skipped"
    duration: float = 0.0
    findings_added: int = 0
    error: str = ""


class Engine:
    # If nothing finishes for this long, tell the user which phases are still
    # working — so a slow target never looks like a frozen run, at any verbosity.
    HEARTBEAT = 15.0

    def __init__(self, workspace, phases, console, concurrency: int = 8):
        self.ws = workspace
        self.console = console
        self.concurrency = max(1, concurrency)
        self.phases = {p.name: p for p in phases}

    async def run(self) -> list[PhaseResult]:
        selected = set(self.phases)
        done: set[str] = set()
        failed: set[str] = set()
        results: list[PhaseResult] = []
        pending = dict(self.phases)
        running: dict[str, asyncio.Task] = {}
        started: dict[str, float] = {}
        sem = asyncio.Semaphore(self.concurrency)

        # On a real terminal, animate a spinner so a slow phase never looks
        # frozen; piped/CI output falls back to a line every HEARTBEAT seconds.
        tty = sys.stdout.isatty()
        tick = 0.12 if tty else self.HEARTBEAT
        spin_i = 0
        last_beat = 0.0

        # A phase whose dependency is not part of this selection can never run.
        for name, phase in list(pending.items()):
            if not set(phase.requires) <= selected:
                pending.pop(name)
                failed.add(name)
                results.append(PhaseResult(name, "skipped", error="required phase not selected"))
                self.console.warn(f"skip {name}: required phase not selected")

        while pending or running:
            progressed = False
            for name, phase in list(pending.items()):
                req = set(phase.requires)
                if req & failed:
                    pending.pop(name)
                    failed.add(name)
                    results.append(PhaseResult(name, "skipped", error="dependency failed"))
                    self.console.warn(f"skip {name}: dependency failed")
                    progressed = True
                elif req <= done:
                    pending.pop(name)
                    running[name] = asyncio.create_task(self._run_phase(phase, sem), name=name)
                    started[name] = time.monotonic()
                    progressed = True

            if running:
                completed, _ = await asyncio.wait(
                    running.values(), timeout=tick, return_when=asyncio.FIRST_COMPLETED)
                if not completed:
                    # Nothing finished this tick — keep the user company.
                    now = time.monotonic()
                    names = sorted(running, key=lambda n: started[n])
                    if tty:
                        secs = int(now - min(started.values()))
                        self.console.spinner(_SPINNER[spin_i % len(_SPINNER)],
                                             f"working · {' · '.join(names)} · {secs}s")
                        spin_i += 1
                    elif now - last_beat >= self.HEARTBEAT:
                        busy = ", ".join(f"{n} ({int(now - started[n])}s)" for n in names)
                        self.console.info(f"still working — {busy}")
                        last_beat = now
                    continue
                self.console.spin_clear()
                for task in completed:
                    name = task.get_name()
                    running.pop(name, None)
                    started.pop(name, None)
                    result = task.result()
                    results.append(result)
                    (done if result.status == "done" else failed).add(name)
            elif pending and not progressed:
                # Nothing running and nothing schedulable -> dependency cycle.
                for name in list(pending):
                    pending.pop(name)
                    failed.add(name)
                    results.append(PhaseResult(name, "skipped", error="unmet dependencies (cycle?)"))
                    self.console.warn(f"skip {name}: unmet dependencies (cycle?)")
                break

        self.console.spin_clear()
        return results

    async def _run_phase(self, phase, sem) -> PhaseResult:
        async with sem:
            # Normally buffer a phase's output so concurrent phases don't
            # interleave, flushing it atomically when the phase finishes. But
            # under -v stream live, so a slow or stuck phase still narrates in
            # real time instead of hiding everything until it returns.
            buf = self.console if self.console.verbose else BufferedConsole(self.console)
            buf.phase(phase.name, phase.description)
            before = len(self.ws.findings)
            t0 = time.perf_counter()
            status, error = "done", ""
            try:
                await phase.run(self.ws, buf)
            except Exception as exc:  # one phase failing must not kill the pipeline
                status, error = "failed", f"{type(exc).__name__}: {exc}"
                buf.bad(f"[{phase.name}] {error}")
            duration = time.perf_counter() - t0
            added = len(self.ws.findings) - before
            try:
                self.ws.save()  # persist after every phase -> resumable runs
            except Exception as exc:
                buf.warn(f"could not persist workspace: {exc}")
            buf.flush()
            return PhaseResult(phase.name, status, duration, added, error)
