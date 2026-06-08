"""The scheduler: resolves the phase DAG and runs ready phases concurrently."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class PhaseResult:
    name: str
    status: str           # "done" | "failed" | "skipped"
    duration: float = 0.0
    findings_added: int = 0
    error: str = ""


class Engine:
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
        sem = asyncio.Semaphore(self.concurrency)

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
                    progressed = True

            if running:
                completed, _ = await asyncio.wait(running.values(), return_when=asyncio.FIRST_COMPLETED)
                for task in completed:
                    name = task.get_name()
                    running.pop(name, None)
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

        return results

    async def _run_phase(self, phase, sem) -> PhaseResult:
        async with sem:
            self.console.phase(phase.name, phase.description)
            before = len(self.ws.findings)
            t0 = time.perf_counter()
            status, error = "done", ""
            try:
                await phase.run(self.ws, self.console)
            except Exception as exc:  # one phase failing must not kill the pipeline
                status, error = "failed", f"{type(exc).__name__}: {exc}"
                self.console.bad(f"[{phase.name}] {error}")
            duration = time.perf_counter() - t0
            added = len(self.ws.findings) - before
            try:
                self.ws.save()  # persist after every phase -> resumable runs
            except Exception as exc:
                self.console.warn(f"could not persist workspace: {exc}")
            return PhaseResult(phase.name, status, duration, added, error)
