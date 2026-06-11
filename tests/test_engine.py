import asyncio

from wraith.core.console import Console
from wraith.core.context import Workspace
from wraith.core.engine import Engine


class FakePhase:
    def __init__(self, name, requires=(), fail=False, finding=False):
        self.name = name
        self.requires = frozenset(requires)
        self.description = ""
        self.fail = fail
        self.finding = finding

    async def run(self, ws, console):
        ws.meta.setdefault("order", []).append(self.name)
        if self.finding:
            ws.add_finding("x", 0, phase=self.name)
        if self.fail:
            raise RuntimeError("boom")


def _run(phases, tmp_path):
    ws = Workspace.create("t", base_dir=str(tmp_path))
    engine = Engine(ws, phases, Console(), concurrency=4)
    results = {r.name: r for r in asyncio.run(engine.run())}
    return ws, results


def test_runs_in_dependency_order(tmp_path):
    ws, res = _run([FakePhase("b", requires=("a",)), FakePhase("a")], tmp_path)
    assert res["a"].status == "done"
    assert res["b"].status == "done"
    assert ws.meta["order"] == ["a", "b"]


def test_dependency_failure_skips_dependent(tmp_path):
    _, res = _run([FakePhase("a", fail=True), FakePhase("b", requires=("a",))], tmp_path)
    assert res["a"].status == "failed"
    assert res["b"].status == "skipped"


def test_missing_dependency_is_skipped(tmp_path):
    _, res = _run([FakePhase("b", requires=("missing",))], tmp_path)
    assert res["b"].status == "skipped"


def test_findings_are_counted(tmp_path):
    _, res = _run([FakePhase("a", finding=True)], tmp_path)
    assert res["a"].findings_added == 1


def test_heartbeat_reassures_when_a_phase_is_slow(tmp_path, capsys):
    class SlowPhase(FakePhase):
        async def run(self, ws, console):
            await asyncio.sleep(0.3)

    ws = Workspace.create("t", base_dir=str(tmp_path))
    engine = Engine(ws, [SlowPhase("slow")], Console(banner=False), concurrency=2)
    engine.HEARTBEAT = 0.1          # fire well before the phase finishes
    asyncio.run(engine.run())
    out = capsys.readouterr().out
    assert "still working" in out and "slow" in out
