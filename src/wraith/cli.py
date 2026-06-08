"""Command-line entrypoint for wraith."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import wraith.phases  # noqa: F401  (importing populates PHASE_REGISTRY)
from wraith.core import report
from wraith.core.console import Console
from wraith.core.context import Workspace
from wraith.core.engine import Engine
from wraith.core.phase import PHASE_REGISTRY


def _select(names):
    if not names:
        return [cls() for cls in PHASE_REGISTRY.values()]
    chosen = []
    for n in names:
        cls = PHASE_REGISTRY.get(n)
        if not cls:
            raise SystemExit(f"unknown phase: {n} (see `wraith phases`)")
        chosen.append(cls())
    return chosen


def cmd_phases(args) -> None:
    c = Console()
    c.banner()
    for name, cls in PHASE_REGISTRY.items():
        deps = ", ".join(sorted(cls.requires)) or "—"
        c.plain(f"  {name:<14} requires: {deps}")
        if cls.description:
            c.plain(f"  {'':<14} {cls.description}")
    c.plain("")


def _load_sessions(ws, path, console) -> None:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("base_url"):
        ws.meta["base_url"] = data["base_url"]
    if data.get("seeds"):
        ws.meta["seeds"] = data["seeds"]
    for s in data.get("sessions", []):
        ws.add_session(
            name=s["name"],
            role=s.get("role", "low"),
            headers=s.get("headers", {}),
            cookies=s.get("cookies", {}),
        )
    console.info(f"loaded {len(ws.sessions)} session(s) from {path}")


def cmd_run(args) -> None:
    c = Console()
    c.banner()

    phases = _select(args.phases.split(",") if args.phases else None)
    ws = Workspace.create(args.target, base_dir=args.workdir)
    if args.sessions:
        _load_sessions(ws, args.sessions, c)
    if args.wordlist:
        ws.meta["wordlist"] = args.wordlist
    if args.templates:
        ws.meta["templates"] = args.templates
    c.info(f"target   {ws.target}")
    c.info(f"workdir  {ws.workdir}")
    c.info(f"phases   {', '.join(p.name for p in phases)}")

    engine = Engine(ws, phases, c, concurrency=args.concurrency)
    results = asyncio.run(engine.run())

    report_md = report.write_markdown(ws, results)
    report_html = report.write_html(ws, results)
    ws.save()

    c.rule("summary")
    c.good(
        f"hosts {len(ws.hosts)} · services {len(ws.services)} · "
        f"endpoints {len(ws.endpoints)} · findings {len(ws.findings)}"
    )
    c.info(f"workspace  {ws.workdir / 'workspace.json'}")
    c.info(f"report     {report_md}")
    c.info(f"report     {report_html}")


def cmd_shell(args) -> None:
    from wraith.shell import payloads
    from wraith.shell.handler import ShellServer

    c = Console()
    c.banner()
    try:
        ports = [int(p) for p in args.listen.split(",")]
    except ValueError:
        raise SystemExit("--listen expects comma-separated port numbers")
    lhost = args.lhost or payloads.guess_lhost()
    server = ShellServer(ports, lhost, c)
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wraith", description="Offensive recon & exploitation pipeline.")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the pipeline against a target")
    run.add_argument("target", help="hostname or IP")
    run.add_argument("--phases", help="comma-separated subset of phases to run")
    run.add_argument("--concurrency", type=int, default=8, help="max phases running in parallel")
    run.add_argument("--sessions", help="JSON file with sessions/base_url/seeds (for access-control)")
    run.add_argument("--wordlist", help="path to a wordlist for content-discovery")
    run.add_argument("--templates", help="extra directory of template-checks templates")
    run.add_argument("--workdir", default="wraith-runs", help="base directory for run output")
    run.set_defaults(func=cmd_run)

    ph = sub.add_parser("phases", help="list available phases")
    ph.set_defaults(func=cmd_phases)

    sh = sub.add_parser("shell", help="reverse-shell handler / post-exploitation console")
    sh.add_argument("-l", "--listen", default="9001", help="comma-separated ports to listen on")
    sh.add_argument("--lhost", help="local host embedded in generated payloads (auto-detected)")
    sh.set_defaults(func=cmd_shell)

    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
