"""Command-line entrypoint for wraith."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import wraith.phases  # noqa: F401  (importing populates PHASE_REGISTRY)
from wraith import __version__
from wraith.core import report
from wraith.core.console import THEMES, Console
from wraith.core.context import Workspace
from wraith.core.engine import Engine
from wraith.core.models import Severity
from wraith.core.phase import PHASE_REGISTRY

_SEVERITY_BY_NAME = {s.label.lower(): s for s in Severity}


def _console(args) -> Console:
    return Console(
        theme=getattr(args, "theme", None),
        color=False if getattr(args, "no_color", False) else None,
        banner=not getattr(args, "no_banner", False),
    )


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
    c = _console(args)
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
    c = _console(args)
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
    report_json = report.write_json(ws)
    ws.save()

    c.rule("summary")
    c.good(
        f"hosts {len(ws.hosts)} · services {len(ws.services)} · "
        f"endpoints {len(ws.endpoints)} · findings {len(ws.findings)}"
    )
    counts = {}
    for f in ws.findings:
        counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
    c.severity_summary(counts)
    c.info(f"workspace  {ws.workdir / 'workspace.json'}")
    c.info(f"report     {report_md}")
    c.info(f"report     {report_html}")
    c.info(f"findings   {report_json}")

    if args.showdown:
        c.showdown(len(ws.findings))

    if args.fail_on:
        threshold = _SEVERITY_BY_NAME[args.fail_on]
        worst = max((f.severity for f in ws.findings), default=Severity.INFO)
        if ws.findings and worst >= threshold:
            c.warn(f"findings at/above '{args.fail_on}' (worst: {worst.label}) — exit 2")
            sys.exit(2)


def cmd_login(args) -> None:
    """Authenticate against a form login and emit a sessions.json snippet."""
    import http.cookiejar
    import ssl
    import urllib.request

    c = _console(args)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(jar),
    )

    fields = {args.user_field: args.username, args.pass_field: args.password}
    for pair in args.data or []:
        if "=" in pair:
            k, v = pair.split("=", 1)
            fields[k] = v
    body = "&".join(f"{k}={v}" for k, v in fields.items()).encode()

    try:
        opener.open(urllib.request.Request(args.url, headers={"User-Agent": "wraith/0.1"}), timeout=10)
        opener.open(urllib.request.Request(args.url, data=body, headers={"User-Agent": "wraith/0.1"}), timeout=10)
    except Exception as exc:
        raise SystemExit(f"login request failed: {exc}")

    cookies = {ck.name: ck.value for ck in jar}
    if not cookies:
        c.warn("no cookies captured — check the field names/URL")

    parts = urlsplit(args.url)
    snippet = {
        "base_url": f"{parts.scheme}://{parts.netloc}",
        "seeds": ["/"],
        "sessions": [{"name": args.name, "role": args.role, "cookies": cookies}],
    }
    text = json.dumps(snippet, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        c.good(f"captured {len(cookies)} cookie(s) -> {args.output}")
    else:
        print(text)


def cmd_aces(args) -> None:
    _console(args).aces()


def cmd_shell(args) -> None:
    from wraith.shell import payloads
    from wraith.shell.handler import ShellServer

    c = _console(args)
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
    p.add_argument("--version", action="version", version=f"wraith {__version__}")
    p.add_argument("--theme", choices=list(THEMES), help="colour theme (default: crimson)")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--no-banner", action="store_true", help="suppress the ASCII banner")
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    run = sub.add_parser("run", help="run the pipeline against a target")
    run.add_argument("target", help="hostname or IP")
    run.add_argument("--phases", help="comma-separated subset of phases to run")
    run.add_argument("--concurrency", type=int, default=8, help="max phases running in parallel")
    run.add_argument("--sessions", help="JSON file with sessions/base_url/seeds (for access-control)")
    run.add_argument("--wordlist", help="path to a wordlist for content-discovery")
    run.add_argument("--templates", help="extra directory of template-checks templates")
    run.add_argument("--fail-on", choices=list(_SEVERITY_BY_NAME),
                     help="exit 2 if a finding at/above this severity is found")
    run.add_argument("--showdown", action="store_true",
                     help="reveal the wraith and the hand it was holding (your findings) at the end")
    run.add_argument("--workdir", default="wraith-runs", help="base directory for run output")
    run.set_defaults(func=cmd_run)

    ph = sub.add_parser("phases", help="list available phases")
    ph.set_defaults(func=cmd_phases)

    sh = sub.add_parser("shell", help="reverse-shell handler / post-exploitation console")
    sh.add_argument("-l", "--listen", default="9001", help="comma-separated ports to listen on")
    sh.add_argument("--lhost", help="local host embedded in generated payloads (auto-detected)")
    sh.set_defaults(func=cmd_shell)

    lg = sub.add_parser("login", help="authenticate to a form login and emit a sessions.json")
    lg.add_argument("url", help="login form URL (GET to seed cookies, POST to submit)")
    lg.add_argument("-u", "--username", required=True)
    lg.add_argument("-p", "--password", required=True)
    lg.add_argument("--user-field", default="username", help="username form field name")
    lg.add_argument("--pass-field", default="password", help="password form field name")
    lg.add_argument("--data", action="append", help="extra form field k=v (repeatable)")
    lg.add_argument("--name", default="user", help="session name for the output")
    lg.add_argument("--role", default="low", help="session role (none/low/med/high)")
    lg.add_argument("-o", "--output", help="write the sessions.json to this path")
    lg.set_defaults(func=cmd_login)

    egg = sub.add_parser("aces")  # easter egg: no help= keeps it out of the listing
    egg.set_defaults(func=cmd_aces)

    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
