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

# Subcommands. Anything else on the command line is treated as a target for the
# default `run` command, so `wraith example.com` works without typing `run`.
_COMMANDS = {"run", "phases", "shell", "login", "aces"}

EXAMPLES = """\
examples:
  wraith example.com                     full scan — `run` is the default command
  wraith example.com -p tcp-scan,http-probe   only these phases
  wraith example.com -s sessions.json    add Broken Access Control / IDOR
  wraith example.com -x high             exit 2 if a High+ finding turns up
  wraith example.com --showdown          reveal the findings at the end
  wraith login http://host/login -u alice -p secret -o sessions.json
  wraith shell -l 9001                   catch a reverse shell

run `wraith phases` to see the pipeline; phases run concurrently by dependency.
"""


class _Help(argparse.RawDescriptionHelpFormatter):
    """Keep the examples block verbatim and give options room to breathe."""

    def __init__(self, prog):
        super().__init__(prog, max_help_position=30, width=86)


def _with_default_command(argv):
    """Insert `run` when the first non-option token isn't a known subcommand,
    so the common case (`wraith TARGET ...`) needs no subcommand at all."""
    out = list(argv)
    i = 0
    while i < len(out):
        tok = out[i]
        if tok in ("-h", "--help", "--version"):
            return out                       # let argparse handle these as-is
        if tok == "--theme":                 # the one global option that takes a value
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        if tok not in _COMMANDS:             # first bare word is a target -> default to run
            out.insert(i, "run")
        return out
    return out


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
    p = argparse.ArgumentParser(
        prog="wraith",
        description="Offensive recon & exploitation pipeline.  Run is the default: `wraith TARGET`.",
        epilog=EXAMPLES,
        formatter_class=_Help,
    )
    p.add_argument("--version", action="version", version=f"wraith {__version__}")
    p.add_argument("--theme", metavar="NAME", choices=list(THEMES),
                   help="colour theme: " + " | ".join(THEMES) + " (default: crimson)")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--no-banner", action="store_true", help="suppress the ASCII banner")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    run = sub.add_parser("run", help="scan a target (default command)", epilog=EXAMPLES,
                         formatter_class=_Help, description="Run the phase pipeline against a target.")
    run.add_argument("target", help="hostname, IP or URL")
    run.add_argument("-p", "--phases", metavar="LIST", help="comma-separated subset of phases (default: all)")
    run.add_argument("-s", "--sessions", metavar="FILE", help="sessions JSON — enables access-control / IDOR")
    run.add_argument("-w", "--wordlist", metavar="FILE", help="wordlist for content-discovery")
    run.add_argument("-t", "--templates", metavar="DIR", help="extra template-checks directory")
    run.add_argument("-x", "--fail-on", metavar="SEV", choices=list(_SEVERITY_BY_NAME),
                     help="exit 2 on a finding at/above SEV (info|low|medium|high|critical)")
    run.add_argument("--showdown", action="store_true", help="reveal the wraith and its hand at the end")
    run.add_argument("-c", "--concurrency", metavar="N", type=int, default=8,
                     help="max phases running in parallel (default: 8)")
    run.add_argument("--workdir", metavar="DIR", default="wraith-runs", help="output directory (default: wraith-runs)")
    run.set_defaults(func=cmd_run)

    ph = sub.add_parser("phases", help="list available phases", formatter_class=_Help)
    ph.set_defaults(func=cmd_phases)

    sh = sub.add_parser("shell", help="reverse-shell handler / post-exploitation console", formatter_class=_Help)
    sh.add_argument("-l", "--listen", metavar="PORTS", default="9001",
                    help="comma-separated ports to listen on (default: 9001)")
    sh.add_argument("--lhost", metavar="IP", help="LHOST embedded in generated payloads (auto-detected)")
    sh.set_defaults(func=cmd_shell)

    lg = sub.add_parser("login", help="grab a session from a form login -> sessions.json", formatter_class=_Help)
    lg.add_argument("url", help="login form URL (GET to seed cookies, POST to submit)")
    lg.add_argument("-u", "--username", required=True)
    lg.add_argument("-p", "--password", required=True)
    lg.add_argument("-o", "--output", metavar="FILE", help="write the sessions.json here (default: stdout)")
    lg.add_argument("--user-field", metavar="NAME", default="username", help="username form field name")
    lg.add_argument("--pass-field", metavar="NAME", default="password", help="password form field name")
    lg.add_argument("--data", metavar="K=V", action="append", help="extra form field (repeatable)")
    lg.add_argument("--name", metavar="NAME", default="user", help="session name for the output")
    lg.add_argument("--role", metavar="ROLE", default="low", help="session role (none/low/med/high)")
    lg.set_defaults(func=cmd_login)

    egg = sub.add_parser("aces")  # easter egg: no help= keeps it out of the listing
    egg.set_defaults(func=cmd_aces)

    return p


def main(argv=None) -> None:
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    if not argv:                         # bare `wraith` -> banner + help, not an error
        Console().banner()
        parser.print_help()
        return
    args = parser.parse_args(_with_default_command(argv))
    if not hasattr(args, "func"):        # options but no command
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
