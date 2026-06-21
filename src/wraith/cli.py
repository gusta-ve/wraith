"""Command-line entrypoint for wraith."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlsplit

import wraith.phases  # noqa: F401  (importing populates PHASE_REGISTRY)
from wraith import __version__
from wraith.core import report, search
from wraith.core.console import DIM, THEMES, Console
from wraith.core.context import Workspace, runs_dir
from wraith.core.engine import Engine
from wraith.core.models import Severity
from wraith.core.phase import PHASE_REGISTRY
from wraith.core.showdown import Showdown

_SEVERITY_BY_NAME = {s.label.lower(): s for s in Severity}

# Subcommands. Anything else on the command line is treated as a target for the
# default `run` command, so `wraith example.com` works without typing `run`.
_COMMANDS = {"run", "showdown", "phases", "login", "hand", "dork"}

# A lean tutorial for the bare command — the full help lives behind -h.
_QUICKSTART = [
    ("wraith target.com", "scan a target — the full pipeline"),
    ("wraith -u https://host:8443", "scan a URL (the port too)"),
    ("wraith phases", "list the phases"),
]


def _quickstart(c) -> None:
    """Banner + a few example commands (run `wraith -h` for the full help)."""
    c.banner()
    for cmd, desc in _QUICKSTART:
        c.plain("  " + c._accent(cmd.ljust(30)) + c._c(DIM, desc))
    c.plain("")
    c.plain("  " + c._c(DIM, "wraith -h  ·  full help, every command and option"))

EXAMPLES = """\
examples:
  wraith example.com                     full scan — `run` is the default command
  wraith -u https://example.com          same, target given with -u/--url
  wraith example.com -p tcp-scan,http-probe   only these phases
  wraith 127.0.0.1 -P web                 sweep HTTP/alt-HTTP ports (finds odd ones, e.g. 8666)
  wraith 127.0.0.1 -P 1-65535             full port scan — find a service on any port
  wraith example.com -s sessions.json    add Broken Access Control / IDOR
  wraith example.com -v                  narrate the attack: payloads, oracles, confirmations
  wraith example.com -x high             exit 2 if a High+ finding turns up
  wraith showdown                        toggle showdown mode (reveal on a find; sticks)
  wraith login http://host/login -u alice -p secret -o sessions.json

run `wraith phases` to see the pipeline; phases run concurrently by dependency.
landing a shell is hickok's job — wraith's companion: github.com/gusta-ve/hickok
"""

DORK_EXAMPLES = """\
examples:
  wraith dork "inurl:login"                  a raw dork
  wraith dork --params                       URLs with injectable params (SQLi/IDOR candidates)
  wraith dork --params --site target.com     the same, scoped to an authorized target
  wraith dork --files --max 50 -o urls.txt   exposed files, save the list

discovery only — `dork` lists URLs and never touches them; testing them is the
separate, deliberate `wraith <url>` step. Works with no setup (DuckDuckGo); for
scale, configure an API backend (env):
  WRAITH_SEARXNG_URL  ·  WRAITH_GOOGLE_API_KEY + WRAITH_GOOGLE_CX  ·  WRAITH_BRAVE_API_KEY
"""


class _Help(argparse.RawDescriptionHelpFormatter):
    """Keep the examples block verbatim and give options room to breathe."""

    def __init__(self, prog):
        super().__init__(prog, max_help_position=30, width=86)


_runs_dir = runs_dir   # the shared run-output location (defined in wraith.core.context)


def _normalize_target(raw):
    """Accept a bare host/IP or a full URL and return (host, explicit_port|None),
    so `-u https://site:8443/path` scans the host `site` (and pins port 8443)."""
    parts = urlsplit(raw if "://" in raw else "//" + raw)
    host = parts.hostname or raw
    try:
        port = parts.port
    except ValueError:
        port = None
    return host, port


def _with_default_command(argv):
    """Insert `run` when the first non-global token isn't a known subcommand, so
    the common case needs no subcommand: `wraith TARGET`, `wraith -u URL`, even
    `wraith -p resolve TARGET` all route to `run`."""
    out = list(argv)
    i = 0
    while i < len(out):
        tok = out[i]
        if tok in ("-h", "--help", "--version"):
            return out                       # let argparse handle these as-is
        if tok == "--theme":                 # the one global option that takes a value
            i += 2
            continue
        if tok in ("--no-color", "--no-banner"):
            i += 1
            continue
        # First token that isn't a global option. A real subcommand is left as
        # is; anything else (a target, -u/--url, -p, ...) means the implicit run.
        if tok not in _COMMANDS:
            out.insert(i, "run")
        return out
    return out


def _console(args) -> Console:
    c = Console(
        theme=getattr(args, "theme", None),
        color=False if getattr(args, "no_color", False) else None,
        banner=not getattr(args, "no_banner", False),
        verbose=getattr(args, "verbose", False),
    )
    if _load_config().get("showdown"):       # mode on -> wire it to the console
        c.showdown = Showdown(c)
    return c


# `wraith showdown` flips a mode that sticks between runs, so it's persisted here.
_CONFIG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "wraith" / "config.json"


def _load_config() -> dict:
    try:
        return json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_config(cfg: dict) -> None:
    try:
        _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except OSError:
        pass


# Phase presets for -p. "recon" is the quiet set: DNS, port discovery and
# service/version fingerprinting — the wraith equivalent of an nmap -sV sweep —
# with none of the attack phases (no injection, content-discovery, vhost or
# template-checks), so it touches the target like a scan, not an attack.
_PHASE_PRESETS = {
    "recon": ["resolve", "tcp-scan", "http-probe", "tech-detect"],
}


def _resolve_deps(names):
    """Expand phase names to include everything they (transitively) require,
    dependencies first. Selecting `injection` thus also pulls in the
    `resolve → tcp-scan → http-probe` chain it needs, instead of the engine
    silently skipping it for an unmet requirement."""
    ordered, seen = [], set()

    def add(name, stack):
        if name in seen or name in stack:    # already pulled in, or a cycle (shouldn't happen)
            return
        cls = PHASE_REGISTRY.get(name)
        if not cls:
            raise SystemExit(f"unknown phase: {name} (see `wraith phases`)")
        for dep in sorted(cls.requires):
            add(dep, stack | {name})
        seen.add(name)
        ordered.append(name)

    for n in names:
        add(n, frozenset())
    return ordered


def _select(names):
    if not names:
        return [cls() for cls in PHASE_REGISTRY.values()]
    expanded = []
    for n in names:
        expanded.extend(_PHASE_PRESETS.get(n, [n]))
    return [PHASE_REGISTRY[n]() for n in _resolve_deps(expanded)]


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


# Finding titles that mean server-side code execution — a way in that hickok,
# wraith's post-exploitation companion, can turn into a shell.
_FOOTHOLD_TITLES = ("command injection", "remote code", "rce", "code execution",
                    "server-side template injection", "ssti", "deserial", "file upload",
                    "sql injection", "sqli")


def _is_foothold(title: str) -> bool:
    t = (title or "").lower()
    return any(k in t for k in _FOOTHOLD_TITLES)


def _drive(coro, c):
    """Run the async pipeline and turn a Ctrl-C into one clean exit.

    asyncio.run() would swallow the first SIGINT and then block in its own
    shutdown, joining the in-flight HTTP worker threads (asyncio.to_thread)
    until they drain — so the run looks frozen and needs a second Ctrl-C, and a
    third trips the ThreadPoolExecutor's atexit join and prints a traceback.
    Driving the loop ourselves lets the first Ctrl-C surface at once; os._exit
    then skips the blocking thread joins (per-phase saves already left the run
    resumable) so there's no second press and no traceback.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    except KeyboardInterrupt:
        c.spin_clear()
        print("\n  [-] interrupted", file=sys.stderr)
        sys.stderr.flush()
        sys.stdout.flush()
        os._exit(130)            # 128 + SIGINT; hard exit skips the thread joins
    finally:
        loop.close()
        asyncio.set_event_loop(None)


def _parse_headers(items):
    """Turn -H 'Key: Value' strings into a dict (last wins on a repeat)."""
    out = {}
    for raw in items or []:
        k, sep, v = raw.partition(":")
        if sep and k.strip():
            out[k.strip()] = v.strip()
    return out


def _apply_opsec(args, c) -> None:
    """Build the process-wide opsec profile from the CLI and verify routing before
    any attack traffic. Handles --check-tor (verify and exit) and --tor fail-closed."""
    from wraith.core import http as _http

    if getattr(args, "ghost", False):        # the max-opsec preset: fill in each piece unless set
        c.info("ghost mode — Tor (fail-closed) · random UA · low-and-slow · serial")
        args.tor = True
        if not args.user_agent:
            args.random_agent = True
        if not args.delay:
            args.delay = 0.5
        if not args.jitter:
            args.jitter = 0.5

    ua = args.user_agent or (_http.random_agent() if args.random_agent else None)
    try:
        _http.configure(user_agent=ua, headers=_parse_headers(args.header), cookie=args.cookie,
                        proxy=args.proxy, tor=args.tor, delay=args.delay, jitter=args.jitter)
    except _http.TorError as exc:
        c.bad(str(exc))
        sys.exit(2)

    if args.check_tor:                       # verify the routing is anonymising, then exit
        if _http.check_tor():
            c.good("Tor/proxy confirmed — traffic exits through it")
            sys.exit(0)
        c.bad("NOT anonymised — could not confirm the exit (is Tor/the proxy up?)")
        sys.exit(2)

    if args.tor or args.proxy:
        c.info(f"routing through {'Tor' if args.tor else args.proxy}")
    if args.tor:                             # fail closed: never scan in the clear if Tor is unconfirmed
        c.info("verifying Tor exit…")
        if not _http.check_tor():
            c.bad("Tor exit not confirmed — refusing to send in the clear (fail closed)")
            sys.exit(2)
        c.good("Tor confirmed")

    if args.delay or args.jitter:
        note = f"~{args.delay:g}s" + (f" +0..{args.jitter:g}s jitter" if args.jitter else "")
        c.info(f"throttled — {note} between requests")
        # not set explicitly -> serial (pacing only works serial); guarded so
        # commands without scan options (e.g. `dork`) don't trip on the attr.
        if hasattr(args, "concurrency") and args.concurrency is None:
            args.concurrency = 1
    if ua:
        c.info(f"user-agent  {ua}")


def cmd_run(args) -> None:
    c = _console(args)
    c.banner()
    _apply_opsec(args, c)

    raw = args.target or args.url
    if not raw:
        c.bad("no target — give one positionally (`wraith example.com`) or with -u/--url")
        sys.exit(2)
    target, port = _normalize_target(raw)

    if args.phases:
        names = args.phases.split(",")
    elif getattr(args, "recon", False):
        names = ["recon"]
        c.info("recon mode — ports + service/version only, no attack traffic")
    else:
        names = None
    phases = _select(names)
    ws = Workspace.create(target, base_dir=args.workdir)
    c.tee_to(ws.workdir / "log.txt")      # persist a plain-text transcript of the run
    if getattr(args, "ports", None):      # explicit port spec replaces the default list
        from wraith.phases.tcp_scan import parse_ports
        resolved = parse_ports(args.ports)
        if not resolved:
            c.bad(f"--ports {args.ports!r}: no valid ports")
            sys.exit(2)
        ws.meta["ports"] = resolved
    if port:                              # a URL/host:port pins an extra port to scan
        ws.meta["extra_ports"] = [port]
    if args.sessions:
        _load_sessions(ws, args.sessions, c)
    if args.wordlist:
        ws.meta["wordlist"] = args.wordlist
    if args.templates:
        ws.meta["templates"] = args.templates
    c.info(f"target   {ws.target}")
    c.info(f"workdir  {ws.workdir}")
    c.info(f"phases   {', '.join(p.name for p in phases)}")

    concurrency = args.concurrency if args.concurrency is not None else 8
    engine = Engine(ws, phases, c, concurrency=concurrency)
    results = _drive(engine.run(), c)

    command = "wraith " + " ".join(sys.argv[1:])
    report_md = report.write_markdown(ws, results)
    report_html = report.write_html(ws, results)
    report_json = report.write_json(ws)
    report_txt = report.write_text(ws)
    report_target = report.write_target(ws, results, command)
    ws.save()

    c.rule("summary")
    c.good(
        f"hosts {len(ws.hosts)} · services {len(ws.services)} · "
        f"endpoints {len(ws.endpoints)} · findings {len(ws.findings)}"
    )
    c.info(f"workspace  {ws.workdir / 'workspace.json'}")
    c.info(f"report     {report_md}")
    c.info(f"report     {report_html}")
    c.info(f"report     {report_txt}")
    c.info(f"findings   {report_json}")
    c.info(f"summary    {report_target}")
    c.info(f"log        {ws.workdir / 'log.txt'}")

    worst = max((f.severity for f in ws.findings), default=Severity.INFO)
    fail = bool(args.fail_on) and bool(ws.findings) and worst >= _SEVERITY_BY_NAME[args.fail_on]
    if fail:
        c.warn(f"findings at/above '{args.fail_on}' (worst: {worst.label}) — exit 2")

    if c.showdown is not None:
        # Showdown mode owns the ending: reveal, kill-chain, receipts, verdict.
        c.showdown.close(ws)
    else:
        # Plain run: the findings, then the tally.
        c.findings_report(ws.findings)
        counts = {}
        for f in ws.findings:
            counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
        c.severity_summary(counts)

    # A code-execution finding is a foothold — point at hickok, but only when
    # there's actually a hand to play.
    if any(_is_foothold(f.title) for f in ws.findings):
        c.info(f"a way in — deal the hand to hickok:  hickok call {report_json}")

    if fail:
        sys.exit(2)


def _login_form(html: str, page_url: str):
    """Find the login form on the page and return (action_url, hidden_fields).

    The login form is the one with a password input. We grab its action (where
    the POST really goes — often /auth/login, not the page URL) and every hidden
    field, so anti-CSRF tokens (ASP.NET __RequestVerificationToken, Django
    csrfmiddlewaretoken, Rails authenticity_token...) ride along automatically.
    Returns (None, {}) when no such form is found.
    """
    import re

    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html or "", re.I | re.S):
        attrs, inner = fm.group(1), fm.group(2)
        if not re.search(r'type\s*=\s*["\']password', inner, re.I):
            continue  # not the login form
        action_m = re.search(r'action\s*=\s*["\']([^"\']*)', attrs, re.I)
        action = urljoin(page_url, action_m.group(1)) if action_m and action_m.group(1) else page_url
        hidden = {}
        for inp in re.finditer(r"<input\b([^>]*)>", inner, re.I):
            a = inp.group(1)
            if not re.search(r'type\s*=\s*["\']hidden', a, re.I):
                continue
            name = re.search(r'name\s*=\s*["\']([^"\']+)', a, re.I)
            value = re.search(r'value\s*=\s*["\']([^"\']*)', a, re.I)
            if name:
                hidden[name.group(1)] = value.group(1) if value else ""
        return action, hidden
    return None, {}


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
    ua = {"User-Agent": f"wraith/{__version__}"}

    # GET the login page first: seeds the session cookie *and* lets us read the
    # form's real action and any hidden token it expects on submit.
    action, hidden = args.url, {}
    try:
        with opener.open(urllib.request.Request(args.url, headers=ua), timeout=10) as resp:
            html = resp.read(200000).decode("utf-8", "ignore")
        found_action, hidden = _login_form(html, args.url)
        if found_action:
            action = found_action
            if hidden:
                c.info(f"form action {action} · carried {len(hidden)} hidden field(s): {', '.join(hidden)}")
    except Exception as exc:
        raise SystemExit(f"could not load login page: {exc}")

    # hidden fields first, then our credentials and any --data overrides on top.
    fields = dict(hidden)
    fields[args.user_field] = args.username
    fields[args.pass_field] = args.password
    for pair in args.data or []:
        if "=" in pair:
            k, v = pair.split("=", 1)
            fields[k] = v
    body = urlencode(fields).encode()

    try:
        post = urllib.request.Request(action, data=body, headers={**ua, "Referer": args.url})
        opener.open(post, timeout=10)
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


def _fmt_result(c, url: str) -> str:
    """Dim the scheme and accent the query string so the host and the injectable
    ``?param=`` stand out in a list of results."""
    p = urlsplit(url)
    scheme = c._c(DIM, f"{p.scheme}://") if p.scheme else ""
    query = c._accent(f"?{p.query}") if p.query else ""
    return scheme + p.netloc + p.path + query


def cmd_dork(args) -> None:
    """Discover URLs from a search engine using a dork. Lists results only — it
    never sends a request to them (testing is the separate `wraith <url>` step)."""
    c = _console(args)
    c.banner()
    _apply_opsec(args, c)

    presets = [name for name, on in (
        ("params", args.params), ("files", args.files),
        ("panels", args.panels), ("listing", args.listing)) if on]
    try:
        query = search.build_query(args.query or "", presets, args.site or "")
    except ValueError as exc:
        c.bad(str(exc))
        sys.exit(2)
    if not query:
        c.bad("nothing to search — give a query, a preset (--params/--files/…), or --site")
        sys.exit(2)

    with_params = args.with_params or args.params   # --params implies wanting parametric URLs
    c.info(f"dork   {query}")
    if not args.site:
        c.warn("no --site scope — discovery only; only test hosts you're authorized to")

    try:
        results, engine = _drive(search.search(
            query, engine=args.engine or "", max_results=args.max, site=args.site or "",
            with_params=with_params, searx_url=args.searx_url or "",
            on_page=lambda e, p, n: c.trace(f"{e} page {p}: {n} result(s)", level=1),
        ), c)
    except search.SearchError as exc:
        c.bad(str(exc))
        sys.exit(2)

    if not results:
        what = "parametric URLs" if with_params else "results"
        c.warn(f"no {what} — try a broader dork or another --engine "
               "(Google CSE honours inurl: far better than DuckDuckGo)")
        return
    c.good(f"{len(results)} result(s) · {engine}")
    width = len(str(len(results)))
    for i, r in enumerate(results, 1):
        c.plain(f"  {c._c(DIM, f'{i:>{width}}.')} {_fmt_result(c, r.url)}")
    if args.output:
        Path(args.output).write_text("\n".join(r.url for r in results) + "\n", encoding="utf-8")
        c.info(f"saved {len(results)} URL(s) → {args.output}")


def cmd_showdown(args) -> None:
    """Toggle showdown mode on/off — it sticks between runs. While on, every run
    that finds a vulnerability reveals the wraith (more mode behaviour to come)."""
    c = _console(args)
    cfg = _load_config()
    cfg["showdown"] = not cfg.get("showdown", False)
    _save_config(cfg)
    if cfg["showdown"]:
        if c.show_banner:
            c.aces()
        c.good("showdown mode ON — runs now play the catch out (run `wraith showdown` again to turn off)")
    else:
        c.info("showdown mode OFF — wraith runs plain again")


def cmd_hand(args) -> None:
    _console(args).aces()


def _output_options() -> argparse.ArgumentParser:
    """Cosmetic options every command understands, shared via parents= so they
    work in any position (`wraith TARGET --no-banner`, not only before it)."""
    op = argparse.ArgumentParser(add_help=False)
    op.add_argument("--theme", metavar="NAME", choices=list(THEMES),
                    help="colour theme: " + " | ".join(THEMES) + " (default: crimson)")
    op.add_argument("--no-color", action="store_true", help="disable coloured output")
    op.add_argument("--no-banner", action="store_true", help="suppress the ASCII banner")
    return op


def _scan_options() -> argparse.ArgumentParser:
    """The scan options, shared (via parents=) by the top-level parser and the
    `run` subparser — so `wraith -h` lists them, not just `wraith run -h`."""
    sp = argparse.ArgumentParser(add_help=False)
    g = sp.add_argument_group("scan options")
    g.add_argument("-u", "--url", metavar="TARGET",
                   help="hostname, IP or URL to scan (or pass it positionally)")
    g.add_argument("-p", "--phases", metavar="LIST",
                   help="comma-separated subset of phases, or the preset 'recon' (default: all)")
    g.add_argument("--recon", action="store_true",
                   help="recon only — ports + service/version, no attack traffic (≈ nmap -sV)")
    g.add_argument("-P", "--ports", metavar="SPEC",
                   help="ports to scan: list/ranges (80,443,8000-8100) or a keyword "
                        "(top | web | all). Default: top. Combines with a host:port pin.")
    g.add_argument("-s", "--sessions", metavar="FILE", help="sessions JSON — enables access-control / IDOR")
    g.add_argument("-w", "--wordlist", metavar="FILE", help="wordlist for content-discovery")
    g.add_argument("-t", "--templates", metavar="DIR", help="extra template-checks directory")
    g.add_argument("-x", "--fail-on", metavar="SEV", choices=list(_SEVERITY_BY_NAME),
                   help="exit 2 on a finding at/above SEV (info|low|medium|high|critical)")
    g.add_argument("-c", "--concurrency", metavar="N", type=int, default=None,
                   help="max phases running in parallel (default: 8)")
    g.add_argument("--workdir", metavar="DIR", default=_runs_dir(),
                   help="output directory (default: ~/.local/share/wraith/runs, or $WRAITH_RUNS)")
    g.add_argument("-v", "--verbose", nargs="?", const=1, type=int, default=0, metavar="LEVEL",
                   help="verbosity — 1 progress · 2 attack detail (payloads & requests) · "
                        "3 + responses (bare -v = 1)")
    return sp


def _opsec_options() -> argparse.ArgumentParser:
    """Evasion / opsec — control wraith's footprint on the target so a run can be
    paced and routed instead of a flood that lights up every WAF and log."""
    op = argparse.ArgumentParser(add_help=False)
    g = op.add_argument_group("evasion / opsec")
    g.add_argument("--ghost", action="store_true",
                   help="max-opsec preset: Tor (fail-closed) + random UA + delay/jitter + serial — "
                        "the safest footprint for an attack (override any piece with its own flag)")
    g.add_argument("--delay", metavar="SEC", type=float, default=0.0,
                   help="minimum seconds between requests — paces the scan (default: 0, full speed)")
    g.add_argument("--jitter", metavar="SEC", type=float, default=0.0,
                   help="add a random 0..SEC on top of --delay, so the timing isn't a fixed beat")
    g.add_argument("-A", "--user-agent", metavar="UA", help="explicit User-Agent (default: wraith/<ver>)")
    g.add_argument("--random-agent", action="store_true", help="use a random real browser User-Agent")
    g.add_argument("-H", "--header", action="append", metavar="'K: V'",
                   help="extra request header, repeatable")
    g.add_argument("--cookie", metavar="STR", help="Cookie header sent on every request")
    g.add_argument("--proxy", metavar="URL",
                   help="route through http://host:port or socks5h://host:port (Burp, a SOCKS proxy)")
    g.add_argument("--tor", action="store_true",
                   help="route via Tor (socks5h://127.0.0.1:9050), verified — fails closed")
    g.add_argument("--check-tor", action="store_true",
                   help="just verify Tor/proxy is anonymising you, then exit")
    return op


def build_parser() -> argparse.ArgumentParser:
    common, scan, opsec = _output_options(), _scan_options(), _opsec_options()
    p = argparse.ArgumentParser(
        prog="wraith",
        description="Offensive recon & vulnerability detection pipeline.  Run is the default: "
                    "`wraith TARGET` or `wraith -u TARGET`.",
        epilog=EXAMPLES,
        formatter_class=_Help,
        parents=[common, scan, opsec],
    )
    p.add_argument("--version", action="version", version=f"wraith {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    run = sub.add_parser("run", help="scan a target (default command)", epilog=EXAMPLES,
                         formatter_class=_Help, parents=[common, scan, opsec],
                         description="Run the phase pipeline against a target.")
    run.add_argument("target", nargs="?", help="hostname, IP or URL (or use -u/--url)")
    run.set_defaults(func=cmd_run)

    sd = sub.add_parser("showdown", help="toggle showdown mode on/off (sticks between runs)",
                        formatter_class=_Help, parents=[common],
                        description="Toggle showdown mode. While it's on, every run reveals the "
                                    "wraith when it catches a vulnerability. Run it again to turn off.")
    sd.set_defaults(func=cmd_showdown)

    ph = sub.add_parser("phases", help="list available phases", formatter_class=_Help, parents=[common])
    ph.set_defaults(func=cmd_phases)

    lg = sub.add_parser("login", help="grab a session from a form login -> sessions.json",
                        formatter_class=_Help, parents=[common])
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

    dk = sub.add_parser("dork", help="find URLs with a search-engine dork (discovery only — never scans them)",
                        formatter_class=_Help, parents=[common, opsec], epilog=DORK_EXAMPLES,
                        description="Discover URLs from a search engine using a dork. It lists results "
                                    "only — it never sends a request to them. Works with no setup "
                                    "(DuckDuckGo); set WRAITH_SEARXNG_URL / WRAITH_GOOGLE_API_KEY+"
                                    "WRAITH_GOOGLE_CX / WRAITH_BRAVE_API_KEY to use an API backend.")
    dk.add_argument("query", nargs="?", help="the search query / dork (e.g. 'inurl:login')")
    dg = dk.add_argument_group("dork presets (combine with a query and/or each other)")
    dg.add_argument("--params", "--injec", dest="params", action="store_true",
                    help="URLs with injectable-looking parameters — SQLi/IDOR candidates")
    dg.add_argument("--files", action="store_true", help="exposed files (.env/.bak/.sql/.log/…)")
    dg.add_argument("--panels", action="store_true", help="login / admin panels")
    dg.add_argument("--listing", action="store_true", help='open directory listings (intitle:"index of")')
    do = dk.add_argument_group("dork options")
    do.add_argument("--site", metavar="DOMAIN", help="scope results to a domain (site:DOMAIN + post-filter)")
    do.add_argument("--with-params", dest="with_params", action="store_true",
                    help="keep only URLs that carry a ?param= — drops the blog posts a search "
                         "engine mixes in (implied by --params)")
    do.add_argument("--engine", choices=list(search.ENGINES),
                    help="search backend (default: duckduckgo — no key; or a configured API backend)")
    do.add_argument("--searx-url", metavar="URL", dest="searx_url",
                    help="SearXNG instance URL (or WRAITH_SEARXNG_URL)")
    do.add_argument("--max", type=int, default=30, metavar="N", help="max results (default: 30)")
    do.add_argument("-o", "--output", metavar="FILE", help="write the URLs here, one per line")
    dk.set_defaults(func=cmd_dork)

    egg = sub.add_parser("hand", parents=[common])  # easter egg: no help= keeps it out of the listing
    egg.set_defaults(func=cmd_hand)

    return p


def main(argv=None) -> None:
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    if not argv:                         # bare `wraith` -> banner + a lean tutorial
        _quickstart(Console())
        return
    args = parser.parse_args(_with_default_command(argv))
    if not hasattr(args, "func"):        # options but no command
        _quickstart(_console(args))
        return
    try:
        args.func(args)
    except KeyboardInterrupt:            # Ctrl-C mid-run: exit clean, no traceback
        print("\n  [-] interrupted", file=sys.stderr)
        sys.exit(130)                    # 128 + SIGINT, the conventional code


if __name__ == "__main__":
    main()
