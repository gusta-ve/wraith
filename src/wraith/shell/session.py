"""Connected reverse-shell sessions and their registry."""

from __future__ import annotations

import asyncio
import sys
import time


class ShellSession:
    """One connected shell. A background task pumps inbound data either into a
    queue (so `cmd` can collect a burst of output) or straight to stdout (while
    interacting)."""

    def __init__(self, sid: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.id = sid
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername") or ("?", 0)
        self.connected = time.time()
        self.alive = True
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._mirror = False
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._pump())

    async def _pump(self) -> None:
        try:
            while True:
                data = await self.reader.read(4096)
                if not data:
                    break
                if self._mirror:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                else:
                    await self._queue.put(data)
        except Exception:
            pass
        finally:
            self.alive = False

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def collect(self, timeout: float = 1.0) -> bytes:
        """Drain buffered output for up to `timeout` seconds of silence."""
        chunks: list[bytes] = []
        try:
            while True:
                chunks.append(await asyncio.wait_for(self._queue.get(), timeout=timeout))
        except asyncio.TimeoutError:
            pass
        return b"".join(chunks)

    def mirror_on(self) -> None:
        # Flush whatever is queued, then stream subsequent output to stdout.
        while not self._queue.empty():
            sys.stdout.buffer.write(self._queue.get_nowait())
        sys.stdout.buffer.flush()
        self._mirror = True

    def mirror_off(self) -> None:
        self._mirror = False

    def close(self) -> None:
        self.alive = False
        try:
            self.writer.close()
        except Exception:
            pass

    @property
    def age(self) -> str:
        return f"{int(time.time() - self.connected)}s"


class SessionManager:
    def __init__(self):
        self._sessions: dict[int, ShellSession] = {}
        self._counter = 0

    def add(self, reader, writer) -> ShellSession:
        self._counter += 1
        sess = ShellSession(self._counter, reader, writer)
        self._sessions[sess.id] = sess
        return sess

    def get(self, sid: int) -> ShellSession | None:
        return self._sessions.get(sid)

    def remove(self, sid: int) -> None:
        sess = self._sessions.pop(sid, None)
        if sess:
            sess.close()

    def all(self) -> list[ShellSession]:
        return list(self._sessions.values())
