"""The Workspace: shared, persisted state that flows through every phase."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .models import Endpoint, Finding, Host, Service, Session, Severity


def runs_dir() -> str:
    """Default per-user location for run output — a fixed XDG data dir, shared
    with hickok so it finds runs from any working directory. Overridden globally
    by $WRAITH_RUNS, or per-run by an explicit base_dir / --workdir."""
    env = os.environ.get("WRAITH_RUNS")
    if env:
        return os.path.expanduser(env)
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "wraith", "runs")


@dataclass
class Workspace:
    target: str
    scope: list = field(default_factory=list)
    workdir: Path = field(default_factory=lambda: Path("."))
    started: float = field(default_factory=time.time)
    hosts: list = field(default_factory=list)
    services: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    sessions: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    # ----- mutation helpers (dedupe so phases stay idempotent on re-run) -----
    def add_host(self, value, kind="ip", source=""):
        if any(h.value == value for h in self.hosts):
            return None
        host = Host(value=value, kind=kind, source=source)
        self.hosts.append(host)
        return host

    def add_service(self, host, port, proto="tcp", name="", product="", version="", banner="", source=""):
        key = f"{host}:{port}/{proto}"
        for svc in self.services:
            if svc.key == key:
                return svc
        svc = Service(host=host, port=port, proto=proto, name=name,
                      product=product, version=version, banner=banner, source=source)
        self.services.append(svc)
        return svc

    def add_endpoint(self, url, method="GET", status=0, title="", server="", tech=None):
        for ep in self.endpoints:
            if ep.url == url and ep.method == method:
                return ep
        ep = Endpoint(url=url, method=method, status=status, title=title, server=server, tech=list(tech or []))
        self.endpoints.append(ep)
        return ep

    def add_session(self, name, role="low", headers=None, cookies=None):
        sess = Session(name=name, role=role, headers=dict(headers or {}), cookies=dict(cookies or {}))
        self.sessions.append(sess)
        return sess

    def add_finding(self, title, severity, phase="", target="", evidence="", description=""):
        finding = Finding(title=title, severity=Severity(severity), phase=phase,
                          target=target, evidence=evidence, description=description)
        self.findings.append(finding)
        return finding

    # ----- persistence -----
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scope": self.scope,
            "started": self.started,
            "meta": self.meta,
            "hosts": [asdict(h) for h in self.hosts],
            "services": [asdict(s) for s in self.services],
            "endpoints": [asdict(e) for e in self.endpoints],
            "sessions": [asdict(s) for s in self.sessions],
            "findings": [{**asdict(f), "severity": int(f.severity)} for f in self.findings],
        }

    def save(self, path=None) -> Path:
        path = Path(path) if path else self.workdir / "workspace.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path) -> "Workspace":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        ws = cls(target=data["target"], scope=data.get("scope", []), workdir=Path(path).parent)
        ws.started = data.get("started", time.time())
        ws.meta = data.get("meta", {})
        ws.hosts = [Host(**h) for h in data.get("hosts", [])]
        ws.services = [Service(**s) for s in data.get("services", [])]
        ws.endpoints = [Endpoint(**e) for e in data.get("endpoints", [])]
        ws.sessions = [Session(**s) for s in data.get("sessions", [])]
        ws.findings = [Finding(**{**f, "severity": Severity(f["severity"])}) for f in data.get("findings", [])]
        return ws

    @classmethod
    def create(cls, target, base_dir=None, scope=None) -> "Workspace":
        ts = time.strftime("%Y%m%d-%H%M%S")
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)
        workdir = Path(base_dir or runs_dir()) / f"{safe}-{ts}"
        workdir.mkdir(parents=True, exist_ok=True)
        return cls(target=target, scope=scope or [target], workdir=workdir)
