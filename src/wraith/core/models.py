"""Core data types shared across phases through the Workspace."""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Host:
    value: str
    kind: str = "ip"          # "ip" | "hostname"
    source: str = ""


@dataclass
class Service:
    host: str
    port: int
    proto: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    source: str = ""

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}/{self.proto}"


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    status: int = 0
    title: str = ""
    server: str = ""
    tech: list = field(default_factory=list)


@dataclass
class Session:
    """A captured authentication context, used by access-control phases."""

    name: str
    role: str = "low"          # none | low | med | high (privilege ranking)
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)


@dataclass
class Finding:
    title: str
    severity: Severity = Severity.INFO
    phase: str = ""
    target: str = ""
    evidence: str = ""
    description: str = ""
    meta: dict = field(default_factory=dict)   # structured extras, e.g. SQLi technique/dbms for the handoff
    created: float = field(default_factory=time.time)
