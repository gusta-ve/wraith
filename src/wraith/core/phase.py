"""Phase abstraction and registry.

A phase is one stage of the kill-chain. Phases declare a unique ``name`` and the
set of phase names they depend on (``requires``); they share state only through
the Workspace. This keeps them decoupled and lets the engine run independent
phases concurrently while honoring dependencies.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

PHASE_REGISTRY: dict[str, type["Phase"]] = {}


def register(cls: type["Phase"]) -> type["Phase"]:
    """Class decorator that adds a phase to the global registry."""
    if not getattr(cls, "name", ""):
        raise ValueError(f"{cls.__name__} must define a non-empty 'name'")
    PHASE_REGISTRY[cls.name] = cls
    return cls


class Phase(ABC):
    name: str = ""
    requires: frozenset = frozenset()
    description: str = ""

    @abstractmethod
    async def run(self, ws, console) -> None:
        """Execute the phase, mutating the shared Workspace ``ws``."""
        ...
