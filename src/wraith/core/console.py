"""Dependency-free console output. Sober, dark-terminal friendly."""

from __future__ import annotations

import sys

_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


class Console:
    def banner(self) -> None:
        print()
        print(_c("1;37", "  wraith"))
        print(_c("2", "  offensive recon & exploitation pipeline"))
        print()

    def rule(self, title: str = "") -> None:
        if title:
            print()
            print(_c("2", f"── {title} " + "─" * max(0, 52 - len(title))))
        else:
            print(_c("2", "─" * 56))

    def phase(self, name: str, description: str = "") -> None:
        print()
        print(_c("36", f"▸ {name}") + (_c("2", f"  {description}") if description else ""))

    def info(self, msg) -> None:
        print(_c("36", "  [*] ") + str(msg))

    def good(self, msg) -> None:
        print(_c("32", "  [+] ") + str(msg))

    def warn(self, msg) -> None:
        print(_c("33", "  [!] ") + str(msg))

    def bad(self, msg) -> None:
        print(_c("31", "  [-] ") + str(msg))

    def plain(self, msg: str = "") -> None:
        print(msg)
