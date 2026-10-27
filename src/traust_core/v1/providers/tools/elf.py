"""An ELF binary's header, the shared libraries it links and the byte patterns in it, read without
external tools or domain knowledge."""

from __future__ import annotations

import mmap
import re
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from traust_core.v1.models import elf_formats

MAX_SCAN_BYTES = 32_000_000
_MACHINE_NAMES: dict[int, str] = {
    3: "i386",
    62: "x86_64",
    40: "arm",
    183: "aarch64",
    243: "riscv64",
    8: "mips",
    10: "mips64",
}

Patterns = Sequence[tuple[str, re.Pattern[bytes]]]


@dataclass(frozen=True, slots=True)
class ElfMetadata:
    arch: str
    elf_class: int
    endian: str


@dataclass(frozen=True, slots=True)
class StringMatch:
    pattern_id: str
    matched: str
    offset: int


@dataclass(frozen=True, slots=True)
class LinkedLibrary:
    name: str


class ElfAnalyzer:
    """One ELF file, read once on first use."""

    def __init__(self, path: str | Path, data: bytes | None = None) -> None:
        self.path = Path(path)
        self._data = data

    def _load(self) -> bytes:
        if self._data is None:
            self._data = self.path.read_bytes()
        return self._data

    def metadata(self) -> ElfMetadata | None:
        """Architecture, class and byte order; None for anything that isn't an ELF."""
        data = self._load()
        if len(data) < 64 or not elf_formats.is_elf(data) or data[4] not in (1, 2):
            return None
        endian = {1: "<", 2: ">"}.get(data[5])
        if endian is None:
            return None
        machine = struct.unpack_from(endian + "H", data, 18)[0]
        return ElfMetadata(
            arch=_MACHINE_NAMES.get(machine, f"unknown({machine})"),
            elf_class=32 if data[4] == 1 else 64,
            endian="little" if endian == "<" else "big",
        )

    def linked_libraries(self) -> list[LinkedLibrary]:
        return [LinkedLibrary(name) for name in elf_formats.linked_libraries(self._load())]

    @classmethod
    def linked_libraries_from_bytes(cls, data: bytes) -> list[LinkedLibrary]:
        return cls(Path(), data).linked_libraries()

    def scan_strings(
        self, patterns: Patterns, *, max_scan: int = MAX_SCAN_BYTES
    ) -> list[StringMatch]:
        """Each pattern's matches in the file's first `max_scan` bytes, memory-mapped."""
        with self.path.open("rb") as fh:
            try:
                with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    return self.scan_bytes(mm[: min(len(mm), max_scan)], patterns)
            except (ValueError, OSError):  # an empty file or one mmap can't map: read it instead
                return self.scan_bytes(self._load(), patterns, max_scan=max_scan)

    @classmethod
    def scan_bytes(
        cls, data: bytes, patterns: Patterns, *, max_scan: int = MAX_SCAN_BYTES
    ) -> list[StringMatch]:
        scan = data[: min(len(data), max_scan)]
        return [
            StringMatch(pattern_id, m.group(0).decode("ascii", errors="replace"), m.start())
            for pattern_id, regex in patterns
            for m in regex.finditer(scan)
        ]

    @classmethod
    def is_elf(cls, data: bytes) -> bool:
        return len(data) >= 4 and elf_formats.is_elf(data)
