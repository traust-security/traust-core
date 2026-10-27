from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest

from tests.v1.models.test_elf_formats import elf
from traust_core.v1.providers.tools.elf import (
    ElfAnalyzer,
    ElfMetadata,
    LinkedLibrary,
    StringMatch,
)

PATTERNS = [("ssl", re.compile(rb"libssl\.so\.\d")), ("c", re.compile(rb"libc\.so"))]


def write(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "bin"
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize(("endian", "order"), [("<", "little"), (">", "big")])
def test_metadata_reads_class_byte_order_and_architecture(
    tmp_path: Path, bits: int, endian: str, order: str
) -> None:
    analyzer = ElfAnalyzer(write(tmp_path, elf(bits=bits, endian=endian)))
    assert analyzer.metadata() == ElfMetadata(arch="x86_64", elf_class=bits, endian=order)


def test_an_unknown_machine_is_named_by_its_number(tmp_path: Path) -> None:
    data = bytearray(elf())
    struct.pack_into("<H", data, 18, 999)
    assert ElfAnalyzer(write(tmp_path, bytes(data))).metadata() == ElfMetadata(
        "unknown(999)", 64, "little"
    )


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x7fELF",
        b"MZ" + bytes(100),
        b"\x7fELF\x03\x01" + bytes(80),
        b"\x7fELF\x02\x03" + bytes(80),
    ],
)
def test_anything_but_an_elf_has_no_metadata_or_libraries(tmp_path: Path, data: bytes) -> None:
    analyzer = ElfAnalyzer(str(write(tmp_path, data)))
    assert analyzer.metadata() is None
    assert analyzer.linked_libraries() == []


def test_linked_libraries_from_a_file_or_bytes(tmp_path: Path) -> None:
    expected = [LinkedLibrary("libssl.so.3"), LinkedLibrary("libc.so.6")]
    assert ElfAnalyzer(write(tmp_path, elf())).linked_libraries() == expected
    assert ElfAnalyzer.linked_libraries_from_bytes(elf()) == expected
    assert ElfAnalyzer.linked_libraries_from_bytes(elf(dynamic=False)) == []


def test_scan_strings_finds_each_pattern_with_its_offset(tmp_path: Path) -> None:
    data = elf()
    matches = ElfAnalyzer(write(tmp_path, data)).scan_strings(PATTERNS)
    assert matches == [
        StringMatch("ssl", "libssl.so.3", data.index(b"libssl")),
        StringMatch("c", "libc.so", data.index(b"libc.so")),
    ]


def test_scan_strings_stops_at_max_scan(tmp_path: Path) -> None:
    data = elf()
    cut = data.index(b"libc.so")
    assert [
        m.pattern_id
        for m in ElfAnalyzer(write(tmp_path, data)).scan_strings(PATTERNS, max_scan=cut)
    ] == ["ssl"]


def test_scan_strings_reads_a_file_mmap_cannot_map(tmp_path: Path) -> None:
    assert ElfAnalyzer(write(tmp_path, b"")).scan_strings(PATTERNS) == []


def test_scan_bytes_without_a_file() -> None:
    assert ElfAnalyzer.scan_bytes(b"xx libc.so yy", PATTERNS) == [StringMatch("c", "libc.so", 3)]
    assert ElfAnalyzer.scan_bytes(b"xx libc.so yy", PATTERNS, max_scan=5) == []


@pytest.mark.parametrize(("data", "found"), [(b"\x7fELF", True), (b"\x7fEL", False), (b"", False)])
def test_is_elf(data: bytes, found: bool) -> None:
    assert ElfAnalyzer.is_elf(data) is found
