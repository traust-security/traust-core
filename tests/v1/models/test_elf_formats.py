from __future__ import annotations

import struct

import pytest

from traust_core.v1.models.elf_formats import is_elf, linked_libraries

VADDR = 0x400000


def elf(
    needed: tuple[str, ...] = ("libssl.so.3", "libc.so.6"),
    *,
    bits: int = 64,
    endian: str = "<",
    dynamic: bool = True,
    strtab_mapped: bool = True,
    strsz: int | None = None,
    terminated: bool = True,
) -> bytes:
    """A minimal ELF: header, two program headers (PT_LOAD over the file, PT_DYNAMIC), the
    dynamic entries, then the string table."""
    ehsize, phentsize, dynentry = (64, 56, 16) if bits == 64 else (52, 32, 8)
    phoff = ehsize
    dyn_offset = phoff + 2 * phentsize
    strings = b"\x00" + b"".join(n.encode() + b"\x00" for n in needed)
    if not terminated:
        strings = strings.rstrip(b"\x00")
    offsets = [1 + sum(len(n) + 1 for n in needed[:i]) for i in range(len(needed))]
    entries = [(1, o) for o in offsets] + [(5, 0), (10, strsz or len(strings)), (0, 0)]
    str_offset = dyn_offset + len(entries) * dynentry
    total = str_offset + len(strings)
    entries[-3] = (5, (VADDR if strtab_mapped else 0x900000) + str_offset)
    word = "Q" if bits == 64 else "I"
    header = bytearray(ehsize)
    header[:6] = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if endian == "<" else 2])
    struct.pack_into(endian + "H", header, 18, 62)
    if bits == 64:
        struct.pack_into(endian + "Q", header, 32, phoff)
        struct.pack_into(endian + "HH", header, 54, phentsize, 2)
        load = struct.pack(endian + "IIQQQQQQ", 1, 5, 0, VADDR, VADDR, total, total, 0x1000)
        dyn = struct.pack(
            endian + "IIQQQQQQ",
            2 if dynamic else 4,
            6,
            dyn_offset,
            VADDR + dyn_offset,
            0,
            len(entries) * dynentry,
            0,
            8,
        )
    else:
        struct.pack_into(endian + "I", header, 28, phoff)
        struct.pack_into(endian + "HH", header, 42, phentsize, 2)
        load = struct.pack(endian + "IIIIIIII", 1, 0, VADDR, VADDR, total, total, 5, 0x1000)
        dyn = struct.pack(
            endian + "IIIIIIII",
            2 if dynamic else 4,
            dyn_offset,
            VADDR + dyn_offset,
            0,
            len(entries) * dynentry,
            0,
            6,
            4,
        )
    body = b"".join(struct.pack(endian + word * 2, t, v) for t, v in entries)
    return bytes(header) + load + dyn + body + strings


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_linked_libraries_in_file_order_for_each_class_and_byte_order(
    bits: int, endian: str
) -> None:
    assert linked_libraries(elf(bits=bits, endian=endian)) == ("libssl.so.3", "libc.so.6")


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x7fELF",
        b"#!/bin/sh\n" + b"\x00" * 64,
        b"\x7fELF\x03\x01" + b"\x00" * 64,
        b"\x7fELF\x02\x03" + b"\x00" * 64,
        elf(dynamic=False),
        elf(()),
        elf(strtab_mapped=False),
        elf()[:120],
    ],
    ids=[
        "empty",
        "magic only",
        "script",
        "bad class",
        "bad byte order",
        "static",
        "no DT_NEEDED",
        "strtab outside PT_LOAD",
        "truncated",
    ],
)
def test_anything_but_a_whole_dynamic_elf_links_nothing(data: bytes) -> None:
    assert linked_libraries(data) == ()


def test_a_name_without_its_terminator_inside_the_string_table_is_dropped() -> None:
    assert linked_libraries(elf(("libssl.so.3", "libcrypto.so.3"), terminated=False)) == (
        "libssl.so.3",
    )


def test_strsz_bounds_the_names() -> None:
    assert linked_libraries(elf(("libssl.so.3", "libc.so.6"), strsz=13)) == ("libssl.so.3",)


def test_is_elf_reads_the_magic() -> None:
    assert is_elf(elf()) and not is_elf(b"MZ\x90\x00")
