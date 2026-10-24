"""ELF binaries as the shared libraries they link (DT_NEEDED), read from the bytes alone: no
loader, no external tools, no crypto knowledge."""

from __future__ import annotations

import struct

_MAGIC = b"\x7fELF"
_PT_LOAD, _PT_DYNAMIC = 1, 2
_DT_NULL, _DT_NEEDED, _DT_STRTAB, _DT_STRSZ = 0, 1, 5, 10
_MAX_NAME = 256
# Per ELF class: program header table fields (offset, entry size, count), one program header,
# its size, and one dynamic entry.
_LAYOUT = {
    1: ((28, "I"), (42, "H"), (44, "H"), "IIIIIIII", 32, "II"),
    2: ((32, "Q"), (54, "H"), (56, "H"), "IIQQQQQQ", 56, "QQ"),
}


def is_elf(data: bytes) -> bool:
    return data[:4] == _MAGIC


def linked_libraries(data: bytes) -> tuple[str, ...]:
    """The DT_NEEDED names in file order; empty for anything that isn't a dynamically linked ELF
    or whose headers don't hold together."""
    if len(data) < 64 or not is_elf(data) or data[4] not in _LAYOUT or data[5] not in (1, 2):
        return ()
    endian = "<" if data[5] == 1 else ">"
    phoff, phentsize, phnum, header, header_size, entry = _LAYOUT[data[4]]
    try:
        segments, dynamic = _segments(data, endian, phoff, phentsize, phnum, header, header_size)
        if dynamic is None:
            return ()
        strtab, strsz, needed = _dynamic(data, endian, dynamic, entry)
    except struct.error:
        return ()
    base = next((off + strtab - va for off, va, size in segments if va <= strtab < va + size), None)
    if base is None or not strtab or not needed:
        return ()
    limit = base + (strsz or len(data) - base)
    names = []
    for index in needed:
        start = base + index
        end = data.find(b"\x00", start, min(start + _MAX_NAME, limit))
        if start < len(data) and end > start:
            names.append(data[start:end].decode("ascii", errors="replace"))
    return tuple(names)


def _segments(
    data: bytes,
    endian: str,
    phoff: tuple[int, str],
    phentsize: tuple[int, str],
    phnum: tuple[int, str],
    header: str,
    header_size: int,
) -> tuple[list[tuple[int, int, int]], tuple[int, int] | None]:
    def field(spec: tuple[int, str]) -> int:
        return int(struct.unpack_from(endian + spec[1], data, spec[0])[0])

    table, step = field(phoff), field(phentsize)
    loads: list[tuple[int, int, int]] = []
    dynamic = None
    for i in range(field(phnum)):
        at = table + i * step
        if at + header_size > len(data):
            break
        values = struct.unpack_from(endian + header, data, at)
        # ELF32 orders p_flags after p_memsz; ELF64 right after p_type.
        kind, offset, vaddr, filesz = (
            (values[0], values[1], values[2], values[4])
            if header_size == 32
            else (values[0], values[2], values[3], values[5])
        )
        if kind == _PT_LOAD:
            loads.append((offset, vaddr, filesz))
        elif kind == _PT_DYNAMIC:
            dynamic = (offset, filesz)
    if dynamic is None or not dynamic[0] or sum(dynamic) > len(data):
        return loads, None
    return loads, dynamic


def _dynamic(
    data: bytes, endian: str, dynamic: tuple[int, int], entry: str
) -> tuple[int, int, list[int]]:
    strtab = strsz = 0
    needed: list[int] = []
    step = struct.calcsize(entry)
    offset, size = dynamic
    for at in range(offset, offset + size - step + 1, step):
        tag, value = struct.unpack_from(endian + entry, data, at)
        if tag == _DT_NULL:
            break
        if tag == _DT_STRTAB:
            strtab = value
        elif tag == _DT_STRSZ:
            strsz = value
        elif tag == _DT_NEEDED:
            needed.append(value)
    return strtab, strsz, needed
