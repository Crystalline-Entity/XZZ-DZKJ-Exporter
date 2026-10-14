# PCB decoder and validation helpers for XZZ/DZKJ Exporter by CE.

from __future__ import annotations

import mmap
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Sequence

BLOCK_BYTES = 0x40000
MAX_PREFIX = 256
MAX_DOCUMENT = 1024 * 1024 * 1024
MAGIC = b"XZZPCB V1.0".ljust(32, b"\0")
FOOTER = b"v6v6555v6v6\n===PCB\xb8\xbd\xbc\xd3\n"


class PCBError(ValueError):
    # The data does not match the recovered PCB wire format.
    pass


@dataclass(frozen=True)
class Chunk:
    # Offset is the starting byte of the chunk in the capture file.
    offset: int
    size: int
    position: int


def _u32(data, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise PCBError("Truncated 32-bit length or PCB header")
    return struct.unpack_from("<I", data, offset)[0]


def wrapper_skip(data, marker: int) -> int:
    # Return validated wrapper byte count, or 0 for an unwrapped block.
    for i in range(min(MAX_PREFIX, max(0, len(data) - 7))):
        if (data[i] == marker and data[i + 2] == (marker ^ 0x11)
                and data[i + 4] == (marker ^ 0x11) and data[i + 6] == marker):
            return i + 7
    return 0


def _begin(data) -> tuple[int, bool, int]:
    if len(data) < len(MAGIC):
        raise PCBError("PCB header is too short")
    for offset in range(min(MAX_PREFIX, len(data) - len(MAGIC)) + 1):
        key = data[offset + 11]
        if all((data[offset + i] ^ key) == expected for i, expected in enumerate(MAGIC)):
            if offset:
                marker = data[offset - 1]
                if wrapper_skip(data, marker) != offset:
                    continue
                return key, True, marker
            return key, False, 0
    raise PCBError("Encoded XZZPCB V1.0 header not found")


def pcb_file_length(data) -> int:
    # Validate net records and return the end of the PCB core section.
    if len(data) < 68 or bytes(data[:32]) != MAGIC:
        raise PCBError("Decoded PCB does not have the expected 32-byte header")
    offset = _u32(data, 40) + 32
    if offset > len(data) or len(data) - offset < 4:
        raise PCBError("Invalid net section offset")
    section_size = _u32(data, offset)
    start = offset + 4
    end = start + section_size
    if end > len(data) or end > MAX_DOCUMENT:
        raise PCBError("Declared net section extends past PCB end")
    pos = start
    while pos < end:
        if end - pos < 8:
            raise PCBError("Truncated net record")
        record = _u32(data, pos)
        if record < 8 or record > end - pos:
            raise PCBError("Invalid net record length")
        pos += record
    if pos != end:
        raise PCBError("Net records do not terminate at section end")
    if end < len(data):
        # Bboardview files may have other data before it.
        last_start = len(data) - len(FOOTER) - 1
        for footer_start in range(end, last_start + 1):
            footer_key = data[footer_start] ^ FOOTER[0]
            if (data[footer_start + 1] ^ footer_key) != FOOTER[1]:
                continue
            if any((data[footer_start + i] ^ footer_key) != byte
                   for i, byte in enumerate(FOOTER)):
                continue
            json_start = footer_start + len(FOOTER)
            if (data[json_start] ^ footer_key) != ord("{"):
                continue
            close = bytes([ord("}") ^ footer_key])
            if data.find(close, json_start + 1) >= 0:
                return footer_start
        # The declared net section and all of its records are already valid.
        # Unknown trailing bytes are transport metadata, so keep the PCB core.
    return end


def _xor(source: bytes, key: int) -> bytes:
    return source.translate(bytes.maketrans(bytes(range(256)), bytes(x ^ key for x in range(256))))


def decode_stream(data: bytes) -> bytes:
    # Decode contiguous wire-format PCB bytes.
    key, wrapped, marker = _begin(data)
    read = 0
    result = bytearray()
    while read < len(data):
        remaining = len(data) - read
        skip = wrapper_skip(data[read:read + min(remaining, MAX_PREFIX + 8)], marker) if wrapped else 0
        part = min(remaining, skip + BLOCK_BYTES) if wrapped else remaining
        if skip >= part:
            raise PCBError("Empty PCB part")
        result.extend(_xor(data[read + skip:read + part], key))
        if len(result) > MAX_DOCUMENT:
            raise PCBError("PCB exceeds maximum decoded length")
        read += part
    length = pcb_file_length(result)
    return bytes(result[:length])


def decode_positioned(data: bytes, chunks: Sequence[Chunk]) -> bytes:
    # Decode captured tree chunks using one-based logical Position values.
    if not chunks or len(chunks) > 1048576:
        raise PCBError("Invalid number of PCB nodes")
    if chunks[0].position != 1:
        raise PCBError("Positioned PCB must begin at logical Position 1")
    first = chunks[0]
    first_bytes = data[first.offset:first.offset + first.size]
    if len(first_bytes) != first.size:
        raise PCBError("Truncated first PCB node")
    key, wrapped, marker = _begin(first_bytes)
    decoded = bytearray()
    expected_offset = 0
    for index, chunk in enumerate(chunks):
        if chunk.offset < 0 or chunk.size <= 0 or chunk.size > MAX_DOCUMENT:
            raise PCBError("Invalid node size")
        part = data[chunk.offset:chunk.offset + chunk.size]
        if len(part) != chunk.size:
            raise PCBError("Truncated PCB node")
        skip = 0
        if index + 1 < len(chunks):
            next_pos = chunks[index + 1].position
            logical = next_pos - chunk.position
            if logical <= 0 or logical > chunk.size:
                raise PCBError("Invalid or reversed PCB positions")
            skip = chunk.size - logical
            if skip:
                if skip < 7 or skip > MAX_PREFIX + 7:
                    raise PCBError("Unreasonable wrapper size")
                term = part[skip - 7:skip]
                actual_marker = term[0]
                if (term[2] != (actual_marker ^ 0x11)
                        or term[4] != (actual_marker ^ 0x11)
                        or term[6] != actual_marker):
                    raise PCBError("Position wrapper terminator did not validate")
                marker = actual_marker
        elif wrapped:
            skip = wrapper_skip(part, marker)
        if index == 0 and len(chunks) == 1:
            skip = wrapper_skip(part, marker) if wrapped else 0
        if skip >= chunk.size or expected_offset != chunk.position - 1:
            raise PCBError("PCB chunk logical position mismatch")
        if index == 0:
            if len(part) - skip < len(MAGIC):
                raise PCBError("First PCB node too small")
            if any((part[skip + i] ^ key) != b for i, b in enumerate(MAGIC)):
                raise PCBError("First PCB node header invalid after wrapper removal")
        decoded.extend(_xor(part[skip:], key))
        expected_offset += chunk.size - skip
        if len(decoded) > MAX_DOCUMENT:
            raise PCBError("PCB exceeds maximum decoded length")
    return bytes(decoded[:pcb_file_length(decoded)])


def _validate_extension(file: Path) -> None:
    if file.resolve() == Path(os.devnull).resolve():
        raise PCBError("Invalid output path")


def repair_file(source: str | Path, target: str | Path) -> tuple[int, int]:
    # Repair a captured PCB to a new file; refuses to overwrite existing data.
    source, target = Path(source), Path(target)
    _validate_extension(target)
    if source.resolve() == target.resolve():
        raise PCBError("Input and output must be different paths")
    size = source.stat().st_size
    if size < 68 or size > MAX_DOCUMENT:
        raise PCBError("Input PCB size is outside supported limits")
    fixed = decode_stream(source.read_bytes())
    with target.open("xb") as stream:
        stream.write(fixed)
    return size, len(fixed)


def _finish_file(path: str | Path) -> int:
    path = Path(path)
    with path.open("r+b") as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as image:
            length = pcb_file_length(image)
        stream.truncate(length)
    return length


def _write_xor(source, first: int, size: int, key: int, target: BinaryIO) -> None:
    table = bytes(x ^ key for x in range(256))
    cursor = first
    stop = first + size
    while cursor < stop:
        count = min(1024 * 1024, stop - cursor)
        target.write(source[cursor:cursor + count].translate(table))
        cursor += count


def decode_positioned_file(source: str | Path, chunks: Sequence[Chunk], destination: str | Path) -> int:
    # Stream a position-aware PCB capture to a new decoded file.
    if not chunks or len(chunks) > 1048576 or chunks[0].position != 1:
        raise PCBError("Invalid PCB chunk positions")
    with Path(source).open("rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            first = chunks[0]
            if first.size < 32 or first.offset + first.size > len(raw):
                raise PCBError("Truncated first PCB node")
            key, wrapped, marker = _begin(raw[first.offset:first.offset + min(first.size, MAX_PREFIX + 32)])
            have_marker = wrapped
            logical_offset = 0
            with Path(destination).open("wb") as out:
                for index, chunk in enumerate(chunks):
                    if chunk.offset < 0 or chunk.size < 1 or chunk.size > MAX_DOCUMENT or chunk.offset + chunk.size > len(raw):
                        raise PCBError("Invalid PCB chunk extent")
                    skip = 0
                    if index + 1 < len(chunks):
                        logical = chunks[index + 1].position - chunk.position
                        if logical <= 0 or logical > chunk.size:
                            raise PCBError("Invalid PCB position delta")
                        skip = chunk.size - logical
                        if skip:
                            if skip < 7 or skip > MAX_PREFIX + 7:
                                raise PCBError("Invalid PCB wrapper length")
                            tail = raw[chunk.offset + skip - 7:chunk.offset + skip]
                            marker = tail[0]
                            if (tail[2] != (marker ^ 0x11) or tail[4] != (marker ^ 0x11)
                                    or tail[6] != marker):
                                raise PCBError("PCB wrapper terminator damaged")
                            have_marker = True
                    elif have_marker:
                        skip = wrapper_skip(raw[chunk.offset:chunk.offset + min(chunk.size, MAX_PREFIX + 8)], marker)
                    if skip >= chunk.size or logical_offset != chunk.position - 1:
                        raise PCBError("PCB logical offsets do not match")
                    if index == 0:
                        if chunk.size - skip < len(MAGIC):
                            raise PCBError("PCB header truncated")
                        header = raw[chunk.offset + skip:chunk.offset + skip + len(MAGIC)]
                        if any((x ^ key) != m for x, m in zip(header, MAGIC)):
                            raise PCBError("PCB header is invalid after decoding")
                    content_length = chunk.size - skip
                    _write_xor(raw, chunk.offset + skip, content_length, key, out)
                    logical_offset += content_length
                    if logical_offset > MAX_DOCUMENT:
                        raise PCBError("PCB decoded file exceeds size limit")
    return _finish_file(destination)


def decode_stream_file(source: str | Path, destination: str | Path) -> int:
    # Stream-decode the unpositioned wire format to a new decoded file.
    with Path(source).open("rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            key, wrapped, marker = _begin(raw[:min(len(raw), MAX_PREFIX + 32)])
            read = 0
            written = 0
            with Path(destination).open("wb") as out:
                while read < len(raw):
                    remaining = len(raw) - read
                    skip = wrapper_skip(raw[read:read + min(remaining, MAX_PREFIX + 8)], marker) if wrapped else 0
                    part = min(remaining, skip + BLOCK_BYTES) if wrapped else remaining
                    if skip >= part:
                        raise PCBError("Empty PCB section")
                    _write_xor(raw, read + skip, part - skip, key, out)
                    read += part
                    written += part - skip
                    if written > MAX_DOCUMENT:
                        raise PCBError("Decoded PCB exceeds size limit")
    return _finish_file(destination)
