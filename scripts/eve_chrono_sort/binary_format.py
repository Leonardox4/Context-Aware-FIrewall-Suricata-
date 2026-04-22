"""On-disk (timestamp_ns, file_offset) records — 16 bytes, big-endian signed int64 pair."""

from __future__ import annotations

import struct
from typing import BinaryIO, Iterator, Optional, Tuple

PAIR_STRUCT = struct.Struct(">qq")  # ts_ns, offset
PAIR_SIZE = PAIR_STRUCT.size  # 16


def write_pair(f: BinaryIO, ts_ns: int, offset: int) -> None:
    f.write(PAIR_STRUCT.pack(ts_ns, offset))


def read_pair(f: BinaryIO) -> Optional[Tuple[int, int]]:
    b = f.read(PAIR_SIZE)
    if len(b) < PAIR_SIZE:
        return None
    return PAIR_STRUCT.unpack(b)


def iter_pairs(path: str) -> Iterator[Tuple[int, int]]:
    with open(path, "rb") as f:
        while True:
            p = read_pair(f)
            if p is None:
                break
            yield p
