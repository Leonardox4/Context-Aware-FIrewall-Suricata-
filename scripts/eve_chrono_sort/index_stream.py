"""Stream original JSONL lines in global time order using a sorted (ts, offset) index."""

from __future__ import annotations

from typing import BinaryIO, Iterator, Optional, Tuple

from .binary_format import PAIR_SIZE, read_pair


def iter_lines_from_sorted_index(
    original_path: str,
    sorted_index_path: str,
    pair_start: int,
    pair_end: int,
    buffer_size: int = 8 * 1024 * 1024,
) -> Iterator[bytes]:
    """
    Yield raw lines (including newline) for index pairs [pair_start, pair_end).

    pair_* are 0-based counts of 16-byte records in sorted_index_path.
    """
    if pair_start < 0 or pair_end < pair_start:
        raise ValueError("invalid pair range")
    with open(sorted_index_path, "rb", buffering=buffer_size) as fidx, open(
        original_path, "rb", buffering=buffer_size
    ) as fin:
        fidx.seek(pair_start * PAIR_SIZE)
        cur_pos: Optional[int] = None
        n = pair_end - pair_start
        for _ in range(n):
            p = read_pair(fidx)
            if p is None:
                break
            _, off = p
            if cur_pos is None or off != cur_pos:
                fin.seek(off)
            line = fin.readline()
            if not line:
                break
            cur_pos = off + len(line)
            yield line


def read_pair_at(sorted_index_path: str, pair_index: int) -> Optional[Tuple[int, int]]:
    with open(sorted_index_path, "rb") as f:
        f.seek(pair_index * PAIR_SIZE)
        return read_pair(f)
