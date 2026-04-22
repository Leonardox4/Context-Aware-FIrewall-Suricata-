"""Phase 2: external sort of (ts_ns, offset) chunks + k-way merge."""

from __future__ import annotations

import heapq
import os
import tempfile
from typing import Callable, Iterator, List, Optional, Tuple

from .binary_format import read_pair, write_pair


def sort_index_external(
    index_path: str,
    sorted_index_path: str,
    chunk_lines: int,
    temp_dir: Optional[str],
    keep_chunks: bool = False,
    log: Optional[Callable[[str], None]] = None,
) -> Tuple[int, str]:
    """
    Read `index_path` (pairs), write sorted stream to `sorted_index_path`.
    Returns (num_chunks, temp_dir_used_or_empty).
    """
    _log = log or (lambda s: None)
    index_size = os.path.getsize(index_path)
    approx_lines = index_size // 16  # PAIR_SIZE
    _log(
        f"Phase2: external sort index_size={index_size:,} bytes (~{approx_lines:,} lines), "
        f"chunk_lines={chunk_lines:,}"
    )

    tmp = temp_dir or tempfile.mkdtemp(prefix="eve_chrono_sort_")
    os.makedirs(tmp, exist_ok=True)

    chunk_files: List[str] = []
    buf: List[Tuple[int, int]] = []

    def flush_chunk(idx: int) -> None:
        nonlocal buf
        if not buf:
            return
        buf.sort(key=lambda t: (t[0], t[1]))
        path = os.path.join(tmp, f"chunk_{idx:06d}.bin")
        with open(path, "wb", buffering=8 * 1024 * 1024) as f:
            for ts, off in buf:
                write_pair(f, ts, off)
        chunk_files.append(path)
        buf = []

    chunk_idx = 0
    with open(index_path, "rb", buffering=8 * 1024 * 1024) as fin:
        while True:
            p = read_pair(fin)
            if p is None:
                break
            buf.append(p)
            if len(buf) >= chunk_lines:
                flush_chunk(chunk_idx)
                chunk_idx += 1
        flush_chunk(chunk_idx)

    num_chunks = len(chunk_files)
    if num_chunks == 0:
        open(sorted_index_path, "wb").close()
        _log("Phase2: empty index -> empty sorted index")
        if not keep_chunks:
            try:
                os.rmdir(tmp)
            except OSError:
                pass
        return 0, ""

    _log(f"Phase2: wrote {num_chunks} sorted chunks under {tmp}")

    def iter_chunk(path: str) -> Iterator[Tuple[int, int]]:
        with open(path, "rb", buffering=8 * 1024 * 1024) as f:
            while True:
                p = read_pair(f)
                if p is None:
                    break
                yield p

    with open(sorted_index_path, "wb", buffering=8 * 1024 * 1024) as fout:
        if num_chunks == 1:
            merged = iter_chunk(chunk_files[0])
        else:
            iters = [iter_chunk(p) for p in chunk_files]
            # Tuples compare lexicographically; each chunk sorted by (ts_ns, offset).
            merged = heapq.merge(*iters)

        written = 0
        for ts, off in merged:
            write_pair(fout, ts, off)
            written += 1
            if written and written % 5_000_000 == 0:
                _log(f"Phase2: merge wrote {written:,} pairs...")

    _log(f"Phase2: merge complete -> {sorted_index_path} ({os.path.getsize(sorted_index_path):,} bytes)")

    if not keep_chunks:
        for p in chunk_files:
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass
        return num_chunks, ""

    return num_chunks, tmp
