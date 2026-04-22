"""Phase 1: scan JSONL, extract (ts_ns, line_start_offset), write binary index."""

from __future__ import annotations

import os
from typing import Callable, Optional, Tuple

from .binary_format import PAIR_SIZE, write_pair
from .timestamp_extract import MISSING_TS_NS


def index_file(
    input_path: str,
    index_path: str,
    extract_ts_ns: Callable[[bytes], Optional[int]],
    buffer_size: int = 8 * 1024 * 1024,
    progress_every_bytes: int = 512 * 1024 * 1024,
    log: Optional[Callable[[str], None]] = None,
) -> Tuple[int, int, int, int, bool]:
    """Return lines_total, lines_indexed, lines_missing_ts, bytes_read, monotonic."""
    _log = log or (lambda s: None)

    lines_total = 0
    lines_missing_ts = 0
    bytes_read = 0
    prev_key = None
    monotonic = True
    next_progress = progress_every_bytes

    in_size = os.path.getsize(input_path)
    _log("Phase1: indexing %s (%.2f GB est.) -> %s" % (input_path, in_size / 1e9, index_path))

    fin = open(input_path, "rb", buffering=buffer_size)
    fidx = open(index_path, "wb", buffering=buffer_size)
    try:
        offset = 0
        while True:
            line = fin.readline()
            if not line:
                break
            lines_total += 1
            n = len(line)
            bytes_read += n

            ts = extract_ts_ns(line)
            if ts is None:
                lines_missing_ts += 1
                ts = MISSING_TS_NS

            write_pair(fidx, ts, offset)

            key = (ts, offset)
            if prev_key is not None and key < prev_key:
                monotonic = False
            prev_key = key

            offset += n

            if bytes_read >= next_progress:
                pct = 100.0 * bytes_read / max(in_size, 1)
                _log(
                    "Phase1: %.2f GiB scanned, %s lines, missing_ts=%s (%.1f%%)"
                    % (bytes_read / 1e9, f"{lines_total:,}", f"{lines_missing_ts:,}", pct)
                )
                next_progress += progress_every_bytes
    finally:
        fin.close()
        fidx.close()

    lines_indexed = lines_total
    _log(
        "Phase1: done lines=%s missing_ts=%s monotonic_in_file_order=%s index_bytes=%s"
        % (
            f"{lines_total:,}",
            f"{lines_missing_ts:,}",
            monotonic,
            f"{lines_total * PAIR_SIZE:,}",
        )
    )
    return lines_total, lines_indexed, lines_missing_ts, bytes_read, monotonic
