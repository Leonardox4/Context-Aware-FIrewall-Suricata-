"""Phase 3: follow sorted (ts, offset) pairs; seek/read from original JSONL; write sorted output."""

from __future__ import annotations

import os
from typing import Callable, Optional, Tuple

from .binary_format import read_pair


def rebuild_sorted_jsonl(
    input_path: str,
    sorted_index_path: str,
    output_path: str,
    buffer_size: int = 8 * 1024 * 1024,
    progress_every_pairs: int = 2_000_000,
    log: Optional[Callable[[str], None]] = None,
) -> Tuple[int, int]:
    """
    Returns (pairs_processed, output_bytes).
    Seeks in original file; batches sequential reads when offsets chain forward.
    """
    _log = log or (lambda s: None)
    in_size = os.path.getsize(input_path)
    _log(f"Phase3: rebuild {input_path} using {sorted_index_path} -> {output_path}")

    pairs_done = 0
    out_bytes = 0
    next_log = progress_every_pairs

    with open(input_path, "rb", buffering=buffer_size) as fin, open(
        sorted_index_path, "rb", buffering=buffer_size
    ) as fidx, open(output_path, "wb", buffering=buffer_size) as fout:
        cur_pos: Optional[int] = None

        while True:
            p = read_pair(fidx)
            if p is None:
                break
            _, off = p
            pairs_done += 1

            if cur_pos is None or off != cur_pos:
                fin.seek(off)
            line = fin.readline()
            if not line:
                _log(f"Phase3: WARN empty read at offset {off} (EOF?) pair#{pairs_done}")
                cur_pos = fin.tell()
                continue

            fout.write(line)
            out_bytes += len(line)
            cur_pos = off + len(line)

            if pairs_done >= next_log:
                pct = 100.0 * off / max(in_size, 1)
                _log(
                    f"Phase3: {pairs_done:,} lines written, {out_bytes / 1e9:.2f} GiB out "
                    f"(last_src_offset ~{pct:.1f}% into input)"
                )
                next_log += progress_every_pairs

    _log(f"Phase3: done pairs={pairs_done:,} out_bytes={out_bytes:,}")
    return pairs_done, out_bytes
