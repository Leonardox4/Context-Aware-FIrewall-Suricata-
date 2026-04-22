"""Phase 4: worker manifests over sorted (ts,offset) index."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from .binary_format import PAIR_SIZE


def _equal_pair_ranges(n_pairs: int, workers: int) -> List[Tuple[int, int]]:
    if workers <= 0:
        raise ValueError("workers must be positive")
    if n_pairs < 0:
        raise ValueError("n_pairs must be non-negative")
    if workers > n_pairs and n_pairs > 0:
        workers = n_pairs
    if n_pairs == 0:
        return []
    base, rem = divmod(n_pairs, workers)
    out: List[Tuple[int, int]] = []
    s = 0
    for i in range(workers):
        sz = base + (1 if i < rem else 0)
        e = s + sz
        out.append((s, e))
        s = e
    return out


def build_index_pair_manifest(
    original_input: str,
    sorted_index_path: str,
    workers: int,
    warmup_pairs: int = 0,
    sorted_jsonl_path: Optional[str] = None,
) -> Dict[str, Any]:
    idx_sz = os.path.getsize(sorted_index_path)
    n_pairs = idx_sz // PAIR_SIZE
    ranges = _equal_pair_ranges(n_pairs, workers)

    parts: List[Dict[str, Any]] = []
    for wid, (emit_lo, emit_hi) in enumerate(ranges):
        wp = max(0, int(warmup_pairs))
        read_lo = max(0, emit_lo - wp)
        read_hi = emit_hi
        parts.append(
            {
                "worker_id": wid,
                "emit_pair_start": emit_lo,
                "emit_pair_end": emit_hi,
                "read_pair_start": read_lo,
                "read_pair_end": read_hi,
                "emit_line_count": emit_hi - emit_lo,
                "read_line_count": read_hi - read_lo,
            }
        )

    manifest: Dict[str, Any] = {
        "version": 1,
        "mode": "sorted_index_pairs",
        "pair_size_bytes": PAIR_SIZE,
        "original_input": os.path.abspath(original_input),
        "sorted_index": os.path.abspath(sorted_index_path),
        "total_pairs": n_pairs,
        "workers": parts,
    }
    if sorted_jsonl_path:
        manifest["sorted_jsonl"] = os.path.abspath(sorted_jsonl_path)
    return manifest


def write_manifest(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def suggest_warmup_pairs(lines_total: int, phase1_seconds: float, warmup_seconds: float) -> int:
    """Rough line count ~= (lines_total / phase1_elapsed) * warmup_seconds."""
    if warmup_seconds <= 0 or phase1_seconds <= 0 or lines_total <= 0:
        return 0
    rate = lines_total / phase1_seconds
    return max(0, int(rate * warmup_seconds))
