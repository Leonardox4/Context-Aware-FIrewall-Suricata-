"""
EVE input handle for training: **single-pass** flow JSONL (raw Suricata).

TCP flags are read only from the optional ``tcp`` object on each **flow** event.
There is no two-pass ``tcp_agg`` preprocessor and no dependence on ``event_type=="tcp"``.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


@dataclass(frozen=True)
class EveWork:
    """Path to EVE JSONL consumed by Rust/Python extractors (one streaming pass)."""

    path: Path


@contextlib.contextmanager
def enhanced_eve_file_context(
    raw_eve: Path,
    *,
    legacy_raw_stream: bool = True,
    tmp_dir: Optional[Path] = None,
    force_temp_enhanced: bool = False,
):
    """
    Yields :class:`EveWork` pointing at ``raw_eve``.

    ``legacy_raw_stream``, ``tmp_dir``, and ``force_temp_enhanced`` are kept for call-site
    compatibility but are ignored (no temporary enhanced JSONL).
    """
    _ = legacy_raw_stream
    _ = tmp_dir
    _ = force_temp_enhanced
    yield EveWork(path=Path(raw_eve))


def iter_enhanced_flow_lines(path: Path) -> Iterator[str]:
    """Yield non-empty JSONL lines from ``path`` (same as raw EVE scan)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield line
