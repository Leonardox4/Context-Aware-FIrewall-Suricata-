"""
Fast timestamp extraction from Suricata EVE JSONL lines without full json.loads.

Strategies (first match wins, configurable order):
  - top-level "timestamp" string (ISO-8601)
  - numeric flow start (seconds since epoch, often float)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Callable, List, Optional

# Sentinel: lines with no parseable time sort near end (not at 2**63-1 to avoid int edge cases)
MISSING_TS_NS = (1 << 62)

# Top-level: "timestamp":"2020-01-01T12:00:00.123456+0000"
_RE_TIMESTAMP_STR = re.compile(
    rb'"timestamp"\s*:\s*"([^"]+)"',
    re.IGNORECASE,
)
# flow.start as number (common in Suricata flow records)
_RE_FLOW_START_NUM = re.compile(
    rb'"start"\s*:\s*([0-9]{9,16}(?:\.[0-9]+)?)',
    re.IGNORECASE,
)


def _iso_to_ns(s: str) -> Optional[int]:
    """Parse Suricata-style ISO timestamp to integer nanoseconds since Unix epoch."""
    s = s.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Suricata sometimes uses +0000 without colon
    if len(s) >= 5 and (s[-5] in "+-" and s[-4:].isdigit() and s[-5:-4] in "+-"):
        if s[-3] != ":":
            s = s[:-5] + s[-5:-2] + ":" + s[-2:]
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    sec = dt.timestamp()
    # ns (avoid float drift for sub-second)
    whole = int(sec)
    frac = sec - whole
    ns = whole * 1_000_000_000 + int(round(frac * 1e9))
    return ns


def _float_unix_to_ns(b: bytes) -> Optional[int]:
    try:
        x = float(b)
    except ValueError:
        return None
    if x > 1e12:  # already ms?
        x = x / 1000.0
    sec = int(x)
    frac = x - sec
    return sec * 1_000_000_000 + int(round(frac * 1e9))


def extract_ts_ns_timestamp(line: bytes) -> Optional[int]:
    m = _RE_TIMESTAMP_STR.search(line)
    if not m:
        return None
    try:
        raw = m.group(1).decode("utf-8", errors="replace")
    except Exception:
        return None
    return _iso_to_ns(raw)


def extract_ts_ns_flow_start(line: bytes) -> Optional[int]:
    m = _RE_FLOW_START_NUM.search(line)
    if not m:
        return None
    return _float_unix_to_ns(m.group(1))


def build_extractor_chain(field_order: List[str]) -> Callable[[bytes], Optional[int]]:
    """field_order entries: 'timestamp' | 'flow.start'"""
    funcs: List[Callable[[bytes], Optional[int]]] = []
    for name in field_order:
        n = name.strip().lower().replace("_", ".")
        if n in ("timestamp", "ts", "time"):
            funcs.append(extract_ts_ns_timestamp)
        elif n in ("flow.start", "flow_start", "start"):
            funcs.append(extract_ts_ns_flow_start)
        else:
            raise ValueError(f"Unknown timestamp field: {name!r} (use timestamp, flow.start)")

    def _chain(line: bytes) -> Optional[int]:
        for fn in funcs:
            v = fn(line)
            if v is not None:
                return v
        return None

    return _chain


def default_field_order() -> List[str]:
    return ["timestamp", "flow.start"]
