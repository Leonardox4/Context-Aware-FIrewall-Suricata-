"""
Sliding-window behavioral feature extractor for runtime pipeline.

Produces additional features from per-src_ip and per-dst_ip state with O(1)
amortized updates and bounded memory (LRU eviction). Windows: 10s (burst),
30s (scan), 60s (brute force), 120s (DDoS). Used for logging and optional
multiclass RF; existing binary RF and IF use only the canonical 24 features.
"""

from __future__ import annotations

import ipaddress
from collections import deque
from typing import Any, Dict, List, Tuple

try:
    import pandas as pd
except ImportError:
    pd = None  # type: ignore

# Feature names produced by this module (order fixed for downstream)
BEHAVIORAL_FEATURE_NAMES: List[str] = [
    "src_flow_count_60s",
    "src_unique_dst_ports_60s",
    "src_unique_dst_ips_60s",
    "same_src_dst_port_count_60s",
    "dst_unique_src_120s",
    "is_internal_src",
    "is_internal_dst",
    "is_same_subnet",
    "tcp_flag_score",
]

# Window lengths in seconds (for documentation; actual windows are 60s and 120s for the requested features)
WINDOW_60S = 60.0
WINDOW_120S = 120.0

# Default max entries per key (bounded memory)
DEFAULT_MAX_SRC_ENTRIES = 50_000
DEFAULT_MAX_DST_ENTRIES = 50_000


def _is_private_ip(ip_str: str) -> bool:
    """True if IPv4 private (10/8, 172.16/12, 192.168/16)."""
    if not ip_str or ip_str.strip() in ("", "UNKNOWN"):
        return False
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return addr.is_private
    except Exception:
        return False


def _same_subnet(src_ip: str, dst_ip: str, prefix_bits: int = 24) -> bool:
    """True if both are valid IPv4 and in same subnet (default /24)."""
    if not src_ip or not dst_ip or src_ip.strip() in ("", "UNKNOWN") or dst_ip.strip() in ("", "UNKNOWN"):
        return False
    try:
        a = ipaddress.ip_address(src_ip.strip())
        b = ipaddress.ip_address(dst_ip.strip())
        if a.version != 4 or b.version != 4:
            return False
        na = ipaddress.ip_network(f"{a}/{prefix_bits}", strict=False)
        nb = ipaddress.ip_network(f"{b}/{prefix_bits}", strict=False)
        return na == nb
    except Exception:
        return False


def _tcp_flag_score_from_ev(ev: Dict[str, Any]) -> float:
    """
    Heuristic score [0,1] from TCP flags. SYN-only / RST → higher (scan-like).
    Uses eve 'tcp' block (Suricata parses syn, ack, fin, rst, psh).
    """
    tcp = ev.get("tcp") or {}
    syn = bool(tcp.get("syn"))
    ack = bool(tcp.get("ack"))
    fin = bool(tcp.get("fin"))
    rst = bool(tcp.get("rst"))
    # SYN-only (typical scan): high
    if syn and not ack and not fin:
        return 0.9
    if rst:
        return 0.5
    if syn and ack:
        return 0.2
    return 0.1


def _safe_str(v: Any) -> str:
    return str(v).strip() if v is not None else ""


class _SlidingWindowEntry:
    """Per-key sliding window: (ts, dst_port, dst_ip) with O(1) add and bounded unique counts."""

    __slots__ = ("deque_60", "deque_120", "ports_60", "ips_60", "srcs_120", "max_ts_60", "max_ts_120")

    def __init__(self) -> None:
        self.deque_60: deque = deque()  # (ts, dst_port, dst_ip) for 60s
        self.deque_120: deque = deque()  # (ts, src_ip) for 120s (dst entry stores src_ips)
        self.ports_60: Dict[Any, int] = {}  # count per port (for unique)
        self.ips_60: Dict[str, int] = {}   # count per ip (for unique)
        self.srcs_120: Dict[str, int] = {}  # count per src_ip (for dst_unique_src_120s)
        self.max_ts_60 = 0.0
        self.max_ts_120 = 0.0

    def add_60(self, ts: float, dst_port: int, dst_ip: str) -> None:
        self.deque_60.append((ts, dst_port, dst_ip))
        self.ports_60[dst_port] = self.ports_60.get(dst_port, 0) + 1
        self.ips_60[dst_ip] = self.ips_60.get(dst_ip, 0) + 1
        self.max_ts_60 = max(self.max_ts_60, ts)
        while self.deque_60 and self.deque_60[0][0] < ts - WINDOW_60S:
            _, p, ip = self.deque_60.popleft()
            self.ports_60[p] = self.ports_60.get(p, 1) - 1
            if self.ports_60[p] <= 0:
                del self.ports_60[p]
            self.ips_60[ip] = self.ips_60.get(ip, 1) - 1
            if self.ips_60[ip] <= 0:
                del self.ips_60[ip]

    def add_120_src(self, ts: float, src_ip: str) -> None:
        """For dst entry: record a source IP in 120s window."""
        self.deque_120.append((ts, src_ip))
        self.srcs_120[src_ip] = self.srcs_120.get(src_ip, 0) + 1
        self.max_ts_120 = max(self.max_ts_120, ts)
        while self.deque_120 and self.deque_120[0][0] < ts - WINDOW_120S:
            _, s = self.deque_120.popleft()
            self.srcs_120[s] = self.srcs_120.get(s, 1) - 1
            if self.srcs_120[s] <= 0:
                del self.srcs_120[s]

    def flow_count_60(self) -> int:
        return len(self.deque_60)

    def unique_ports_60(self) -> int:
        return len(self.ports_60)

    def unique_ips_60(self) -> int:
        return len(self.ips_60)

    def unique_srcs_120(self) -> int:
        return len(self.srcs_120)


class _SameSrcDstPortCounter:
    """Count (src_ip, dst_port) in 60s window for same_src_dst_port_count_60s."""

    __slots__ = ("deque", "key_count", "max_ts")

    def __init__(self) -> None:
        self.deque: deque = deque()  # (ts, key)
        self.key_count: Dict[str, int] = {}
        self.max_ts = 0.0

    def add(self, ts: float, src_ip: str, dst_port: int) -> None:
        key = f"{src_ip}|{dst_port}"
        self.deque.append((ts, key))
        self.key_count[key] = self.key_count.get(key, 0) + 1
        self.max_ts = max(self.max_ts, ts)
        while self.deque and self.deque[0][0] < ts - WINDOW_60S:
            _, k = self.deque.popleft()
            self.key_count[k] = self.key_count.get(k, 1) - 1
            if self.key_count[k] <= 0:
                del self.key_count[k]

    def count(self, src_ip: str, dst_port: int) -> int:
        return self.key_count.get(f"{src_ip}|{dst_port}", 0)


def _ts_from_ev(ev: Dict[str, Any]) -> float:
    """Extract epoch seconds from eve event."""
    ts = ev.get("timestamp")
    if ts is None:
        flow = ev.get("flow") or {}
        ts = flow.get("start") or flow.get("end")
    if ts is None:
        return 0.0
    if pd is None:
        return 0.0
    try:
        t = pd.to_datetime(ts, errors="coerce", utc=True)
        if pd.isna(t):
            return 0.0
        return float(t.value) / 1e9
    except Exception:
        return 0.0


class BehavioralFeatureExtractor:
    """
    Stateful extractor: call update(ev) per event, then get_features() for the last event,
    or update_batch(events) and get_batch_features() for a chunk. Bounded memory via LRU.
    """

    def __init__(
        self,
        max_src_entries: int = DEFAULT_MAX_SRC_ENTRIES,
        max_dst_entries: int = DEFAULT_MAX_DST_ENTRIES,
    ) -> None:
        self._max_src = max_src_entries
        self._max_dst = max_dst_entries
        self._src: Dict[str, _SlidingWindowEntry] = {}
        self._dst: Dict[str, _SlidingWindowEntry] = {}
        self._same_src_dst_port: _SameSrcDstPortCounter = _SameSrcDstPortCounter()
        self._order: List[str] = []  # LRU for src
        self._order_dst: List[str] = []  # LRU for dst

    def _get_or_create_src(self, src_ip: str) -> _SlidingWindowEntry:
        if src_ip not in self._src:
            while len(self._src) >= self._max_src and self._order:
                evict = self._order.pop(0)
                if evict in self._src:
                    del self._src[evict]
            self._src[src_ip] = _SlidingWindowEntry()
            self._order.append(src_ip)
        else:
            self._order.remove(src_ip)
            self._order.append(src_ip)
        return self._src[src_ip]

    def _get_or_create_dst(self, dst_ip: str) -> _SlidingWindowEntry:
        if dst_ip not in self._dst:
            while len(self._dst) >= self._max_dst and self._order_dst:
                evict = self._order_dst.pop(0)
                if evict in self._dst:
                    del self._dst[evict]
            self._dst[dst_ip] = _SlidingWindowEntry()
            self._order_dst.append(dst_ip)
        else:
            self._order_dst.remove(dst_ip)
            self._order_dst.append(dst_ip)
        return self._dst[dst_ip]

    def update(self, ev: Dict[str, Any]) -> Dict[str, float]:
        """
        Update state with one event and return the 9 behavioral features for this event.
        O(1) amortized. Event must have src_ip, dest_ip, src_port, dest_port, proto.
        """
        src_ip = _safe_str(ev.get("src_ip", "")) or "UNKNOWN"
        dst_ip = _safe_str(ev.get("dest_ip", "")) or "UNKNOWN"
        src_port = int(ev.get("src_port") or 0)
        dst_port = int(ev.get("dest_port") or 0)
        ts = _ts_from_ev(ev)

        src_entry = self._get_or_create_src(src_ip)
        dst_entry = self._get_or_create_dst(dst_ip)

        src_entry.add_60(ts, dst_port, dst_ip)
        dst_entry.add_120_src(ts, src_ip)
        self._same_src_dst_port.add(ts, src_ip, dst_port)

        return {
            "src_flow_count_60s": float(src_entry.flow_count_60()),
            "src_unique_dst_ports_60s": float(src_entry.unique_ports_60()),
            "src_unique_dst_ips_60s": float(src_entry.unique_ips_60()),
            "same_src_dst_port_count_60s": float(self._same_src_dst_port.count(src_ip, dst_port)),
            "dst_unique_src_120s": float(dst_entry.unique_srcs_120()),
            "is_internal_src": 1.0 if _is_private_ip(src_ip) else 0.0,
            "is_internal_dst": 1.0 if _is_private_ip(dst_ip) else 0.0,
            "is_same_subnet": 1.0 if _same_subnet(src_ip, dst_ip) else 0.0,
            "tcp_flag_score": _tcp_flag_score_from_ev(ev),
        }

    def update_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, float]]:
        """Update state for each event and return list of 9-feature dicts (same order as events)."""
        return [self.update(ev) for ev in events]


def behavioral_features_to_row(feature_dict: Dict[str, float]) -> List[float]:
    """Return a list of values in BEHAVIORAL_FEATURE_NAMES order."""
    return [float(feature_dict.get(k, 0.0)) for k in BEHAVIORAL_FEATURE_NAMES]
