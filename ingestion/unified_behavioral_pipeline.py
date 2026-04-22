"""
Unified Behavioral Pipeline: extract UNIFIED_BEHAVIORAL_FEATURE_NAMES from Suricata EVE **flow** records
with 60s/120s/300s windows and SanityCheck (flow-stream state only).

High-throughput design: optional netflow pass can refine rhythm fields when netflow EVE is present.

- Sliding-window state (60s and 120s) with cleanup for bounded memory.
- SanityCheck: no NaN/Inf (impute 0), bounds (e.g. src_pkts_ratio in [0,1]), float64.
- Output: CSV or Parquet for downstream ML. Ground-truth augmentation: join features with labeled CSVs.
"""

from __future__ import annotations

import csv
import gc
import json
import logging
import sys
from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ingestion.flow_identity import flow_key_with_time_bucket
from ingestion.identity_key import IDENTITY_KEY_COL, identity_key_for_eve_flow, identity_key_from_label_csv_row
from ingestion.src_ip_temporal_features import SrcIpTemporalTracker
from ingestion.unified_behavioral_schema import (
    DEFAULT_FILL,
    FEATURE_BOUNDS,
    UNIFIED_BEHAVIORAL_FEATURE_NAMES,
)
from ingestion.flow_tcp_behavioral_engine import FlowTcpBehavioralEngine

logger = logging.getLogger(__name__)

WINDOW_60_SEC = 60.0
WINDOW_120_SEC = 120.0
WINDOW_300_SEC = 300.0
# Amortized full-map prune: avoids O(n_keys) work on every flow (major bottleneck on large EVE).
DEFAULT_GLOBAL_CLEANUP_INTERVAL = 4096
LABEL_KEY = "label"
FLOW_KEY_COL = "flow_key"
TIMESTAMP_COL = "timestamp_epoch"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        x = float(val)
        return x if np.isfinite(x) else default
    except (TypeError, ValueError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(float(val))
    except (TypeError, ValueError):
        return default


def flow_event_sort_key(ev: Dict[str, Any]) -> Tuple[float, str, str, str, int, int]:
    """Stable ordering for chunked EVE processing (deterministic scores for duplicate timestamps)."""
    fid = ev.get("flow_id")
    fid_s = "" if fid is None else str(fid)
    return (
        _ts_from_ev(ev),
        fid_s,
        str(ev.get("src_ip", "") or ""),
        str(ev.get("dest_ip", "") or ""),
        _safe_int(ev.get("src_port", 0)),
        _safe_int(ev.get("dest_port", 0)),
    )


def _ts_from_ev(ev: Dict[str, Any]) -> float:
    flow = ev.get("flow") or {}
    raw = flow.get("start") or flow.get("end") or ev.get("timestamp")
    if raw is None:
        return 0.0
    try:
        if isinstance(raw, (int, float)):
            return float(raw)
        s = str(raw).replace("Z", "+00:00").strip()
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


def shannon_entropy_numpy(arr: np.ndarray) -> float:
    if arr is None or arr.size == 0:
        return 0.0
    arr = np.asarray(arr).ravel()
    if arr.size == 0:
        return 0.0
    _, counts = np.unique(arr, return_counts=True)
    probs = counts.astype(np.float64) / arr.size
    probs = probs[probs > 0]
    if probs.size == 0:
        return 0.0
    return float(-np.sum(probs * np.log2(probs)))


def entropy_of_set(values: List[Any]) -> float:
    if not values:
        return 0.0
    arr = np.array(values, dtype=np.float64)
    return shannon_entropy_numpy(arr)


def _service_class(dst_port: int, proto: str) -> str:
    """
    Classify flow into http, dns, ssh, or other from destination port and protocol.
    Used for 60s-window service_freq_* counts. Only TCP/UDP ports are classified.
    """
    proto = (proto or "").strip().upper()
    if dst_port == 53:
        return "dns"
    if dst_port == 22:
        return "ssh"
    if proto == "TCP" and dst_port in (80, 443, 8080, 8000, 8443):
        return "http"
    return "other"


# -----------------------------------------------------------------------------
# SanityCheck: no NaN/Inf, bounds, float64
# -----------------------------------------------------------------------------


class SanityCheck:
    """
    Validate and fix feature vectors before output: impute NaN/Inf, enforce bounds, ensure float64.
    """

    def __init__(
        self,
        feature_names: List[str],
        bounds: Optional[Dict[str, Tuple[Optional[float], Optional[float]]]] = None,
        fill: float = DEFAULT_FILL,
    ) -> None:
        self.feature_names = list(feature_names)
        self.bounds = bounds or {}
        self.fill = fill

    def check_and_fix(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Return a new dict with all feature values valid (finite float64, within bounds)."""
        out = {}
        for k in self.feature_names:
            v = row.get(k)
            if v is None or (isinstance(v, float) and not np.isfinite(v)):
                v = self.fill
            else:
                try:
                    v = float(v)
                except (TypeError, ValueError):
                    v = self.fill
            if not np.isfinite(v):
                v = self.fill
            lo, hi = self.bounds.get(k, (None, None))
            if lo is not None and v < lo:
                v = lo
            if hi is not None and v > hi:
                v = hi
            out[k] = np.float64(v)
        return out

    def to_vector(self, row: Dict[str, Any]) -> np.ndarray:
        """Return (n_features,) float64 array in schema order."""
        fixed = self.check_and_fix(row)
        return np.array([fixed[k] for k in self.feature_names], dtype=np.float64)


# -----------------------------------------------------------------------------
# BehavioralExtractor: 60s and 120s sliding windows
# -----------------------------------------------------------------------------


class BehavioralExtractorUnified:
    """
    Rolling 60s and 120s windows for Context 60s and Long-Term Context features.
    Prunes records older than window to keep memory bounded.

    Performance:
    - Per-flow work uses lazy pruning for only the touched src_ip/dst_ip (not a full map scan).
    - A periodic global prune (every ``global_cleanup_interval`` ``add()`` calls) reclaims
      stale entries for IPs that are no longer observed, preserving bounded memory and
      matching the semantics of the previous eager global cleanup asymptotically.
    - FIFO eviction uses ``OrderedDict`` for O(1) pop/evict (lists were O(n) for pop(0)/remove).
    """

    def __init__(
        self,
        window_60: float = WINDOW_60_SEC,
        window_120: float = WINDOW_120_SEC,
        max_src_entries: int = 100_000,
        max_dst_entries: int = 100_000,
        global_cleanup_interval: int = DEFAULT_GLOBAL_CLEANUP_INTERVAL,
    ) -> None:
        self._w60 = window_60
        self._w120 = window_120
        self._max_src = max_src_entries
        self._max_dst = max_dst_entries
        self._global_cleanup_interval = max(1, int(global_cleanup_interval))
        self._add_calls = 0
        # src_ip -> deque of (ts, src_port, dst_port, dst_ip, bytes_total, pkts_total, service_class)
        # service_class: "http" | "dns" | "ssh" | "other"
        self._src_60: Dict[str, deque] = {}
        self._src_120: Dict[str, deque] = {}
        # FIFO of src_ips for cap eviction (first-seen order; do not refresh on reuse).
        self._src_fifo: "OrderedDict[str, None]" = OrderedDict()
        self._dst_60: Dict[str, deque] = {}
        self._dst_fifo: "OrderedDict[str, None]" = OrderedDict()

    def _cleanup_global(self, now: float) -> None:
        """Scan all keys and drop expired deque entries (expensive; call rarely)."""
        c60 = now - self._w60
        c120 = now - self._w120
        # Match legacy two-pass semantics: 60s deque may be empty while 120s still holds
        # flows in (now-120s, now-60s); do not remove _src_120 in the first pass.
        for key in list(self._src_60.keys()):
            dq = self._src_60[key]
            while dq and dq[0][0] < c60:
                dq.popleft()
            if not dq:
                self._src_60.pop(key, None)
                self._src_fifo.pop(key, None)
        for key in list(self._src_120.keys()):
            dq = self._src_120[key]
            while dq and dq[0][0] < c120:
                dq.popleft()
            if not dq:
                self._src_120.pop(key, None)
        for key in list(self._dst_60.keys()):
            dq = self._dst_60[key]
            while dq and dq[0][0] < c60:
                dq.popleft()
            if not dq:
                self._dst_60.pop(key, None)
                self._dst_fifo.pop(key, None)

    def _prune_src(self, src_ip: str, now: float) -> None:
        """Drop expired records for one src_ip; remove empty keys from maps and FIFO."""
        c60 = now - self._w60
        c120 = now - self._w120
        dq60 = self._src_60.get(src_ip)
        dq120 = self._src_120.get(src_ip)
        if dq60 is not None:
            while dq60 and dq60[0][0] < c60:
                dq60.popleft()
            if not dq60:
                self._src_60.pop(src_ip, None)
                self._src_fifo.pop(src_ip, None)
        if dq120 is not None:
            while dq120 and dq120[0][0] < c120:
                dq120.popleft()
            if not dq120:
                self._src_120.pop(src_ip, None)

    def _prune_dst(self, dst_ip: str, now: float) -> None:
        c60 = now - self._w60
        dq = self._dst_60.get(dst_ip)
        if dq is None:
            return
        while dq and dq[0][0] < c60:
            dq.popleft()
        if not dq:
            self._dst_60.pop(dst_ip, None)
            self._dst_fifo.pop(dst_ip, None)

    def _ensure_src(self, src_ip: str) -> Tuple[deque, deque]:
        if src_ip not in self._src_60:
            while len(self._src_60) >= self._max_src and self._src_fifo:
                evict, _ = self._src_fifo.popitem(last=False)
                self._src_60.pop(evict, None)
                self._src_120.pop(evict, None)
            self._src_60[src_ip] = deque()
            self._src_120[src_ip] = deque()
            self._src_fifo[src_ip] = None
        return self._src_60[src_ip], self._src_120[src_ip]

    def _ensure_dst(self, dst_ip: str) -> deque:
        if dst_ip not in self._dst_60:
            while len(self._dst_60) >= self._max_dst and self._dst_fifo:
                evict, _ = self._dst_fifo.popitem(last=False)
                self._dst_60.pop(evict, None)
            self._dst_60[dst_ip] = deque()
            self._dst_fifo[dst_ip] = None
        return self._dst_60[dst_ip]

    def add(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        bytes_total: int,
        pkts_total: int,
        service_class: str,
        failed: float,
    ) -> None:
        """
        Append flow to 60s/120s windows.

        service_class must be one of http, dns, ssh, other.
        failed is a 0/1 float indicating whether the flow looks like a failed connection
        (SYN scan / unanswered probes / port probing).
        """
        self._add_calls += 1
        if self._add_calls % self._global_cleanup_interval == 0:
            self._cleanup_global(ts)
        self._prune_src(src_ip, ts)
        self._prune_dst(dst_ip, ts)
        rec = (ts, src_port, dst_port, dst_ip, bytes_total, pkts_total, service_class, float(failed))
        dq60, dq120 = self._ensure_src(src_ip)
        dq60.append(rec)
        dq120.append(rec)
        self._ensure_dst(dst_ip).append(rec)

    def get_context_60s_and_120s(self, ev: Dict[str, Any]) -> Dict[str, float]:
        """
        Compute Context 60s (8) and Long-Term (1) features before adding this flow.
        Record layout: (ts, src_port, dst_port, dst_ip, bytes_total, pkts_total, service_class, failed_flag).

        ``failed_connection_ratio`` is (failed flows in 60s window **including this event**) /
        (flows in window **including this event**), so repeated SSH failures accumulate in the ratio
        monotonically toward 1.0 as the window fills with failed attempts.
        """
        ts = _ts_from_ev(ev)
        src_ip = str(ev.get("src_ip", "")).strip() or "UNKNOWN"
        dst_ip = str(ev.get("dest_ip", "")).strip() or "UNKNOWN"
        self._prune_src(src_ip, ts)
        self._prune_dst(dst_ip, ts)
        dq60_src = self._src_60.get(src_ip)
        dq120_src = self._src_120.get(src_ip)
        dq60_dst = self._dst_60.get(dst_ip)
        n60_src = len(dq60_src) if dq60_src else 0
        n120_src = len(dq120_src) if dq120_src else 0
        n60_dst = len(dq60_dst) if dq60_dst else 0
        cur_failed = 1.0 if _is_failed_connection(ev) >= 0.5 else 0.0
        if dq60_src:
            # Distinct port counts in 60s window for this src_ip
            src_port_count_60s = len(set(r[1] for r in dq60_src))
            dst_port_count_60s = len(set(r[2] for r in dq60_src))
            # Service counts in 60s window (count of flows per service class)
            service_freq_http = float(sum(1 for r in dq60_src if r[6] == "http"))
            service_freq_dns = float(sum(1 for r in dq60_src if r[6] == "dns"))
            service_freq_ssh = float(sum(1 for r in dq60_src if r[6] == "ssh"))
            service_freq_other = float(sum(1 for r in dq60_src if r[6] == "other"))

            # Recon/scan contextual features (60s window per src_ip)
            unique_dst_ips_60s = float(len(set(r[3] for r in dq60_src)))
            failed_flows_60s = float(sum(1 for r in dq60_src if r[7] >= 0.5))
            denom = float(n60_src + 1)
            failed_connection_ratio = (failed_flows_60s + cur_failed) / denom if denom > 0 else 0.0
        else:
            src_port_count_60s = 0
            dst_port_count_60s = 0
            service_freq_http = 0.0
            service_freq_dns = 0.0
            service_freq_ssh = 0.0
            service_freq_other = 0.0
            unique_dst_ips_60s = 0.0
            failed_connection_ratio = cur_failed
        dns_flow_ratio_per_src = (
            float(service_freq_dns / n60_src) if n60_src > 0 else 0.0
        )
        return {
            "src_ip_flow_count_60s": float(n60_src),
            "dst_ip_flow_count_60s": float(n60_dst),
            "src_port_count_60s": float(src_port_count_60s),
            "dst_port_count_60s": float(dst_port_count_60s),
            "service_freq_http": service_freq_http,
            "service_freq_dns": service_freq_dns,
            "service_freq_ssh": service_freq_ssh,
            "service_freq_other": service_freq_other,
            "src_flow_count_120s": float(n120_src),
            "failed_connection_ratio": failed_connection_ratio,
            "unique_dst_ips_60s": unique_dst_ips_60s,
            "dns_flow_ratio_per_src": min(1.0, max(0.0, dns_flow_ratio_per_src)),
        }


class DstPortVariance300Tracker:
    """
    Per-src_ip sliding 300s window of (ts, dst_port). Population variance of dst_port;
    <2 samples after prune -> 0.0. Matches Rust np_var_population (ddof=0).
    """

    def __init__(
        self,
        window_sec: float = WINDOW_300_SEC,
        max_src_entries: int = 100_000,
        global_cleanup_interval: int = DEFAULT_GLOBAL_CLEANUP_INTERVAL,
    ) -> None:
        self._w = window_sec
        self._max_src = max_src_entries
        self._global_cleanup_interval = max(1, int(global_cleanup_interval))
        self._op_count = 0
        self._src: Dict[str, deque] = {}
        self._fifo: "OrderedDict[str, None]" = OrderedDict()

    def _cleanup_global(self, now: float) -> None:
        cutoff = now - self._w
        for src in list(self._src.keys()):
            dq = self._src[src]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                self._src.pop(src, None)
                self._fifo.pop(src, None)

    def _maybe_global(self, now: float) -> None:
        self._op_count += 1
        if self._op_count % self._global_cleanup_interval == 0:
            self._cleanup_global(now)

    def _prune_src(self, src_ip: str, now: float) -> None:
        cutoff = now - self._w
        dq = self._src.get(src_ip)
        if dq is None:
            return
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if not dq:
            self._src.pop(src_ip, None)
            self._fifo.pop(src_ip, None)

    def variance_before(self, ts: float, src_ip: str) -> float:
        """Variance of dst_port in window before adding the current flow."""
        self._maybe_global(ts)
        self._prune_src(src_ip, ts)
        dq = self._src.get(src_ip)
        if not dq or len(dq) < 2:
            return 0.0
        ports = np.array([r[1] for r in dq], dtype=np.float64)
        return float(np.var(ports))

    def add(self, ts: float, src_ip: str, dst_port: int) -> None:
        self._maybe_global(ts)
        self._prune_src(src_ip, ts)
        if src_ip not in self._src:
            while len(self._src) >= self._max_src and self._fifo:
                evict, _ = self._fifo.popitem(last=False)
                self._src.pop(evict, None)
            self._src[src_ip] = deque()
            self._fifo[src_ip] = None
        self._src[src_ip].append((ts, dst_port))


def _welford_add_delta(n: int, mean: float, m2: float, x: float) -> Tuple[int, float, float]:
    n_new = n + 1
    delta = x - mean
    mean_new = mean + delta / n_new
    delta2 = x - mean_new
    m2_new = m2 + delta * delta2
    return n_new, mean_new, m2_new


def _welford_remove_delta(n: int, mean: float, m2: float, x: float) -> Tuple[int, float, float]:
    if n <= 1:
        return 0, 0.0, 0.0
    n_new = n - 1
    mean_new = (n * mean - x) / n_new
    m2_new = m2 - (x - mean) * (x - mean_new)
    return n_new, mean_new, max(0.0, m2_new)


class FlowInterarrivalVariance300Tracker:
    """
    Per-src_ip: flow start timestamps in 300s window; population variance of inter-arrival
    deltas via incremental add/remove (no full recompute).
    """

    def __init__(
        self,
        window_sec: float = WINDOW_300_SEC,
        max_src_entries: int = 100_000,
        global_cleanup_interval: int = DEFAULT_GLOBAL_CLEANUP_INTERVAL,
    ) -> None:
        self._w = window_sec
        self._max_src = max_src_entries
        self._global_cleanup_interval = max(1, int(global_cleanup_interval))
        self._op_count = 0
        self._ts: Dict[str, deque] = {}
        self._deltas: Dict[str, deque] = {}
        self._wn: Dict[str, int] = {}
        self._wmean: Dict[str, float] = {}
        self._wm2: Dict[str, float] = {}
        self._fifo: "OrderedDict[str, None]" = OrderedDict()

    def _cleanup_global(self, now: float) -> None:
        for src in list(self._ts.keys()):
            self._prune_src(src, now)

    def _maybe_global(self, now: float) -> None:
        self._op_count += 1
        if self._op_count % self._global_cleanup_interval == 0:
            self._cleanup_global(now)

    def _prune_src(self, src_ip: str, now: float) -> None:
        cutoff = now - self._w
        ts_dq = self._ts.get(src_ip)
        if ts_dq is None:
            return
        delta_dq = self._deltas.get(src_ip)
        while ts_dq and ts_dq[0] < cutoff:
            ts_dq.popleft()
            if delta_dq and len(delta_dq) > 0:
                d0 = delta_dq.popleft()
                n0 = self._wn.get(src_ip, 0)
                mn0 = self._wmean.get(src_ip, 0.0)
                m20 = self._wm2.get(src_ip, 0.0)
                nn, mm, m2n = _welford_remove_delta(n0, mn0, m20, d0)
                self._wn[src_ip] = nn
                self._wmean[src_ip] = mm
                self._wm2[src_ip] = m2n
        if not ts_dq:
            self._ts.pop(src_ip, None)
            self._deltas.pop(src_ip, None)
            self._wn.pop(src_ip, None)
            self._wmean.pop(src_ip, None)
            self._wm2.pop(src_ip, None)
            self._fifo.pop(src_ip, None)

    def variance_before(self, ts: float, src_ip: str) -> float:
        self._maybe_global(ts)
        self._prune_src(src_ip, ts)
        n = self._wn.get(src_ip, 0)
        if n < 2:
            return 0.0
        return float(self._wm2[src_ip] / n)

    def add(self, ts: float, src_ip: str) -> None:
        self._maybe_global(ts)
        self._prune_src(src_ip, ts)
        if src_ip not in self._ts:
            while len(self._ts) >= self._max_src and self._fifo:
                evict, _ = self._fifo.popitem(last=False)
                self._ts.pop(evict, None)
                self._deltas.pop(evict, None)
                self._wn.pop(evict, None)
                self._wmean.pop(evict, None)
                self._wm2.pop(evict, None)
            self._ts[src_ip] = deque()
            self._deltas[src_ip] = deque()
            self._wn[src_ip] = 0
            self._wmean[src_ip] = 0.0
            self._wm2[src_ip] = 0.0
            self._fifo[src_ip] = None
        ts_dq = self._ts[src_ip]
        delta_dq = self._deltas[src_ip]
        if ts_dq:
            d = ts - ts_dq[-1]
            delta_dq.append(d)
            n0, mn0, m20 = self._wn[src_ip], self._wmean[src_ip], self._wm2[src_ip]
            nn, mm, m2n = _welford_add_delta(n0, mn0, m20, d)
            self._wn[src_ip] = nn
            self._wmean[src_ip] = mm
            self._wm2[src_ip] = m2n
        ts_dq.append(ts)


class DstUniqueSrcIps60Tracker:
    """Per-dst_ip: count distinct src_ip seen on flow events in the last 60s."""

    def __init__(
        self,
        window_sec: float = WINDOW_60_SEC,
        max_dst_entries: int = 100_000,
        global_cleanup_interval: int = DEFAULT_GLOBAL_CLEANUP_INTERVAL,
    ) -> None:
        self._w = window_sec
        self._max_dst = max_dst_entries
        self._global_cleanup_interval = max(1, int(global_cleanup_interval))
        self._op_count = 0
        self._dq: Dict[str, deque] = {}
        self._counts: Dict[str, Dict[str, int]] = {}
        self._fifo: "OrderedDict[str, None]" = OrderedDict()

    def _cleanup_global(self, now: float) -> None:
        for dst in list(self._dq.keys()):
            self._prune_dst(dst, now)

    def _maybe_global(self, now: float) -> None:
        self._op_count += 1
        if self._op_count % self._global_cleanup_interval == 0:
            self._cleanup_global(now)

    def _prune_dst(self, dst_ip: str, now: float) -> None:
        cutoff = now - self._w
        dq = self._dq.get(dst_ip)
        if dq is None:
            return
        cm = self._counts.get(dst_ip)
        while dq and dq[0][0] < cutoff:
            _, sip = dq.popleft()
            if cm and sip in cm:
                cm[sip] -= 1
                if cm[sip] <= 0:
                    del cm[sip]
        if not dq:
            self._dq.pop(dst_ip, None)
            self._counts.pop(dst_ip, None)
            self._fifo.pop(dst_ip, None)

    def unique_before(self, ts: float, dst_ip: str) -> float:
        self._maybe_global(ts)
        self._prune_dst(dst_ip, ts)
        cm = self._counts.get(dst_ip)
        return float(len(cm)) if cm else 0.0

    def add(self, ts: float, dst_ip: str, src_ip: str) -> None:
        sip = (src_ip or "").strip() or "UNKNOWN"
        self._maybe_global(ts)
        self._prune_dst(dst_ip, ts)
        if dst_ip not in self._dq:
            while len(self._dq) >= self._max_dst and self._fifo:
                evict, _ = self._fifo.popitem(last=False)
                self._dq.pop(evict, None)
                self._counts.pop(evict, None)
            self._dq[dst_ip] = deque()
            self._counts[dst_ip] = {}
            self._fifo[dst_ip] = None
        self._dq[dst_ip].append((ts, sip))
        d = self._counts[dst_ip]
        d[sip] = d.get(sip, 0) + 1


class SrcFlowCount300Tracker:
    """Per-src_ip: number of flow events in the last 300s (timestamp deque length)."""

    def __init__(
        self,
        window_sec: float = WINDOW_300_SEC,
        max_src_entries: int = 100_000,
        global_cleanup_interval: int = DEFAULT_GLOBAL_CLEANUP_INTERVAL,
    ) -> None:
        self._w = window_sec
        self._max_src = max_src_entries
        self._global_cleanup_interval = max(1, int(global_cleanup_interval))
        self._op_count = 0
        self._src: Dict[str, deque] = {}
        self._fifo: "OrderedDict[str, None]" = OrderedDict()

    def _cleanup_global(self, now: float) -> None:
        cutoff = now - self._w
        for src in list(self._src.keys()):
            dq = self._src[src]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                self._src.pop(src, None)
                self._fifo.pop(src, None)

    def _maybe_global(self, now: float) -> None:
        self._op_count += 1
        if self._op_count % self._global_cleanup_interval == 0:
            self._cleanup_global(now)

    def _prune_src(self, src_ip: str, now: float) -> None:
        cutoff = now - self._w
        dq = self._src.get(src_ip)
        if dq is None:
            return
        while dq and dq[0] < cutoff:
            dq.popleft()
        if not dq:
            self._src.pop(src_ip, None)
            self._fifo.pop(src_ip, None)

    def count_before(self, ts: float, src_ip: str) -> float:
        self._maybe_global(ts)
        self._prune_src(src_ip, ts)
        dq = self._src.get(src_ip)
        return float(len(dq)) if dq else 0.0

    def add(self, ts: float, src_ip: str) -> None:
        self._maybe_global(ts)
        self._prune_src(src_ip, ts)
        if src_ip not in self._src:
            while len(self._src) >= self._max_src and self._fifo:
                evict, _ = self._fifo.popitem(last=False)
                self._src.pop(evict, None)
            self._src[src_ip] = deque()
            self._fifo[src_ip] = None
        self._src[src_ip].append(ts)


class TLSBehaviorTracker:
    """
    Placeholder for API compatibility. TLS handshake history (JA3 / SNI streams) is not used
    in the flow-only schema; `is_tls` / `tls_version` come from the flow record only.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass


class TCPFlagEntropyTracker:
    """
    Rolling 60s TCP flag entropy per src_ip.

    Feature: tcp_flag_entropy
      - Maintains counts of SYN/ACK/FIN/RST/PSH/URG occurrences in a sliding
        window per src_ip.
      - Computes Shannon entropy over the normalized flag distribution.

    Shortcut prevention:
      - We do NOT use raw tcp_flags strings. We only use aggregates (counts →
        probabilities → entropy).
      - Non-informative events (no TCP flags present) contribute zero.
    """

    # TCP flag bitmasks (Suricata/pcap standard)
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

    _FLAG_BITS: List[Tuple[str, int]] = [
        ("SYN", SYN),
        ("ACK", ACK),
        ("FIN", FIN),
        ("RST", RST),
        ("PSH", PSH),
        ("URG", URG),
    ]

    def __init__(
        self,
        window_sec: float = WINDOW_60_SEC,
        max_src_entries: int = 100_000,
        global_cleanup_interval: int = DEFAULT_GLOBAL_CLEANUP_INTERVAL,
    ) -> None:
        self._w = window_sec
        self._max_src = max_src_entries
        self._global_cleanup_interval = max(1, int(global_cleanup_interval))
        self._op_count = 0
        # src_ip -> deque[(ts, mask)]
        self._src: Dict[str, deque] = {}
        self._fifo: "OrderedDict[str, None]" = OrderedDict()
        # src_ip -> counts dict for flags in window
        self._counts: Dict[str, Dict[str, int]] = {}
        self._total: Dict[str, int] = {}

    def _cleanup_global(self, now: float) -> None:
        cutoff = now - self._w
        for src in list(self._src.keys()):
            dq = self._src[src]
            while dq and dq[0][0] < cutoff:
                _, mask = dq.popleft()
                for name, bit in self._FLAG_BITS:
                    if mask & bit:
                        self._counts[src][name] -= 1
                        self._total[src] -= 1
            if not dq:
                self._src.pop(src, None)
                self._counts.pop(src, None)
                self._total.pop(src, None)
                self._fifo.pop(src, None)

    def _maybe_global(self, now: float) -> None:
        self._op_count += 1
        if self._op_count % self._global_cleanup_interval == 0:
            self._cleanup_global(now)

    def _prune_src(self, src_ip: str, now: float) -> None:
        cutoff = now - self._w
        dq = self._src.get(src_ip)
        if dq is None:
            return
        while dq and dq[0][0] < cutoff:
            _, mask = dq.popleft()
            for name, bit in self._FLAG_BITS:
                if mask & bit:
                    self._counts[src_ip][name] -= 1
                    self._total[src_ip] -= 1
        if not dq:
            self._src.pop(src_ip, None)
            self._counts.pop(src_ip, None)
            self._total.pop(src_ip, None)
            self._fifo.pop(src_ip, None)

    def _ensure_src(self, src_ip: str) -> None:
        if src_ip in self._src:
            return
        while len(self._src) >= self._max_src and self._fifo:
            evict, _ = self._fifo.popitem(last=False)
            self._src.pop(evict, None)
            self._counts.pop(evict, None)
            self._total.pop(evict, None)
        self._src[src_ip] = deque()
        self._counts[src_ip] = {name: 0 for name, _ in self._FLAG_BITS}
        self._total[src_ip] = 0
        self._fifo[src_ip] = None

    @staticmethod
    def _parse_flag_hex(val: Any) -> int:
        """Parse Suricata tcp_flags strings/ints into an integer bitmask."""
        if val is None:
            return 0
        if isinstance(val, (int, float)):
            try:
                return int(val)
            except Exception:
                return 0
        s = str(val).strip().lower()
        if not s:
            return 0
        # Common formats: "1b", "0x1b"
        try:
            if s.startswith("0x"):
                return int(s, 16)
            return int(s, 16)
        except ValueError:
            # Sometimes Suricata may emit like "S" etc; unsupported → 0
            return 0

    @classmethod
    def extract_mask_from_ev(cls, ev: Dict[str, Any]) -> int:
        """
        Extract a combined TCP flag mask from an EVE event.

        Preference order:
          1) Boolean keys: tcp['syn'], tcp['ack'], ...
          2) tcp_flags_ts / tcp_flags_tc hex values → OR
          3) tcp['tcp_flags'] hex value
        """
        tcp = ev.get("tcp") or {}
        if isinstance(tcp, dict):
            # If boolean keys exist, use them
            bool_map = {
                cls.SYN: bool(tcp.get("syn")),
                cls.ACK: bool(tcp.get("ack")),
                cls.FIN: bool(tcp.get("fin")),
                cls.RST: bool(tcp.get("rst")),
                cls.PSH: bool(tcp.get("psh")),
                cls.URG: bool(tcp.get("urg")),
            }
            if any(bool_map.values()):
                mask = 0
                for bit, present in bool_map.items():
                    if present:
                        mask |= bit
                return mask

            # Directional hex values
            ts_val = tcp.get("tcp_flags_ts")
            tc_val = tcp.get("tcp_flags_tc")
            m_ts = cls._parse_flag_hex(ts_val)
            m_tc = cls._parse_flag_hex(tc_val)
            if m_ts or m_tc:
                return m_ts | m_tc

            # Fallback: generic tcp_flags
            generic = tcp.get("tcp_flags")
            return cls._parse_flag_hex(generic)

        return 0

    def add_flags(self, ts: float, src_ip: str, mask: int) -> None:
        if mask == 0:
            return  # no contribution
        self._maybe_global(ts)
        self._prune_src(src_ip, ts)
        self._ensure_src(src_ip)
        self._src[src_ip].append((ts, mask))
        for name, bit in self._FLAG_BITS:
            if mask & bit:
                self._counts[src_ip][name] += 1
                self._total[src_ip] += 1

    def entropy_60s(self, ts: float, src_ip: str) -> float:
        self._maybe_global(ts)
        self._prune_src(src_ip, ts)
        if src_ip not in self._total:
            return 0.0
        total = self._total.get(src_ip, 0)
        if total <= 0:
            return 0.0
        counts = self._counts.get(src_ip, {})
        ent = 0.0
        for name, _ in self._FLAG_BITS:
            c = counts.get(name, 0)
            if c <= 0:
                continue
            p = c / total
            ent -= p * np.log2(p)
        return float(ent)


class NetflowContextStore:
    """
    Store netflow-derived per-src_ip/flow rate statistics for enrichment.

    Suricata netflow output is typically produced as separate EVE event_type="netflow".
    To avoid losing those signals, we:
      1) In a first pass, store netflow metrics keyed by a computed flow_key.
      2) In the second pass, when we process the corresponding event_type="flow",
         optionally override rhythm features (pkt_rate/byte_rate/iat_*) if netflow
         provides them.

    This is "safe by default": if netflow keys are missing, we fall back to the
    current flow-derived computations.
    """

    def __init__(self, ttl_sec: float = WINDOW_120_SEC, max_entries: int = 200_000) -> None:
        self.ttl_sec = float(ttl_sec)
        self.max_entries = max_entries
        # flow_key -> (ts, metrics_dict)
        self._store: Dict[str, Tuple[float, Dict[str, float]]] = {}
        self._order: List[str] = []

    @staticmethod
    def _flow_key_from_ev(ev: Dict[str, Any]) -> str:
        src_ip = str(ev.get("src_ip", "")).strip() or "UNKNOWN"
        dst_ip = str(ev.get("dest_ip", "")).strip() or "UNKNOWN"
        src_port = _safe_int(ev.get("src_port", 0))
        dst_port = _safe_int(ev.get("dest_port", 0))
        proto = str(ev.get("proto", "TCP")).strip().upper()
        ts = _ts_from_ev(ev)
        return flow_key_with_time_bucket(src_ip, src_port, dst_ip, dst_port, proto, ts)

    @staticmethod
    def _pick_float(d: Dict[str, Any], keys: List[str]) -> Optional[float]:
        for k in keys:
            if k in d and d[k] is not None:
                v = d.get(k)
                try:
                    fv = float(v)
                    if np.isfinite(fv):
                        return fv
                except (TypeError, ValueError):
                    continue
        return None

    def _cleanup(self, now: float) -> None:
        cutoff = now - self.ttl_sec
        # We keep cleanup O(k) using insertion order; worst-case bounded by ttl.
        while self._order:
            fk = self._order[0]
            ts, _ = self._store.get(fk, (None, None))  # type: ignore[misc]
            if ts is None:
                self._order.pop(0)
                continue
            if ts >= cutoff:
                break
            self._order.pop(0)
            self._store.pop(fk, None)

        # Hard cap if needed
        if len(self._store) > self.max_entries:
            # Drop oldest entries
            while len(self._store) > self.max_entries and self._order:
                fk = self._order.pop(0)
                self._store.pop(fk, None)

    def put_from_netflow_event(self, ev: Dict[str, Any]) -> None:
        et = str(ev.get("event_type", "")).strip().lower()
        if et != "netflow":
            return

        ts = _ts_from_ev(ev)  # netflow event timestamp
        fk = self._flow_key_from_ev(ev)
        net = ev.get("netflow") or {}
        if not isinstance(net, dict):
            return

        # Extract only the rhythm fields we currently compute from flow age.
        metrics: Dict[str, float] = {}

        # Rates: prefer netflow-provided values if present.
        pkt_rate = self._pick_float(net, ["pkt_rate", "packet_rate", "pktrate", "pkt_per_sec"])
        byte_rate = self._pick_float(net, ["byte_rate", "bytes_rate", "byterate", "byte_per_sec"])
        iat_min = self._pick_float(net, ["iat_min", "iatmin", "inter_arrival_min"])
        iat_max = self._pick_float(net, ["iat_max", "iatmax", "inter_arrival_max"])
        iat_avg = self._pick_float(net, ["iat_avg", "iatmean", "iat_mean", "inter_arrival_avg"])

        if pkt_rate is not None:
            metrics["pkt_rate"] = float(pkt_rate)
        if byte_rate is not None:
            metrics["byte_rate"] = float(byte_rate)
        if iat_min is not None:
            metrics["iat_min"] = float(iat_min)
        if iat_max is not None:
            metrics["iat_max"] = float(iat_max)
        if iat_avg is not None:
            metrics["iat_avg"] = float(iat_avg)

        if not metrics:
            return

        self._cleanup(ts)
        if fk not in self._store:
            self._order.append(fk)
        self._store[fk] = (ts, metrics)

    def get_metrics_for_flow(self, flow_key: str, now_ts: float) -> Dict[str, float]:
        self._cleanup(now_ts)
        v = self._store.get(flow_key)
        if not v:
            return {}
        ts, metrics = v
        if ts < now_ts - self.ttl_sec:
            return {}
        return metrics


# -----------------------------------------------------------------------------
# Per-flow feature extraction (unified behavioral schema from EVE)
# -----------------------------------------------------------------------------


def _extract_flow_basics(ev: Dict[str, Any]) -> Dict[str, float]:
    flow = ev.get("flow") or {}
    src_pkts = _safe_int(flow.get("pkts_toserver", 0))
    dst_pkts = _safe_int(flow.get("pkts_toclient", 0))
    src_bytes = _safe_int(flow.get("bytes_toserver", 0))
    dst_bytes = _safe_int(flow.get("bytes_toclient", 0))
    pkts = src_pkts + dst_pkts
    bytes_total = src_bytes + dst_bytes
    duration = _safe_float(flow.get("age", 0))
    if duration <= 0:
        duration = 0.0
    avg_pkt_size = bytes_total / pkts if pkts > 0 else 0.0
    return {
        "duration": duration,
        "src_bytes": float(src_bytes),
        "dst_bytes": float(dst_bytes),
        "src_pkts": float(src_pkts),
        "dst_pkts": float(dst_pkts),
        "avg_pkt_size": avg_pkt_size,
    }


def _extract_rhythms(ev: Dict[str, Any]) -> Dict[str, float]:
    flow = ev.get("flow") or {}
    tcp = ev.get("tcp") or {}
    src_pkts = _safe_int(flow.get("pkts_toserver", 0))
    dst_pkts = _safe_int(flow.get("pkts_toclient", 0))
    src_bytes = _safe_int(flow.get("bytes_toserver", 0))
    dst_bytes = _safe_int(flow.get("bytes_toclient", 0))
    pkts = src_pkts + dst_pkts
    bytes_total = src_bytes + dst_bytes
    duration = _safe_float(flow.get("age", 0))
    if duration <= 0:
        duration = 0.0
    pkt_rate = pkts / duration if duration > 0 else 0.0
    byte_rate = bytes_total / duration if duration > 0 else 0.0
    # IAT "Bot Detector": flow-level proxy for automation. Humans = chaotic IAT; bots/beacons = low, consistent IAT.
    # EVE has no per-packet timestamps, so we use effective IAT = duration/(pkts-1); model uses this as automation signal.
    if pkts > 1 and duration > 0:
        iat = duration / (pkts - 1)
        iat_min = iat_max = iat_avg = iat
    else:
        iat_min = iat_max = iat_avg = 0.0
    tcp_flag_count = sum(1 for k in ("syn", "ack", "fin", "rst", "psh") if tcp.get(k)) if tcp else 0
    urg_flag_count = 1 if tcp.get("urg") else 0
    return {
        "pkt_rate": pkt_rate,
        "byte_rate": byte_rate,
        "iat_min": iat_min,
        "iat_max": iat_max,
        "iat_avg": iat_avg,
        "tcp_flag_count": float(tcp_flag_count),
        "urg_flag_count": float(urg_flag_count),
    }


def _extract_advanced_flow(ev: Dict[str, Any]) -> Dict[str, float]:
    """Flow-record-only advanced fields (no payload / HTTP body analysis)."""
    flow = ev.get("flow") or {}
    src_pkts = _safe_int(flow.get("pkts_toserver", 0))
    dst_pkts = _safe_int(flow.get("pkts_toclient", 0))
    pkts = src_pkts + dst_pkts
    src_pkts_ratio = src_pkts / pkts if pkts > 0 else 0.0
    tls_sni_count = 1 if (ev.get("tls") or {}).get("sni") else 0
    dst_port_entropy = 0.0
    return {
        "src_pkts_ratio": min(1.0, max(0.0, src_pkts_ratio)),
        "dst_port_entropy": float(dst_port_entropy),
        "tls_sni_count": float(tls_sni_count),
    }


def _collect_ttl_values(ev: Dict[str, Any]) -> List[float]:
    """Collect TTL values from event (ip, flow, inner). Used for ttl_variance (Evasion Detector)."""
    out: List[float] = []
    for node in (ev.get("ip") or {}, ev.get("inner") or {}, ev.get("flow") or {}):
        if not isinstance(node, dict):
            continue
        v = node.get("ttl")
        if v is not None:
            try:
                x = float(v)
                if np.isfinite(x):
                    out.append(x)
            except (TypeError, ValueError):
                pass
    return out


def _extract_evasion_shield(ev: Dict[str, Any]) -> Dict[str, float]:
    tcp = ev.get("tcp") or {}
    ip_ev = ev.get("ip") or ev.get("inner") or {}
    # ttl_variance "Evasion Detector": 0 normally; non-zero = insertion/evasion (different TTLs to bypass IDS).
    ttls = _collect_ttl_values(ev)
    ttl_var = float(np.var(ttls)) if len(ttls) >= 2 else 0.0
    tcp_win = _safe_float(tcp.get("window", 0))
    ip_frag = _safe_int(ip_ev.get("fragments", 0)) if ip_ev else 0
    return {
        "ttl_variance": ttl_var,
        "tcp_window_size_avg": tcp_win,
        "ip_fragment_count": float(ip_frag),
    }


def _is_failed_connection(ev: Dict[str, Any]) -> float:
    """
    Flow-level failed / rejected attempt heuristic (SSH brute-force friendly).

    Maps Suricata EVE ``flow`` counters to duration/bytes/packet rules. Uses ``flow.age`` as
    duration (seconds) when present; skips the short-duration rule when age is unknown (0).

    Output: 0.0 or 1.0
    """
    flow = ev.get("flow") or {}
    duration = _safe_float(flow.get("age", 0))
    dst_bytes = _safe_int(flow.get("bytes_toclient", 0))
    src_pkts = _safe_int(flow.get("pkts_toserver", 0))
    dst_pkts = _safe_int(flow.get("pkts_toclient", 0))

    if src_pkts <= 0:
        return 0.0

    # Short-lived + low server response (typical failed auth / teardown).
    if duration > 0.0 and duration < 1.5 and dst_bytes < 300:
        return 1.0

    # Asymmetric exchange (client sends, server barely responds).
    if src_pkts > 3 and dst_pkts <= 1:
        return 1.0

    return 0.0


def _extract_tls_flow_flags(ev: Dict[str, Any], _tls_tracker: Optional[TLSBehaviorTracker] = None) -> Dict[str, float]:
    """
    TLS flags from the flow record only (no JA3 / handshake-history aggregates).
    """
    app_proto = str(ev.get("app_proto", "")).strip().lower()
    etype = str(ev.get("event_type", "")).strip().lower()

    is_tls = 1.0 if (etype == "tls" or app_proto == "tls") else 0.0
    if not is_tls:
        return {"is_tls": 0.0, "tls_version": 0.0}

    tls_block = ev.get("tls") or {}
    ver_raw = str(tls_block.get("version") or "").strip().upper()
    if ver_raw.endswith("1.0"):
        tls_version = 1.0
    elif ver_raw.endswith("1.1"):
        tls_version = 1.1
    elif ver_raw.endswith("1.2"):
        tls_version = 1.2
    elif ver_raw.endswith("1.3"):
        tls_version = 1.3
    else:
        tls_version = 0.0

    return {"is_tls": is_tls, "tls_version": float(tls_version)}


def extract_unified_behavioral_row(
    ev: Dict[str, Any],
    behavioral: BehavioralExtractorUnified,
    tls_tracker: TLSBehaviorTracker,
    tcp_tracker: TCPFlagEntropyTracker,
    dst_var_tracker: DstPortVariance300Tracker,
    iat_var_300: FlowInterarrivalVariance300Tracker,
    dst_unique_src_60: DstUniqueSrcIps60Tracker,
    src_flow_300: SrcFlowCount300Tracker,
    temporal: SrcIpTemporalTracker,
) -> Dict[str, Any]:
    """
    Backward-compatible wrapper: compute the flow+TCP behavioral schema for a **flow** row.
    Standalone ``event_type=="tcp"`` lines are ignored (no side effects).
    """
    if not hasattr(extract_unified_behavioral_row, "_engine"):
        extract_unified_behavioral_row._engine = FlowTcpBehavioralEngine()  # type: ignore[attr-defined]
    eng: FlowTcpBehavioralEngine = extract_unified_behavioral_row._engine  # type: ignore[attr-defined]

    et_l = str(ev.get("event_type", "")).strip().lower()
    if et_l == "tcp":
        return {}
    row = eng.build_row_from_flow(ev)
    ts = _ts_from_ev(ev)
    src_ip = str(ev.get("src_ip", "")).strip() or "UNKNOWN"
    dst_ip = str(ev.get("dest_ip", "")).strip() or "UNKNOWN"
    src_port = _safe_int(ev.get("src_port", 0))
    dst_port = _safe_int(ev.get("dest_port", 0))
    proto = str(ev.get("proto", "TCP")).strip().upper()
    fk = flow_key_with_time_bucket(src_ip, src_port, dst_ip, dst_port, proto, ts)
    row[TIMESTAMP_COL] = ts
    row[FLOW_KEY_COL] = fk
    row[IDENTITY_KEY_COL] = identity_key_for_eve_flow(ev, fk)
    row["src_ip"] = src_ip
    row["dst_ip"] = dst_ip
    return row


# -----------------------------------------------------------------------------
# Streaming iterator
# -----------------------------------------------------------------------------


def iter_eve_flow_events(
    filepath: Path,
    event_type_filter: str = "flow",
    max_events: Optional[int] = None,
) -> Iterator[Dict[str, Any]]:
    count = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event_type_filter and event.get("event_type") != event_type_filter:
                continue
            yield event
            count += 1
            if max_events is not None and count >= max_events:
                return


# -----------------------------------------------------------------------------
# Pipeline: extract → SanityCheck → CSV or Parquet
# -----------------------------------------------------------------------------


def run_unified_behavioral_extraction(
    input_eve_path: Path,
    output_path: Path,
    max_events: Optional[int] = None,
    output_format: str = "csv",
    include_join_columns: bool = True,
    include_label: bool = False,
    progress_callback: Optional[Any] = None,
    legacy_raw_eve_stream: bool = False,
) -> int:
    """
    Stream EVE → unified behavioral feature rows → SanityCheck → CSV or Parquet.
    output_format: "csv" or "parquet".

    Streams ``input_eve_path`` once; TCP data comes only from each flow's optional ``tcp`` field.
    ``legacy_raw_eve_stream`` is ignored (kept for API compatibility).
    """
    _ = legacy_raw_eve_stream
    work_path = Path(input_eve_path)
    work_cleanup = None
    engine = FlowTcpBehavioralEngine()
    sanity = SanityCheck(UNIFIED_BEHAVIORAL_FEATURE_NAMES, FEATURE_BOUNDS, DEFAULT_FILL)

    try:
        from build_ground_truth import (
            label_event,
            _filter_windows_for_experiment,
            load_attack_windows_from_hardcoded_table,
        )
        all_w = load_attack_windows_from_hardcoded_table()
        windows, _ = _filter_windows_for_experiment(all_w, input_eve_path)

        def label_fn(e: Dict[str, Any]) -> int:
            return 1 if label_event(e, windows)[0] else 0

    except Exception:
        label_fn = lambda e: 0

    columns = ["flow_id"] + list(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    if include_join_columns:
        columns = columns + [TIMESTAMP_COL, FLOW_KEY_COL, IDENTITY_KEY_COL, "src_ip", "dst_ip"]
    if include_label:
        columns = columns + [LABEL_KEY]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    writer = None
    batch: List[Dict[str, Any]] = []
    BATCH_SIZE = 10_000
    f = None
    writer_csv = None
    pa = None

    if output_format == "parquet":
        try:
            import pyarrow as _pa
            import pyarrow.parquet as pq
            pa = _pa
            fields = [("flow_id", _pa.string())]
            fields.extend((c, _pa.float64()) for c in UNIFIED_BEHAVIORAL_FEATURE_NAMES)
            if include_join_columns:
                fields.extend([
                    (TIMESTAMP_COL, _pa.float64()),
                    (FLOW_KEY_COL, _pa.string()),
                    (IDENTITY_KEY_COL, _pa.string()),
                    ("src_ip", _pa.string()),
                    ("dst_ip", _pa.string()),
                ])
            if include_label:
                fields.append((LABEL_KEY, _pa.int64()))
            writer = pq.ParquetWriter(output_path, _pa.schema(fields))
        except ImportError:
            output_format = "csv"

    if output_format == "csv":
        f = open(output_path, "w", newline="", encoding="utf-8")
        writer_csv = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer_csv.writeheader()

    try:
        flow_seen = 0
        with open(work_path, "r", encoding="utf-8", errors="replace") as f_ev:
            for line in f_ev:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(ev, dict):
                    continue
                et = str(ev.get("event_type", "")).strip().lower()
                if et == "tcp":
                    continue
                if et != "flow":
                    continue
                if max_events is not None and flow_seen >= max_events:
                    break
                row = engine.build_row_from_flow(ev)
                ts = _ts_from_ev(ev)
                flow_seen += 1
                src_ip = str(ev.get("src_ip", "")).strip() or "UNKNOWN"
                dst_ip = str(ev.get("dest_ip", "")).strip() or "UNKNOWN"
                src_port = _safe_int(ev.get("src_port", 0))
                dst_port = _safe_int(ev.get("dest_port", 0))
                proto = str(ev.get("proto", "TCP")).strip().upper()
                fk = flow_key_with_time_bucket(src_ip, src_port, dst_ip, dst_port, proto, ts)
                if include_join_columns:
                    row[TIMESTAMP_COL] = ts
                    row[FLOW_KEY_COL] = fk
                    row[IDENTITY_KEY_COL] = identity_key_for_eve_flow(ev, fk)
                    row["src_ip"] = src_ip
                    row["dst_ip"] = dst_ip
                if include_label:
                    row[LABEL_KEY] = label_fn(ev)
                fixed = sanity.check_and_fix(row)
                for k in list(row.keys()):
                    if k in fixed:
                        row[k] = fixed[k]
                if output_format == "csv":
                    writer_csv.writerow({k: row.get(k, "") for k in columns})
                else:
                    batch.append({k: row.get(k) for k in columns})
                    if len(batch) >= BATCH_SIZE:
                        tbl = pa.table({c: [b[c] for b in batch] for c in columns})
                        writer.write_table(tbl)
                        batch.clear()
                written += 1
                if progress_callback and written % 50_000 == 0:
                    progress_callback(written)
                if written % 100_000 == 0:
                    gc.collect()
    finally:
        if f is not None:
            f.close()
        if writer is not None and pa is not None:
            if batch:
                tbl = pa.table({c: [b[c] for b in batch] for c in columns})
                writer.write_table(tbl)
            writer.close()
        if work_cleanup is not None:
            work_cleanup()

    if progress_callback:
        progress_callback(written)
    return written


# -----------------------------------------------------------------------------
# Ground-truth augmentation: join labeled CSV with feature CSV (no relabeling)
# -----------------------------------------------------------------------------


def augment_ground_truth_csv(
    labels_path: Path,
    features_path: Path,
    output_path: Path,
    feature_columns: Optional[List[str]] = None,
    fill_missing_features: float = DEFAULT_FILL,
    progress_callback: Optional[Any] = None,
) -> int:
    """
    Extend the existing labeled dataset with all behavioral features.

    - Labels CSV must contain flow_key and label (and any other columns to preserve).
    - Features CSV must contain flow_key and the behavioral feature columns (e.g. from
      run_unified_behavioral_extraction with include_join_columns=True).
    - Inner join on identity_key: Suricata flow_id when present on the label row, else flow_key;
      feature rows use column identity_key when present, otherwise flow_key (backward compatible).
    - Feature values are sanity-checked (no NaN/Inf); missing features filled with fill_missing_features.
    - No relabeling or inference: attack/benign labels are preserved as-is.
    """
    feature_cols = feature_columns or list(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    sanity = SanityCheck(feature_cols, FEATURE_BOUNDS, fill_missing_features)

    # Load labels by identity_key (flow_id when valid, else flow_key)
    labels_by_key: Dict[str, Dict[str, Any]] = {}
    label_fieldnames: List[str] = []
    _dup_conflict = 0
    with open(labels_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        label_fieldnames = list(reader.fieldnames or [])
        if "flow_key" not in label_fieldnames:
            raise ValueError("Labels CSV must contain a 'flow_key' column.")
        for row in reader:
            key = identity_key_from_label_csv_row(row)
            if key:
                if key in labels_by_key:
                    a = labels_by_key[key].get("label") or labels_by_key[key].get("binary_label")
                    b = row.get("label") or row.get("binary_label")
                    if a is not None and b is not None and str(a).strip() != str(b).strip():
                        _dup_conflict += 1
                labels_by_key[key] = dict(row)
    if _dup_conflict:
        print(
            f"[WARNING] augment_ground_truth_csv: {_dup_conflict} duplicate identity_key row(s) "
            f"with conflicting labels (last row wins).",
            file=sys.stderr,
        )

    # Output columns: label columns (excluding duplicates with feature names) + feature columns
    out_columns = [c for c in label_fieldnames if c not in feature_cols] + list(feature_cols)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with open(output_path, "w", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=out_columns, extrasaction="ignore")
        writer.writeheader()
        with open(features_path, "r", encoding="utf-8", errors="replace") as feat_f:
            reader = csv.DictReader(feat_f)
            for row in reader:
                key = (row.get(IDENTITY_KEY_COL) or row.get(FLOW_KEY_COL) or row.get("flow_key") or "").strip()
                if key not in labels_by_key:
                    continue
                label_row = labels_by_key[key]
                # Feature values: only the requested feature columns, sanity-checked
                feat_row = {k: row.get(k) for k in feature_cols}
                fixed = sanity.check_and_fix(feat_row)
                merged = {**label_row}
                for k in feature_cols:
                    merged[k] = fixed.get(k, fill_missing_features)
                writer.writerow({k: merged.get(k, "") for k in out_columns})
                written += 1
                if progress_callback and written % 50_000 == 0:
                    progress_callback(written)
    if progress_callback:
        progress_callback(written)
    return written


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="Unified Behavioral Pipeline: behavioral feature extraction from Suricata EVE (CSV or Parquet).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", "-i", type=Path, required=True, help="Path to master_eve.json (JSONL).")
    parser.add_argument("--output", "-o", type=Path, required=True, help="Output path (CSV or Parquet).")
    parser.add_argument("--format", choices=("csv", "parquet"), default="csv", help="Output format for ML training.")
    parser.add_argument("--max-events", type=int, default=None, help="Cap flow events.")
    parser.add_argument("--no-join-cols", action="store_true", help="Omit timestamp_epoch, flow_key, src_ip, dst_ip.")
    parser.add_argument("--label", action="store_true", help="Add label from IP/Time attack schedule.")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: input not found: {args.input}", file=sys.stderr)
        return 1

    ext = args.output.suffix.lower()
    out_format = "parquet" if ext == ".parquet" or args.format == "parquet" else "csv"
    try:
        n = run_unified_behavioral_extraction(
            input_eve_path=args.input,
            output_path=args.output,
            max_events=args.max_events,
            output_format=out_format,
            include_join_columns=not args.no_join_cols,
            include_label=args.label,
            progress_callback=lambda w: sys.stderr.write(f"\rFlows written: {w}"),
        )
        print(f"\nWrote {n} rows to {args.output}", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    sys.exit(main())
