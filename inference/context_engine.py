"""
Context Memory Engine for the ML firewall runtime.

Operates after the ML decision stage. Tracks behavioral context across flows using
NAT-safe keys (src_ip, dst_ip, dst_port). Provides:
- Per-key escalation when repeated suspicious activity exceeds thresholds
- Destination-level DDoS aggregation (flows_per_dst_ip, unique_src_ips_per_dst_ip)
  to detect distributed attacks without feeding identity into ML models
- Destination port fan-out: unique destination ports per dst_ip in a sliding window
  to detect port sweeps and distributed reconnaissance (many IPs each probing a few ports)
- Source-side signals: flow burst, port scan, host sweep, slow scan (sliding windows per src_ip)

Context memory is ephemeral (RAM only); cleared on process restart.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any, List, Optional, Tuple, Dict

# Per-key (flow context) defaults
DEFAULT_WINDOW_SECONDS = 600  # 10 minutes
DEFAULT_TTL_SECONDS = 3600  # 1 hour
DEFAULT_MAX_ENTRIES = 100_000
DEFAULT_ESCALATE_MIN_EVENTS = 3

# DDoS aggregation defaults (sliding window for destination-level metrics)
DEFAULT_DDOS_WINDOW_SECONDS = 10.0
DEFAULT_DDOS_FLOW_THRESHOLD = 100
DEFAULT_DDOS_UNIQUE_SRC_THRESHOLD = 50

# Destination port fan-out (reconnaissance / port sweep detection per dst_ip)
DEFAULT_FANOUT_WINDOW_SECONDS = 120.0  # 2 minutes
DEFAULT_FANOUT_UNIQUE_PORTS_THRESHOLD = 20  # distinct ports on one host in window
DEFAULT_FANOUT_VELOCITY_THRESHOLD = 0.0  # 0 = disabled; else ports/sec to trigger

# Source-side detection (per src_ip; threshold 0 = disabled)
DEFAULT_SRC_BURST_WINDOW_SECONDS = 20.0
DEFAULT_SRC_BURST_THRESHOLD = 100
DEFAULT_SRC_PORTSCAN_WINDOW_SECONDS = 30.0
DEFAULT_SRC_PORTSCAN_PORTS_THRESHOLD = 20
DEFAULT_SRC_DSTFANOUT_WINDOW_SECONDS = 60.0
DEFAULT_SRC_DSTFANOUT_HOSTS_THRESHOLD = 10
DEFAULT_SRC_SLOWSCAN_WINDOW_SECONDS = 600.0
DEFAULT_SRC_SLOWSCAN_PORTS_THRESHOLD = 30
DEFAULT_MAX_SRC_ENTRIES = 50_000


def _parse_timestamp(ts: Any) -> float:
    """Convert event timestamp to epoch float. Returns 0 if missing/invalid."""
    if ts is None:
        return 0.0
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        from datetime import datetime
        if isinstance(ts, str):
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.timestamp()
    except Exception:
        pass
    return 0.0


def _context_key(src_ip: str, dst_ip: str, dst_port: int) -> Tuple[str, str, int]:
    """NAT-safe context key: (src_ip, dst_ip, dst_port)."""
    return (
        (src_ip or "UNKNOWN").strip() or "UNKNOWN",
        (dst_ip or "UNKNOWN").strip() or "UNKNOWN",
        int(dst_port) if dst_port is not None else 0,
    )


class _ContextEntry:
    """
    Per (src_ip, dst_ip, dst_port) state: sliding window of (timestamp, risk)
    and counters. Entries are reset on TTL expiry (inactivity timeout).
    """

    __slots__ = (
        "suspicious_count",
        "last_seen_timestamp",
        "escalation_level",
        "window",
        "window_seconds",
    )

    def __init__(self, window_seconds: float) -> None:
        self.suspicious_count = 0
        self.last_seen_timestamp = 0.0
        self.escalation_level = 0  # 0=none, 1=alert, 2=block
        self.window: List[Tuple[float, float]] = []  # (ts, risk)
        self.window_seconds = window_seconds

    def add(self, ts: float, risk: float, low_thresh: float) -> None:
        now = ts if ts > 0 else time.time()
        self.last_seen_timestamp = now
        cutoff = now - self.window_seconds
        self.window = [(t, r) for t, r in self.window if t >= cutoff]
        self.window.append((now, risk))
        self.suspicious_count = sum(1 for _, r in self.window if r >= low_thresh)


class _DstAggregate:
    """Per-dst_ip sliding window for DDoS metrics: (ts, src_ip) list."""

    __slots__ = ("events", "window_seconds")

    def __init__(self, window_seconds: float) -> None:
        self.events: List[Tuple[float, str]] = []
        self.window_seconds = window_seconds

    def add(self, ts: float, src_ip: str) -> None:
        now = ts if ts > 0 else time.time()
        cutoff = now - self.window_seconds
        self.events = [(t, s) for t, s in self.events if t >= cutoff]
        self.events.append((now, (src_ip or "UNKNOWN").strip() or "UNKNOWN"))

    def flows_per_dst_ip(self) -> int:
        return len(self.events)

    def unique_src_ips_per_dst_ip(self) -> int:
        return len(set(s for _, s in self.events))


class _DstPortFanout:
    """
    Per-dst_ip sliding window for destination port fan-out (reconnaissance detection).
    Stores (ts, src_ip, dst_port); used to compute unique ports and optional velocity.
    """

    __slots__ = ("events", "window_seconds")

    def __init__(self, window_seconds: float) -> None:
        self.events: List[Tuple[float, str, int]] = []  # (ts, src_ip, dst_port)
        self.window_seconds = window_seconds

    def add(self, ts: float, src_ip: str, dst_port: int) -> None:
        now = ts if ts > 0 else time.time()
        cutoff = now - self.window_seconds
        self.events = [(t, s, p) for t, s, p in self.events if t >= cutoff]
        self.events.append((now, (src_ip or "UNKNOWN").strip() or "UNKNOWN", int(dst_port) if dst_port is not None else 0))

    def unique_dst_ports_per_dst_ip(self) -> int:
        return len(set(p for _, _, p in self.events))

    def fanout_velocity(self) -> float:
        """Ports per second (unique ports / window length)."""
        if self.window_seconds <= 0:
            return 0.0
        return self.unique_dst_ports_per_dst_ip() / self.window_seconds


class _SrcContextEntry:
    """
    Per-src_ip state for source-side signals: flow burst, port scan, host sweep, slow scan.
    Each uses a sliding window of (ts, value); expired entries are purged on add().
    """

    __slots__ = (
        "burst_ts",
        "burst_window_seconds",
        "portscan_events",
        "portscan_window_seconds",
        "dstfanout_events",
        "dstfanout_window_seconds",
        "slowscan_events",
        "slowscan_window_seconds",
    )

    def __init__(
        self,
        burst_window: float,
        portscan_window: float,
        dstfanout_window: float,
        slowscan_window: float,
    ) -> None:
        self.burst_ts: List[float] = []
        self.burst_window_seconds = burst_window
        self.portscan_events: List[Tuple[float, int]] = []
        self.portscan_window_seconds = portscan_window
        self.dstfanout_events: List[Tuple[float, str]] = []
        self.dstfanout_window_seconds = dstfanout_window
        self.slowscan_events: List[Tuple[float, int]] = []
        self.slowscan_window_seconds = slowscan_window

    def add(
        self,
        now: float,
        dst_ip: str,
        dst_port: int,
    ) -> None:
        # Flow burst: count flows in short window
        if self.burst_window_seconds > 0:
            cutoff = now - self.burst_window_seconds
            self.burst_ts = [t for t in self.burst_ts if t >= cutoff]
            self.burst_ts.append(now)

        # Port scan (short window): unique dst_ports
        if self.portscan_window_seconds > 0:
            cutoff = now - self.portscan_window_seconds
            self.portscan_events = [(t, p) for t, p in self.portscan_events if t >= cutoff]
            self.portscan_events.append((now, dst_port))

        # Host sweep: unique dst_ips
        if self.dstfanout_window_seconds > 0 and dst_ip and dst_ip != "UNKNOWN":
            cutoff = now - self.dstfanout_window_seconds
            self.dstfanout_events = [(t, d) for t, d in self.dstfanout_events if t >= cutoff]
            self.dstfanout_events.append((now, dst_ip))

        # Slow scan: unique ports over long window
        if self.slowscan_window_seconds > 0:
            cutoff = now - self.slowscan_window_seconds
            self.slowscan_events = [(t, p) for t, p in self.slowscan_events if t >= cutoff]
            self.slowscan_events.append((now, dst_port))

    def flows_in_burst_window(self) -> int:
        return len(self.burst_ts)

    def unique_ports_portscan(self) -> int:
        return len(set(p for _, p in self.portscan_events))

    def unique_dsts_fanout(self) -> int:
        return len(set(d for _, d in self.dstfanout_events))

    def unique_ports_slowscan(self) -> int:
        return len(set(p for _, p in self.slowscan_events))


class ContextEngine:
    """
    Context memory engine: NAT-safe per-flow keys (src_ip, dst_ip, dst_port),
    optional destination-level DDoS aggregation, destination port fan-out
    (reconnaissance detection), source-side signals (burst, port scan, host sweep, slow scan),
    and ephemeral state. Bounded by max_entries (LRU) and TTL. State is cleared on process restart.
    """

    def __init__(
        self,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        escalate_min_events: int = DEFAULT_ESCALATE_MIN_EVENTS,
        ddos_window_seconds: float = DEFAULT_DDOS_WINDOW_SECONDS,
        ddos_flow_threshold: int = DEFAULT_DDOS_FLOW_THRESHOLD,
        ddos_unique_src_threshold: int = DEFAULT_DDOS_UNIQUE_SRC_THRESHOLD,
        fanout_window_seconds: float = DEFAULT_FANOUT_WINDOW_SECONDS,
        fanout_unique_ports_threshold: int = DEFAULT_FANOUT_UNIQUE_PORTS_THRESHOLD,
        fanout_velocity_threshold: float = DEFAULT_FANOUT_VELOCITY_THRESHOLD,
        src_burst_window_seconds: float = DEFAULT_SRC_BURST_WINDOW_SECONDS,
        src_burst_threshold: int = DEFAULT_SRC_BURST_THRESHOLD,
        src_portscan_window_seconds: float = DEFAULT_SRC_PORTSCAN_WINDOW_SECONDS,
        src_portscan_ports_threshold: int = DEFAULT_SRC_PORTSCAN_PORTS_THRESHOLD,
        src_dstfanout_window_seconds: float = DEFAULT_SRC_DSTFANOUT_WINDOW_SECONDS,
        src_dstfanout_hosts_threshold: int = DEFAULT_SRC_DSTFANOUT_HOSTS_THRESHOLD,
        src_slowscan_window_seconds: float = DEFAULT_SRC_SLOWSCAN_WINDOW_SECONDS,
        src_slowscan_ports_threshold: int = DEFAULT_SRC_SLOWSCAN_PORTS_THRESHOLD,
        max_src_entries: int = DEFAULT_MAX_SRC_ENTRIES,
    ) -> None:
        self.window_seconds = window_seconds
        self.ttl_seconds = ttl_seconds
        self.max_entries = max(0, max_entries)
        self.escalate_min_events = max(0, escalate_min_events)
        self.ddos_window_seconds = ddos_window_seconds
        self.ddos_flow_threshold = max(0, ddos_flow_threshold)
        self.ddos_unique_src_threshold = max(0, ddos_unique_src_threshold)
        self.fanout_window_seconds = max(0.0, fanout_window_seconds)
        self.fanout_unique_ports_threshold = max(0, fanout_unique_ports_threshold)
        self.fanout_velocity_threshold = max(0.0, fanout_velocity_threshold)
        self.src_burst_window_seconds = max(0.0, src_burst_window_seconds)
        self.src_burst_threshold = max(0, src_burst_threshold)
        self.src_portscan_window_seconds = max(0.0, src_portscan_window_seconds)
        self.src_portscan_ports_threshold = max(0, src_portscan_ports_threshold)
        self.src_dstfanout_window_seconds = max(0.0, src_dstfanout_window_seconds)
        self.src_dstfanout_hosts_threshold = max(0, src_dstfanout_hosts_threshold)
        self.src_slowscan_window_seconds = max(0.0, src_slowscan_window_seconds)
        self.src_slowscan_ports_threshold = max(0, src_slowscan_ports_threshold)
        self.max_src_entries = max(0, max_src_entries)

        self._store: OrderedDict[Tuple[str, str, int], _ContextEntry] = OrderedDict()
        self._ddos_store: Dict[str, _DstAggregate] = {}
        self._ddos_escalated_dsts: set = set()
        self._fanout_store: Dict[str, _DstPortFanout] = {}
        self._fanout_escalated_dsts: set = set()
        self._src_store: OrderedDict[str, _SrcContextEntry] = OrderedDict()
        self._src_burst_escalated: set = set()
        self._src_portscan_escalated: set = set()
        self._src_dstfanout_escalated: set = set()
        self._src_slowscan_escalated: set = set()

    def clear(self) -> None:
        """Clear all context memory (e.g. on startup to ensure clean state)."""
        self._store.clear()
        self._ddos_store.clear()
        self._ddos_escalated_dsts.clear()
        self._fanout_store.clear()
        self._fanout_escalated_dsts.clear()
        self._src_store.clear()
        self._src_burst_escalated.clear()
        self._src_portscan_escalated.clear()
        self._src_dstfanout_escalated.clear()
        self._src_slowscan_escalated.clear()

    def _get_or_create_entry(self, key: Tuple[str, str, int]) -> Optional[_ContextEntry]:
        if self.max_entries == 0:
            return None
        now = time.time()
        if key in self._store:
            entry = self._store[key]
            if self.ttl_seconds > 0 and (now - entry.last_seen_timestamp) > self.ttl_seconds:
                del self._store[key]
                entry = _ContextEntry(self.window_seconds)
                self._store[key] = entry
                self._store.move_to_end(key)
            else:
                self._store.move_to_end(key)
            return entry
        while len(self._store) >= self.max_entries:
            self._store.popitem(last=False)
        entry = _ContextEntry(self.window_seconds)
        self._store[key] = entry
        return entry

    def _get_or_create_ddos(self, dst_ip: str) -> _DstAggregate:
        if dst_ip not in self._ddos_store:
            self._ddos_store[dst_ip] = _DstAggregate(self.ddos_window_seconds)
        return self._ddos_store[dst_ip]

    def _get_or_create_fanout(self, dst_ip: str) -> _DstPortFanout:
        if dst_ip not in self._fanout_store:
            self._fanout_store[dst_ip] = _DstPortFanout(self.fanout_window_seconds)
        return self._fanout_store[dst_ip]

    def _get_or_create_src_entry(self, src_ip: str) -> Optional[_SrcContextEntry]:
        """Get or create per-src context; LRU eviction when over max_src_entries."""
        if self.max_src_entries == 0 or (src_ip or "").strip() == "" or src_ip == "UNKNOWN":
            return None
        src = (src_ip or "UNKNOWN").strip() or "UNKNOWN"
        if src in self._src_store:
            self._src_store.move_to_end(src)
            return self._src_store[src]
        while len(self._src_store) >= self.max_src_entries:
            self._src_store.popitem(last=False)
        self._src_store[src] = _SrcContextEntry(
            self.src_burst_window_seconds,
            self.src_portscan_window_seconds,
            self.src_dstfanout_window_seconds,
            self.src_slowscan_window_seconds,
        )
        return self._src_store[src]

    def update_and_escalate(
        self,
        src_ips: List[str],
        dst_ips: List[str],
        dst_ports: List[int],
        risk_scores: List[float],
        decisions: List[str],
        actions: List[str],
        timestamps: Optional[List[Any]] = None,
        low_thresh: float = 0.30,
        high_thresh: float = 0.60,
    ) -> Tuple[List[str], List[str], List[Dict[str, Any]]]:
        """
        Update context state and optionally escalate. Uses NAT-safe key
        (src_ip, dst_ip, dst_port). Returns (decisions_updated, actions_updated, context_events).
        context_events are dicts for smart logging (escalation_reason, suspicious_count, etc.).
        """
        n = len(src_ips)
        if n == 0:
            return decisions, actions, []
        if timestamps is None:
            timestamps = [None] * n
        elif len(timestamps) != n:
            timestamps = (list(timestamps) + [None] * n)[:n]
        if len(dst_ips) != n:
            dst_ips = (list(dst_ips) + ["UNKNOWN"] * n)[:n]
        if len(dst_ports) != n:
            dst_ports = (list(dst_ports) + [0] * n)[:n]

        now = time.time()
        decisions_out = list(decisions)
        actions_out = list(actions)
        context_events: List[Dict[str, Any]] = []

        for i in range(n):
            src = (src_ips[i] or "UNKNOWN").strip() or "UNKNOWN"
            dst = (dst_ips[i] if i < len(dst_ips) else "UNKNOWN").strip() or "UNKNOWN"
            dport = int(dst_ports[i]) if i < len(dst_ports) and dst_ports[i] is not None else 0
            risk = float(risk_scores[i]) if i < len(risk_scores) else 0.0
            ts = _parse_timestamp(timestamps[i]) if i < len(timestamps) else 0.0
            if ts <= 0:
                ts = now

            key = _context_key(src, dst, dport)
            entry = self._get_or_create_entry(key)
            if entry is not None:
                entry.add(ts, risk, low_thresh)
                if self.escalate_min_events > 0 and entry.suspicious_count >= self.escalate_min_events:
                    cur = decisions_out[i]
                    if cur in ("MEDIUM", "LOW"):
                        decisions_out[i] = "HIGH"
                        actions_out[i] = "BLOCK"
                        entry.escalation_level = 2
                        context_events.append({
                            "timestamp": datetime_iso(ts),
                            "context_key": f"{key[0]}|{key[1]}|{key[2]}",
                            "event_type": "escalation",
                            "escalation_reason": f"suspicious_count >= {self.escalate_min_events}",
                            "suspicious_count": entry.suspicious_count,
                        })

            if self.ddos_flow_threshold > 0 and self.ddos_unique_src_threshold > 0 and dst != "UNKNOWN":
                agg = self._get_or_create_ddos(dst)
                agg.add(ts, src)
                flows = agg.flows_per_dst_ip()
                unique_srcs = agg.unique_src_ips_per_dst_ip()
                if flows >= self.ddos_flow_threshold and unique_srcs >= self.ddos_unique_src_threshold:
                    if dst not in self._ddos_escalated_dsts:
                        self._ddos_escalated_dsts.add(dst)
                        context_events.append({
                            "timestamp": datetime_iso(ts),
                            "context_key": dst,
                            "event_type": "distributed_attack",
                            "escalation_reason": "ddos_thresholds_exceeded",
                            "suspicious_count": flows,
                            "unique_src_ips": unique_srcs,
                        })

            # Destination port fan-out (reconnaissance / port sweep detection)
            if (
                self.fanout_unique_ports_threshold > 0
                and dst != "UNKNOWN"
                and self.fanout_window_seconds > 0
            ):
                fanout = self._get_or_create_fanout(dst)
                fanout.add(ts, src, dport)
                unique_ports = fanout.unique_dst_ports_per_dst_ip()
                velocity = fanout.fanout_velocity()
                ports_ok = unique_ports >= self.fanout_unique_ports_threshold
                velocity_ok = (
                    self.fanout_velocity_threshold <= 0
                    or velocity >= self.fanout_velocity_threshold
                )
                if ports_ok and velocity_ok and dst not in self._fanout_escalated_dsts:
                    self._fanout_escalated_dsts.add(dst)
                    context_events.append({
                        "timestamp": datetime_iso(ts),
                        "context_key": dst,
                        "event_type": "destination_port_fanout",
                        "escalation_reason": "fanout_thresholds_exceeded",
                        "unique_dst_ports": unique_ports,
                        "fanout_velocity": round(velocity, 4),
                        "window_seconds": self.fanout_window_seconds,
                    })

            # Source-side signals (burst, port scan, host sweep, slow scan)
            src_entry = self._get_or_create_src_entry(src)
            if src_entry is not None:
                src_entry.add(ts, dst, dport)
                if self.src_burst_threshold > 0 and self.src_burst_window_seconds > 0:
                    flows = src_entry.flows_in_burst_window()
                    if flows >= self.src_burst_threshold and src not in self._src_burst_escalated:
                        self._src_burst_escalated.add(src)
                        context_events.append({
                            "timestamp": datetime_iso(ts),
                            "event_type": "source_flow_burst",
                            "src_ip": src,
                            "window_seconds": self.src_burst_window_seconds,
                            "observed_count": flows,
                            "threshold": self.src_burst_threshold,
                        })
                if self.src_portscan_ports_threshold > 0 and self.src_portscan_window_seconds > 0:
                    uports = src_entry.unique_ports_portscan()
                    if uports >= self.src_portscan_ports_threshold and src not in self._src_portscan_escalated:
                        self._src_portscan_escalated.add(src)
                        context_events.append({
                            "timestamp": datetime_iso(ts),
                            "event_type": "source_port_scan",
                            "src_ip": src,
                            "window_seconds": self.src_portscan_window_seconds,
                            "observed_count": uports,
                            "threshold": self.src_portscan_ports_threshold,
                        })
                if self.src_dstfanout_hosts_threshold > 0 and self.src_dstfanout_window_seconds > 0:
                    udsts = src_entry.unique_dsts_fanout()
                    if udsts >= self.src_dstfanout_hosts_threshold and src not in self._src_dstfanout_escalated:
                        self._src_dstfanout_escalated.add(src)
                        context_events.append({
                            "timestamp": datetime_iso(ts),
                            "event_type": "source_dst_fanout",
                            "src_ip": src,
                            "window_seconds": self.src_dstfanout_window_seconds,
                            "observed_count": udsts,
                            "threshold": self.src_dstfanout_hosts_threshold,
                        })
                if self.src_slowscan_ports_threshold > 0 and self.src_slowscan_window_seconds > 0:
                    uports_slow = src_entry.unique_ports_slowscan()
                    if uports_slow >= self.src_slowscan_ports_threshold and src not in self._src_slowscan_escalated:
                        self._src_slowscan_escalated.add(src)
                        context_events.append({
                            "timestamp": datetime_iso(ts),
                            "event_type": "source_slow_scan",
                            "src_ip": src,
                            "window_seconds": self.src_slowscan_window_seconds,
                            "observed_count": uports_slow,
                            "threshold": self.src_slowscan_ports_threshold,
                        })

        for i in range(n):
            dst = (dst_ips[i] if i < len(dst_ips) else "UNKNOWN").strip() or "UNKNOWN"
            src = (src_ips[i] or "UNKNOWN").strip() or "UNKNOWN"
            if dst in self._ddos_escalated_dsts and decisions_out[i] in ("LOW", "MEDIUM"):
                decisions_out[i] = "HIGH"
                actions_out[i] = "BLOCK"
            if dst in self._fanout_escalated_dsts and decisions_out[i] in ("LOW", "MEDIUM"):
                decisions_out[i] = "HIGH"
                actions_out[i] = "BLOCK"
            if src in self._src_burst_escalated and decisions_out[i] in ("LOW", "MEDIUM"):
                decisions_out[i] = "HIGH"
                actions_out[i] = "BLOCK"
            if src in self._src_portscan_escalated and decisions_out[i] in ("LOW", "MEDIUM"):
                decisions_out[i] = "HIGH"
                actions_out[i] = "BLOCK"
            if src in self._src_dstfanout_escalated and decisions_out[i] in ("LOW", "MEDIUM"):
                decisions_out[i] = "HIGH"
                actions_out[i] = "BLOCK"
            if src in self._src_slowscan_escalated and decisions_out[i] in ("LOW", "MEDIUM"):
                decisions_out[i] = "HIGH"
                actions_out[i] = "BLOCK"

        return decisions_out, actions_out, context_events

    def size(self) -> int:
        """Current number of context entries (per-key store)."""
        return len(self._store)


def datetime_iso(ts: float) -> str:
    """Epoch float to ISO timestamp string."""
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return str(ts)


def create_context_engine(
    enabled: bool = True,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ttl_seconds: float = DEFAULT_TTL_SECONDS,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    escalate_min_events: int = DEFAULT_ESCALATE_MIN_EVENTS,
    ddos_window_seconds: float = DEFAULT_DDOS_WINDOW_SECONDS,
    ddos_flow_threshold: int = DEFAULT_DDOS_FLOW_THRESHOLD,
    ddos_unique_src_threshold: int = DEFAULT_DDOS_UNIQUE_SRC_THRESHOLD,
    fanout_window_seconds: float = DEFAULT_FANOUT_WINDOW_SECONDS,
    fanout_unique_ports_threshold: int = DEFAULT_FANOUT_UNIQUE_PORTS_THRESHOLD,
    fanout_velocity_threshold: float = DEFAULT_FANOUT_VELOCITY_THRESHOLD,
    src_burst_window_seconds: float = DEFAULT_SRC_BURST_WINDOW_SECONDS,
    src_burst_threshold: int = DEFAULT_SRC_BURST_THRESHOLD,
    src_portscan_window_seconds: float = DEFAULT_SRC_PORTSCAN_WINDOW_SECONDS,
    src_portscan_ports_threshold: int = DEFAULT_SRC_PORTSCAN_PORTS_THRESHOLD,
    src_dstfanout_window_seconds: float = DEFAULT_SRC_DSTFANOUT_WINDOW_SECONDS,
    src_dstfanout_hosts_threshold: int = DEFAULT_SRC_DSTFANOUT_HOSTS_THRESHOLD,
    src_slowscan_window_seconds: float = DEFAULT_SRC_SLOWSCAN_WINDOW_SECONDS,
    src_slowscan_ports_threshold: int = DEFAULT_SRC_SLOWSCAN_PORTS_THRESHOLD,
    max_src_entries: int = DEFAULT_MAX_SRC_ENTRIES,
) -> ContextEngine:
    """Create a ContextEngine. If enabled=False or max_entries=0, updates will no-op (state not stored)."""
    if not enabled or max_entries <= 0:
        return ContextEngine(
            window_seconds=window_seconds,
            ttl_seconds=ttl_seconds,
            max_entries=0,
            escalate_min_events=escalate_min_events,
            ddos_window_seconds=ddos_window_seconds,
            ddos_flow_threshold=0,
            ddos_unique_src_threshold=0,
            fanout_window_seconds=fanout_window_seconds,
            fanout_unique_ports_threshold=0,
            fanout_velocity_threshold=0.0,
            src_burst_window_seconds=src_burst_window_seconds,
            src_burst_threshold=0,
            src_portscan_window_seconds=src_portscan_window_seconds,
            src_portscan_ports_threshold=0,
            src_dstfanout_window_seconds=src_dstfanout_window_seconds,
            src_dstfanout_hosts_threshold=0,
            src_slowscan_window_seconds=src_slowscan_window_seconds,
            src_slowscan_ports_threshold=0,
            max_src_entries=0,  # no source-side tracking when disabled
        )
    engine = ContextEngine(
        window_seconds=window_seconds,
        ttl_seconds=ttl_seconds,
        max_entries=max_entries,
        escalate_min_events=escalate_min_events,
        ddos_window_seconds=ddos_window_seconds,
        ddos_flow_threshold=ddos_flow_threshold,
        ddos_unique_src_threshold=ddos_unique_src_threshold,
        fanout_window_seconds=fanout_window_seconds,
        fanout_unique_ports_threshold=fanout_unique_ports_threshold,
        fanout_velocity_threshold=fanout_velocity_threshold,
        src_burst_window_seconds=src_burst_window_seconds,
        src_burst_threshold=src_burst_threshold,
        src_portscan_window_seconds=src_portscan_window_seconds,
        src_portscan_ports_threshold=src_portscan_ports_threshold,
        src_dstfanout_window_seconds=src_dstfanout_window_seconds,
        src_dstfanout_hosts_threshold=src_dstfanout_hosts_threshold,
        src_slowscan_window_seconds=src_slowscan_window_seconds,
        src_slowscan_ports_threshold=src_slowscan_ports_threshold,
        max_src_entries=max_src_entries,
    )
    engine.clear()
    return engine
