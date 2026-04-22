"""
Flow-centric behavioral feature engine.

TCP flags are read only from the optional ``tcp`` object on **flow** events (no separate
``event_type=="tcp"`` stream). When ``tcp`` is absent, TCP-derived aggregates use zero
counters and ``has_tcp`` is 0 so the model can distinguish missing metadata from true zeros.
"""

from __future__ import annotations

import json
import logging
import math
import os
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

import numpy as np

EPS = 1e-6
W10 = 10.0
W60 = 60.0
W300 = 300.0
W24H = 86400.0

THETA_SMALL = 128.0
THETA_REQ = 256.0
THETA_SHORT = 1.0
THETA_INCOMPLETE = 1.0
THETA_RATE = 64.0
THETA_LONG = 120.0
THETA_LOW = 512.0

logger = logging.getLogger(__name__)

# First-N sample running sums for optional distribution logging (UNIFIED_FEATURE_DIST_MAX > 0).
_FEATURE_DIST_N = 0
_FEATURE_DIST_SUMS: List[float] = [0.0, 0.0, 0.0, 0.0, 0.0]


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        x = float(v)
        return x if np.isfinite(x) else default
    except (TypeError, ValueError):
        return default


def _flow_id(ev: Dict[str, Any]) -> str:
    v = ev.get("flow_id")
    if v is None:
        return ""
    s = str(v).strip()
    return s


def _ts_from_ev(ev: Dict[str, Any]) -> float:
    flow = ev.get("flow") or {}
    raw = flow.get("start") or flow.get("end") or ev.get("timestamp")
    if raw is None:
        return 0.0
    if isinstance(raw, (int, float)):
        return float(raw)
    s = str(raw).strip()
    if not s:
        return 0.0
    try:
        # Handle trailing Z and +HHMM offsets.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        if len(s) >= 5 and (s[-5] in "+-") and s[-3] != ":" and s[-4:].isdigit():
            s = s[:-5] + s[-5:-2] + ":" + s[-2:]
        dt = datetime.fromisoformat(s.replace(" ", "T"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return float(dt.timestamp())
    except Exception:
        return 0.0


def _entropy_from_counter(counter: Counter) -> float:
    n = float(sum(counter.values()))
    if n <= 0:
        return 0.0
    e = 0.0
    for c in counter.values():
        if c <= 0:
            continue
        p = c / n
        e -= p * math.log2(p + EPS)
    return float(e)


def _autocorr(values: List[float]) -> float:
    if len(values) < 3:
        return 0.0
    x = np.asarray(values[:-1], dtype=np.float64)
    y = np.asarray(values[1:], dtype=np.float64)
    sx = float(np.std(x))
    sy = float(np.std(y))
    if sx <= EPS or sy <= EPS:
        return 0.0
    return float(np.corrcoef(x, y)[0, 1])


def _maybe_debug_feature_audit(
    row: Dict[str, Any],
    q_src60: Deque[Any],
    len_src60: int,
    unique_src_ips_by_dst_60s: float,
) -> None:
    """Optional consistency checks: UNIFIED_FEATURE_DEBUG_ASSERT=1."""
    v = os.environ.get("UNIFIED_FEATURE_DEBUG_ASSERT", "").strip().lower()
    if v not in {"1", "true", "yes", "on"}:
        return
    rst_micro = float(row.get("rst_micro_flow_ratio_src_60s", 0.0) or 0.0)
    if rst_micro > 0.0 and len_src60 >= 5:
        syn_flows = sum(1 for r in q_src60 if r[9] > 0)
        if syn_flows > int(0.85 * len_src60) and rst_micro > 0.3:
            logger.warning(
                "[feature_audit] high rst_micro_flow_ratio_src_60s=%.4f but syn-heavy window (%d/%d flows with SYN)",
                rst_micro,
                syn_flows,
                len_src60,
            )
    ent = float(row.get("dst_src_ip_entropy_60s", 0.0) or 0.0)
    if ent > 1e-6 and unique_src_ips_by_dst_60s <= 1.0 + 1e-9:
        logger.warning(
            "[feature_audit] dst_src_ip_entropy_60s=%.4f but unique_src_ips_by_dst_60s=%.4f",
            ent,
            unique_src_ips_by_dst_60s,
        )


def _maybe_log_feature_dist_first_n(
    f40: float,
    f41: float,
    f42: float,
    f43: float,
    f44: float,
) -> None:
    """Log mean of new features over first N rows (UNIFIED_FEATURE_DIST_MAX, default 0 = off)."""
    global _FEATURE_DIST_N, _FEATURE_DIST_SUMS
    try:
        cap = int(os.environ.get("UNIFIED_FEATURE_DIST_MAX", "0") or "0")
    except ValueError:
        cap = 0
    if cap <= 0:
        return
    if _FEATURE_DIST_N >= cap:
        return
    _FEATURE_DIST_N += 1
    vals = (f40, f41, f42, f43, f44)
    for i, v in enumerate(vals):
        _FEATURE_DIST_SUMS[i] += float(v) if np.isfinite(v) else 0.0
    if _FEATURE_DIST_N == cap:
        n = float(_FEATURE_DIST_N)
        logger.info(
            "[feature_dist] first %d samples mean: rst_micro=%.6f dst_port_focus=%.6f rst_ack=%.6f "
            "dst_ent=%.6f avg_flow_src_dst=%.6f",
            cap,
            _FEATURE_DIST_SUMS[0] / n,
            _FEATURE_DIST_SUMS[1] / n,
            _FEATURE_DIST_SUMS[2] / n,
            _FEATURE_DIST_SUMS[3] / n,
            _FEATURE_DIST_SUMS[4] / n,
        )


def _default_tcp_stats() -> Dict[str, float]:
    return {
        "syn_count": 0.0,
        "ack_count": 0.0,
        "rst_count": 0.0,
        "fin_count": 0.0,
        "total_packets": 0.0,
    }


def _bool_tcp_flag(tcp: Dict[str, Any], key: str) -> float:
    return 1.0 if bool(tcp.get(key)) else 0.0


def tcp_stats_and_has_tcp_from_flow(ev: Dict[str, Any]) -> Tuple[Dict[str, float], float]:
    """
    Per-flow TCP snapshot from ``ev["tcp"]`` only. Returns (stats, has_tcp) with has_tcp in {0.0, 1.0}.
    """
    tcp = ev.get("tcp")
    if not isinstance(tcp, dict):
        return _default_tcp_stats(), 0.0
    syn = _bool_tcp_flag(tcp, "syn")
    ack = _bool_tcp_flag(tcp, "ack")
    rst = _bool_tcp_flag(tcp, "rst")
    fin = _bool_tcp_flag(tcp, "fin")
    flag_sum = syn + ack + rst + fin
    total = flag_sum if flag_sum > 0.0 else 1.0
    return (
        {
            "syn_count": syn,
            "ack_count": ack,
            "rst_count": rst,
            "fin_count": fin,
            "total_packets": total,
        },
        1.0,
    )


class FlowTcpBehavioralEngine:
    def __init__(self) -> None:
        # main windows
        # rec tuple: ts, src, dst, dst_port, dur, fwd, rev, total, fid, syn, ack, rst, fin, tcp_pkts
        self.src_10: Dict[str, Deque[Tuple[float, str, str, int, float, float, float, float, str, int, int, int, int, int]]] = defaultdict(deque)
        self.src_60 = defaultdict(deque)
        self.src_300 = defaultdict(deque)
        self.src_24h = defaultdict(deque)

        self.dst_10: Dict[str, Deque[Tuple[float, str, str, int, float, float, float, float, str, int, int, int, int, int]]] = defaultdict(deque)
        self.dst_60 = defaultdict(deque)

        self.srcdst_300: Dict[Tuple[str, str], Deque[Tuple[float, str, str, int, float, float, float, float, str, int, int, int, int, int]]] = defaultdict(deque)
        self.srcdst_24h: Dict[Tuple[str, str], Deque[Tuple[float, str, str, int, float, float, float, float, str, int, int, int, int, int]]] = defaultdict(deque)

        self.dst_port_active_10: Dict[Tuple[str, int], Deque[Tuple[float, float]]] = defaultdict(deque)
        self.src_active_10: Dict[str, Deque[Tuple[float, float]]] = defaultdict(deque)
        self.dst_active_10: Dict[str, Deque[Tuple[float, float]]] = defaultdict(deque)

    @staticmethod
    def _prune_q(q: Deque, now: float, w: float) -> None:
        c = now - w
        while q and q[0][0] < c:
            q.popleft()

    @staticmethod
    def _prune_active(q: Deque[Tuple[float, float]], now: float, w: float) -> None:
        c = now - w
        while q and (q[0][1] < now or q[0][0] < c):
            q.popleft()

    @staticmethod
    def _iat(timestamps: Iterable[float]) -> List[float]:
        ts = sorted(float(x) for x in timestamps)
        if len(ts) < 2:
            return []
        return [ts[i] - ts[i - 1] for i in range(1, len(ts))]

    def build_row_from_flow(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        fid = _flow_id(ev)
        tcp_stats, has_tcp = tcp_stats_and_has_tcp_from_flow(ev)

        ts = _ts_from_ev(ev)
        src = str(ev.get("src_ip", "")).strip() or "UNKNOWN"
        dst = str(ev.get("dest_ip", "")).strip() or "UNKNOWN"
        dst_port = _safe_int(ev.get("dest_port", 0))
        flow = ev.get("flow") or {}
        dur = max(0.0, _safe_float(flow.get("age", 0.0)))
        end = ts + dur
        fwd = float(_safe_int(flow.get("bytes_toserver", 0)))
        rev = float(_safe_int(flow.get("bytes_toclient", 0)))
        total = fwd + rev

        rec = (
            ts,
            src,
            dst,
            dst_port,
            dur,
            fwd,
            rev,
            total,
            fid,
            int(tcp_stats["syn_count"]),
            int(tcp_stats["ack_count"]),
            int(tcp_stats["rst_count"]),
            int(tcp_stats["fin_count"]),
            int(tcp_stats["total_packets"]),
        )

        q_src10 = self.src_10[src]
        q_src60 = self.src_60[src]
        q_src300 = self.src_300[src]
        q_src24h = self.src_24h[src]
        q_dst10 = self.dst_10[dst]
        q_dst60 = self.dst_60[dst]
        q_sdp300 = self.srcdst_300[(src, dst)]
        q_sdp24h = self.srcdst_24h[(src, dst)]

        for q, w in (
            (q_src10, W10),
            (q_src60, W60),
            (q_src300, W300),
            (q_src24h, W24H),
            (q_dst10, W10),
            (q_dst60, W60),
            (q_sdp300, W300),
            (q_sdp24h, W24H),
        ):
            self._prune_q(q, ts, w)

        sact = self.src_active_10[src]
        dact = self.dst_active_10[dst]
        pact = self.dst_port_active_10[(dst, dst_port)]
        self._prune_active(sact, ts, W10)
        self._prune_active(dact, ts, W10)
        self._prune_active(pact, ts, W10)

        len_src10 = len(q_src10)
        len_src60 = len(q_src60)
        len_src300 = len(q_src300)
        len_src24h = len(q_src24h)
        len_dst10 = len(q_dst10)
        len_sdp24h = len(q_sdp24h)

        flow_rate_src_10s = len_src10 / W10
        flow_rate_src_60s = len_src60 / W60
        flow_rate_dst_10s = len_dst10 / W10
        flow_rate_src_300 = len_src300 / W300
        rate_ratio_src_10s_60s = flow_rate_src_10s / (flow_rate_src_60s + EPS)
        rate_ratio_src_60s_300s = flow_rate_src_60s / (flow_rate_src_300 + EPS)

        concurrent_flows_src_10s = float(sum(1 for st, en in sact if st <= ts <= en))
        concurrent_flows_dst_10s = float(sum(1 for st, en in dact if st <= ts <= en))
        concurrent_flows_per_dst_port_10s = float(sum(1 for st, en in pact if st <= ts <= en))

        unique_src_ips_by_dst_60s = float(len({r[1] for r in q_dst60}))
        dst_ip_unique_src_ips_10s = float(len({r[1] for r in q_dst10}))

        dsts300 = [r[2] for r in q_src300]
        ports300 = [r[3] for r in q_src300]
        n300 = len(dsts300)
        if n300 > 1:
            new_dst_ip_ratio_src_300s = float(len(set(dsts300)) / n300)
            new_dst_ips_per_sec = float(len(set(dsts300)) / W300)
            new_dst_port_ratio_src_300s = float(len(set(ports300)) / n300)
            new_dst_ports_per_sec = float(len(set(ports300)) / W300)
        else:
            new_dst_ip_ratio_src_300s = 0.0
            new_dst_ips_per_sec = 0.0
            new_dst_port_ratio_src_300s = 0.0
            new_dst_ports_per_sec = 0.0
        dst_ip_entropy_src_300s = _entropy_from_counter(Counter(dsts300))
        dst_port_entropy_src_300s = _entropy_from_counter(Counter(ports300))

        iat_src_60 = self._iat([r[0] for r in q_src60])
        iat_cv_src_60s = (
            float(np.std(iat_src_60) / (np.mean(iat_src_60) + EPS)) if iat_src_60 else 0.0
        )

        syn60 = float(sum(r[9] for r in q_src60))
        ack60 = float(sum(r[10] for r in q_src60))
        rst60 = float(sum(r[11] for r in q_src60))
        tcp_pkts60 = float(sum(r[13] for r in q_src60))
        n_src60_f = float(len_src60)
        small_response_ratio_src_60s = (
            float(sum(1 for r in q_src60 if r[6] < THETA_SMALL and r[5] > THETA_REQ)) / n_src60_f
            if len_src60 > 0
            else 0.0
        )

        iat_srcdst_300 = self._iat([r[0] for r in q_sdp300])
        iat_cv_srcdst_300s = (
            float(np.std(iat_srcdst_300) / (np.mean(iat_srcdst_300) + EPS)) if iat_srcdst_300 else 0.0
        )
        iat_autocorr_srcdst_300s = _autocorr(iat_srcdst_300)

        bytes_ratio_fwd_rev = fwd / (rev + 1.0)
        short_flow_ratio_src_300s = (
            float(sum(1 for r in q_src300 if r[4] < THETA_SHORT)) / (n300 + EPS) if n300 else 0.0
        )
        avg_bytes_per_flow_src_300s = (
            float(sum(r[7] for r in q_src300) / (n300 + EPS)) if n300 else 0.0
        )
        bytes_per_flow_srcdst = (
            float(sum(r[7] for r in q_sdp24h) / (len_sdp24h + EPS)) if len_sdp24h else 0.0
        )
        connection_reuse_ratio_srcdst = float(len_sdp24h) / (float(len_src24h) + EPS)

        if q_src300:
            bins = [int(r[7] // 128) for r in q_src300]
            flow_size_mode_src_300s = float(Counter(bins).most_common(1)[0][0])
        else:
            flow_size_mode_src_300s = 0.0

        pair300 = [(r[2], r[3]) for r in q_src300]
        c_pair300 = Counter(pair300)
        retry_rate_same_dstport_300s = (
            float(sum(v - 1 for v in c_pair300.values() if v > 1)) / (n300 + EPS) if n300 else 0.0
        )
        c_dst300 = Counter([r[2] for r in q_src300])
        retry_rate_same_dstip_300s = (
            float(sum(v - 1 for v in c_dst300.values() if v > 1)) / (n300 + EPS) if n300 else 0.0
        )
        dst_port_reuse_ratio_src_300s = (
            float(max(Counter(ports300).values()) / (n300 + EPS)) if ports300 else 0.0
        )

        syn_heavy_ratio_src_60s = syn60 / (tcp_pkts60 + EPS)
        syn_to_established_ratio = syn60 / (ack60 + EPS)
        rst_ratio_src_60s = rst60 / (n_src60_f + EPS)
        rst_to_syn_ratio_src_60s = rst60 / (syn60 + EPS)

        flag_counter = Counter()
        flag_counter["SYN"] = int(syn60)
        flag_counter["ACK"] = int(ack60)
        flag_counter["RST"] = int(rst60)
        flag_counter["FIN"] = int(sum(r[12] for r in q_src60))
        tcp_flag_entropy_src_60s = _entropy_from_counter(flag_counter)

        ack_presence_ratio = (
            float(sum(1 for r in q_src300 if r[10] > 0)) / (n300 + EPS) if n300 else 0.0
        )
        incomplete_flow_duration_ratio_src_300s = (
            float(sum(1 for r in q_src300 if r[4] < THETA_INCOMPLETE)) / (n300 + EPS) if n300 else 0.0
        )
        low_data_rate_long_flow_ratio_src_300s = (
            float(
                sum(
                    1
                    for r in q_src300
                    if r[4] > THETA_LONG and (r[7] / (r[4] + EPS)) < THETA_RATE
                )
            )
            / (n300 + EPS)
            if n300
            else 0.0
        )
        src_contribution_to_dst_ratio_60s = (
            float(sum(1 for r in q_dst60 if r[1] == src)) / (len(q_dst60) + EPS) if q_dst60 else 0.0
        )

        dst_src_ip_entropy_60s = _entropy_from_counter(Counter(r[1] for r in q_dst60))
        avg_flow_per_src_to_dst_10s = float(len_dst10) / (dst_ip_unique_src_ips_10s + EPS)

        if len_src60 < 5:
            rst_micro_flow_ratio_src_60s = 0.0
            single_dst_port_focus_src_60s = 0.0
            rst_after_ack_ratio_src_60s = 0.0
            iat_regularity_src_60s = 0.0
        else:
            n_src60_f = float(len_src60)
            rst_micro_count = sum(
                1
                for r in q_src60
                if (
                    r[11] > 0
                    and r[4] <= 0.5
                    and r[7] <= 150
                    and r[5] <= 120
                    and r[6] <= 120
                )
            )
            rst_micro_flow_ratio_src_60s = float(rst_micro_count) / (n_src60_f + EPS)
            port_counts = Counter(r[3] for r in q_src60)
            max_port_count = max(port_counts.values()) if port_counts else 0
            single_dst_port_focus_src_60s = float(max_port_count) / (n_src60_f + EPS)
            c_rst_ack = sum(1 for r in q_src60 if r[10] > 0 and r[11] > 0)
            rst_after_ack_ratio_src_60s = float(c_rst_ack) / (n_src60_f + EPS)
            if iat_cv_src_60s > 0.0:
                iat_regularity_src_60s = 1.0 / (iat_cv_src_60s + EPS)
            else:
                iat_regularity_src_60s = 0.0

        if has_tcp == 0.0:
            rst_after_ack_ratio_src_60s = 0.0

        row = {
            "flow_id": fid,
            "flow_rate_src_10s": flow_rate_src_10s,
            "flow_rate_src_60s": flow_rate_src_60s,
            "flow_rate_dst_10s": flow_rate_dst_10s,
            "rate_ratio_src_10s_60s": rate_ratio_src_10s_60s,
            "rate_ratio_src_60s_300s": rate_ratio_src_60s_300s,
            "concurrent_flows_src_10s": concurrent_flows_src_10s,
            "concurrent_flows_dst_10s": concurrent_flows_dst_10s,
            "concurrent_flows_per_dst_port_10s": concurrent_flows_per_dst_port_10s,
            "unique_src_ips_by_dst_60s": unique_src_ips_by_dst_60s,
            "dst_ip_unique_src_ips_10s": dst_ip_unique_src_ips_10s,
            "new_dst_ip_ratio_src_300s": new_dst_ip_ratio_src_300s,
            "new_dst_port_ratio_src_300s": new_dst_port_ratio_src_300s,
            "new_dst_ips_per_sec": new_dst_ips_per_sec,
            "new_dst_ports_per_sec": new_dst_ports_per_sec,
            "dst_ip_entropy_src_300s": dst_ip_entropy_src_300s,
            "dst_port_entropy_src_300s": dst_port_entropy_src_300s,
            "iat_cv_src_60s": iat_cv_src_60s,
            "iat_cv_srcdst_300s": iat_cv_srcdst_300s,
            "iat_autocorr_srcdst_300s": iat_autocorr_srcdst_300s,
            "bytes_ratio_fwd_rev": bytes_ratio_fwd_rev,
            "short_flow_ratio_src_300s": short_flow_ratio_src_300s,
            "avg_bytes_per_flow_src_300s": avg_bytes_per_flow_src_300s,
            "bytes_per_flow_srcdst": bytes_per_flow_srcdst,
            "connection_reuse_ratio_srcdst": connection_reuse_ratio_srcdst,
            "flow_size_mode_src_300s": flow_size_mode_src_300s,
            "retry_rate_same_dstport_300s": retry_rate_same_dstport_300s,
            "retry_rate_same_dstip_300s": retry_rate_same_dstip_300s,
            "dst_port_reuse_ratio_src_300s": dst_port_reuse_ratio_src_300s,
            "syn_heavy_ratio_src_60s": syn_heavy_ratio_src_60s,
            "syn_to_established_ratio": syn_to_established_ratio,
            "rst_ratio_src_60s": rst_ratio_src_60s,
            "rst_to_syn_ratio_src_60s": rst_to_syn_ratio_src_60s,
            "tcp_flag_entropy_src_60s": tcp_flag_entropy_src_60s,
            "ack_presence_ratio": ack_presence_ratio,
            "small_response_ratio_src_60s": small_response_ratio_src_60s,
            "incomplete_flow_duration_ratio_src_300s": incomplete_flow_duration_ratio_src_300s,
            "low_data_rate_long_flow_ratio_src_300s": low_data_rate_long_flow_ratio_src_300s,
            "src_contribution_to_dst_ratio_60s": src_contribution_to_dst_ratio_60s,
            "rst_micro_flow_ratio_src_60s": rst_micro_flow_ratio_src_60s,
            "single_dst_port_focus_src_60s": single_dst_port_focus_src_60s,
            "rst_after_ack_ratio_src_60s": rst_after_ack_ratio_src_60s,
            "dst_src_ip_entropy_60s": dst_src_ip_entropy_60s,
            "avg_flow_per_src_to_dst_10s": avg_flow_per_src_to_dst_10s,
            "iat_regularity_src_60s": iat_regularity_src_60s,
            "has_tcp": has_tcp,
        }

        _maybe_debug_feature_audit(row, q_src60, len_src60, unique_src_ips_by_dst_60s)
        _maybe_log_feature_dist_first_n(
            rst_micro_flow_ratio_src_60s,
            single_dst_port_focus_src_60s,
            rst_after_ack_ratio_src_60s,
            dst_src_ip_entropy_60s,
            avg_flow_per_src_to_dst_10s,
        )

        # Debug instrumentation (mandatory for audit):
        # Print flow_id + the TCP counters used for this flow row.
        if os.environ.get("DEBUG_PARITY_AUDIT", "").strip().lower() in {"1", "true", "yes", "on"}:
            limit_raw = os.environ.get("DEBUG_PARITY_AUDIT_LIMIT", "5")
            try:
                limit = int(limit_raw)
            except ValueError:
                limit = 5
            n = getattr(self, "_dbg_emit_count", 0)
            if n < limit:
                print(
                    f"[AUDIT][extract] emit flow_id={fid!r} ts={ts:.6f} "
                    f"tcp_syn={tcp_stats.get('syn_count', 0.0)} tcp_ack={tcp_stats.get('ack_count', 0.0)} "
                    f"tcp_rst={tcp_stats.get('rst_count', 0.0)} tcp_fin={tcp_stats.get('fin_count', 0.0)} "
                    f"tcp_total_packets={tcp_stats.get('total_packets', 0.0)} src={src!r} dst={dst!r} dst_port={dst_port}",
                    file=sys.stderr,
                )
                setattr(self, "_dbg_emit_count", n + 1)

        # Update windows with current flow after computing context.
        q_src10.append(rec)
        q_src60.append(rec)
        q_src300.append(rec)
        q_src24h.append(rec)
        q_dst10.append(rec)
        q_dst60.append(rec)
        q_sdp300.append(rec)
        q_sdp24h.append(rec)
        sact.append((ts, end))
        dact.append((ts, end))
        pact.append((ts, end))
        return row


def stream_join_extract_rows(
    eve_path: Path,
    *,
    legacy_raw_eve_stream: Optional[bool] = None,
) -> Iterable[Dict[str, Any]]:
    _ = legacy_raw_eve_stream  # backward compatibility; ignored
    engine = FlowTcpBehavioralEngine()
    with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
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
            if et == "flow":
                yield engine.build_row_from_flow(ev)

