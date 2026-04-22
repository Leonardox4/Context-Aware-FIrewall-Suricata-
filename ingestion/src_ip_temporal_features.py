"""
Per-src_ip sliding-window state for high-signal temporal features (10s / 60s).

Used by unified behavioral extraction and runtime scoring. O(1) amortized per event:
expire from the front of deques and adjust keyed counters; append current event; emit features.

All windows use the same event timestamp axis as Suricata EVE (epoch seconds).
"""

from __future__ import annotations

from collections import Counter, deque, OrderedDict
from typing import Any, Deque, Dict, Tuple

W10 = 10.0
W60 = 60.0
MAX_SRC_IPS = 100_000

Rec = Tuple[float, str, int]  # ts, dst_ip, dst_port


class SrcIpTemporalTracker:
    """
    Rolling 10s / 60s queues per src_ip with frequency maps for (dst_ip, dst_port) and dst_ip.
    """

    __slots__ = ("_per_src", "_fifo")

    def __init__(self) -> None:
        self._per_src: Dict[str, Dict[str, Any]] = {}
        self._fifo: "OrderedDict[str, None]" = OrderedDict()

    def _ensure(self, src_ip: str) -> Dict[str, Any]:
        if src_ip not in self._per_src:
            while len(self._per_src) >= MAX_SRC_IPS and self._fifo:
                evict, _ = self._fifo.popitem(last=False)
                self._per_src.pop(evict, None)
            self._per_src[src_ip] = {
                "q10": deque(),  # type: Deque[Rec]
                "q60": deque(),  # type: Deque[Rec]
                "c10_pair": Counter(),
                "c60_pair": Counter(),
                "c60_dst": Counter(),
            }
            self._fifo[src_ip] = None
        else:
            self._fifo.move_to_end(src_ip, last=True)
        return self._per_src[src_ip]

    @staticmethod
    def _pop_older(q: Deque[Rec], cutoff: float, c_pair: Counter, c_dst: Counter) -> None:
        while q and q[0][0] < cutoff:
            ts, dip, dpt = q.popleft()
            key = (dip, dpt)
            c_pair[key] -= 1
            if c_pair[key] <= 0:
                del c_pair[key]
            c_dst[dip] -= 1
            if c_dst[dip] <= 0:
                del c_dst[dip]

    @staticmethod
    def _pop_older_10(
        q: Deque[Rec], cutoff: float, c_pair: Counter
    ) -> None:
        while q and q[0][0] < cutoff:
            _ts, dip, dpt = q.popleft()
            key = (dip, dpt)
            c_pair[key] -= 1
            if c_pair[key] <= 0:
                del c_pair[key]

    def update_and_get_features(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
    ) -> Dict[str, float]:
        """
        Prune windows, record this flow, return the five temporal features (current flow included).
        """
        st = self._ensure(src_ip)
        q10: Deque[Rec] = st["q10"]
        q60: Deque[Rec] = st["q60"]
        c10_pair: Counter = st["c10_pair"]
        c60_pair: Counter = st["c60_pair"]
        c60_dst: Counter = st["c60_dst"]

        if ts > 0.0:
            self._pop_older(q60, ts - W60, c60_pair, c60_dst)
            self._pop_older_10(q10, ts - W10, c10_pair)

        rec: Rec = (ts, dst_ip, dst_port)
        q10.append(rec)
        q60.append(rec)
        keyp = (dst_ip, dst_port)
        c10_pair[keyp] += 1
        c60_pair[keyp] += 1
        c60_dst[dst_ip] += 1

        n10 = float(len(q10))
        n60 = float(len(q60))
        to_pair_10 = float(c10_pair.get(keyp, 0))
        same_dp = float(c60_pair.get(keyp, 0)) / n60 if n60 > 0 else 0.0
        burst = n10 / n60 if n60 > 0 else 0.0
        same_di = float(c60_dst.get(dst_ip, 0)) / n60 if n60 > 0 else 0.0

        return {
            "src_flow_count_10s": n10,
            "src_to_dst_port_count_10s": to_pair_10,
            "same_dst_port_ratio": same_dp,
            "burst_ratio": burst,
            "same_dst_ip_ratio": same_di,
        }
