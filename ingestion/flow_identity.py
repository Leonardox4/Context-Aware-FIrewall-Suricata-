"""
Time-bucketed flow identity for joins.

Suricata rows are keyed by 5-tuple plus a coarse time bucket so the same 5-tuple
at different times does not collide in label/feature joins.

Bucket width must match Rust eve_extractor (FLOW_KEY_BUCKET_SEC).
"""

from __future__ import annotations

import os


def _flow_key_bucket_sec_from_env() -> float:
    raw = os.getenv("FLOW_KEY_BUCKET_SEC", "5.0").strip()
    try:
        v = float(raw)
        if v == v and v > 0.0:
            return v
    except ValueError:
        pass
    return 5.0


# Must match Rust `eve_extractor` (`FLOW_KEY_BUCKET_SEC` env). Set before importing this module.
FLOW_KEY_BUCKET_SEC: float = _flow_key_bucket_sec_from_env()


def flow_key_with_time_bucket(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    proto: str,
    ts_epoch: float,
) -> str:
    """
    Canonical join key: ``{src}:{sp}-{dst}:{dp}-{PROTO}_{bucket}``.

    ``bucket = int(floor(ts_epoch / FLOW_KEY_BUCKET_SEC))`` (same semantics as Rust).
    """
    proto_u = (proto or "TCP").strip().upper() or "TCP"
    sip = (src_ip or "").strip() or "UNKNOWN"
    dip = (dst_ip or "").strip() or "UNKNOWN"
    base = f"{sip}:{int(src_port)}-{dip}:{int(dst_port)}-{proto_u}"
    try:
        t = float(ts_epoch)
        if t != t or t < 0.0:
            t = 0.0
    except (TypeError, ValueError):
        t = 0.0
    b = int(t // FLOW_KEY_BUCKET_SEC)
    return f"{base}_{b}"


if __name__ == "__main__":
    # Before/after sample (documentation aid for audits)
    ts = 1_700_000_000.0
    old = "203.0.113.7:44345-198.51.100.2:443-TCP"
    new = flow_key_with_time_bucket("203.0.113.7", 44345, "198.51.100.2", 443, "TCP", ts)
    print("Sample (5-tuple-only vs time-bucketed):")
    print(f"  before: {old}")
    print(f"  after:  {new}")
