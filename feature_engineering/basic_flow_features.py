"""
Basic flow feature helpers for the unified behavioral schema.
Applies simple transforms (e.g. clip) to records with canonical names (duration, src_bytes, dst_bytes, etc.).
"""

from ingestion.unified_behavioral_schema import UNIFIED_BEHAVIORAL_FEATURE_NAMES


def clip_extremes(row, max_duration=1e6, max_bytes=1e9):
    """Clip extreme values to avoid overflow. Uses core schema names (duration, src_bytes, dst_bytes)."""
    out = dict(row)
    if out.get("duration", 0) > max_duration:
        out["duration"] = max_duration
    if out.get("src_bytes", 0) > max_bytes:
        out["src_bytes"] = max_bytes
    if out.get("dst_bytes", 0) > max_bytes:
        out["dst_bytes"] = max_bytes
    return out
