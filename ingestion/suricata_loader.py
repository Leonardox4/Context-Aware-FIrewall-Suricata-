"""
Load Suricata eve.json (file or path) and yield raw flow events.

For unified behavioral extraction use ingestion.unified_behavioral_pipeline:
  run_unified_behavioral_extraction(), or extract_unified_behavioral_row with flow-window trackers
  (dst port variance 300s, flow IAT variance 300s, dst unique src 60s, src flow count 300s,
  SrcIpTemporalTracker for 10s/60s repetition features).
"""

import json
from pathlib import Path


def load_suricata_eve(filepath, max_events=None):
    """
    Load eve.json (JSONL) and yield raw eve events (dicts).
    For unified behavioral rows use unified_behavioral_pipeline.run_unified_behavioral_extraction()
    or extract_unified_behavioral_row(..., temporal).
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(filepath)
    count = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if max_events is not None and count >= max_events:
                break
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                yield event
                count += 1
            except (json.JSONDecodeError, Exception):
                continue


def map_eve_event(event):
    """
    Deprecated: For unified behavioral extraction use
    ingestion.unified_behavioral_pipeline.extract_unified_behavioral_row(
        ev, behavioral, tls_tracker, tcp_tracker, dst_var_tracker,
        iat_var_300, dst_unique_src_60, src_flow_300, temporal
    )
    """
    raise NotImplementedError(
        "Use ingestion.unified_behavioral_pipeline.extract_unified_behavioral_row("
        "ev, behavioral, tls_tracker, tcp_tracker, dst_var_tracker, "
        "iat_var_300, dst_unique_src_60, src_flow_300, temporal) for feature rows, "
        "or run_unified_behavioral_extraction() for full pipeline."
    )
