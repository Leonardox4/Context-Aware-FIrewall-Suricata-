"""
Unified behavioral schema: flow-only network features for a high-throughput behavioral IDS.

Design goals:
- **Flow-level and lightweight protocol signals** — no payload / HTTP body analysis,
  no Suricata alert/signature features. Sliding-window context from **flow events only**
  (no separate anomaly/tls EVE streams).
- **Strong on** scans, floods, brute-force patterns, recon (volume, diversity, inter-arrival
  variance, dst fan-in, 60s/300s windows).
- **TCP:** Suricata may omit the per-flow ``tcp`` object. ``has_tcp`` is 1 when it is present
  so the model can separate “no TCP metadata” from “TCP counters are zero”. Other TCP-heavy
  features are zero when ``has_tcp`` is 0.

Feature count: `N_UNIFIED_BEHAVIORAL_FEATURES` (must match Rust `eve_extractor`).
"""

from typing import Dict, List, Optional, Tuple

# -----------------------------------------------------------------------------
# Flow-only behavioral schema (fixed column order for ML + Rust eve_extractor)
# -----------------------------------------------------------------------------

UNIFIED_BEHAVIORAL_FEATURE_NAMES: List[str] = [
    "flow_rate_src_10s",
    "flow_rate_src_60s",
    "flow_rate_dst_10s",
    "rate_ratio_src_10s_60s",
    "rate_ratio_src_60s_300s",
    "concurrent_flows_src_10s",
    "concurrent_flows_dst_10s",
    "concurrent_flows_per_dst_port_10s",
    "unique_src_ips_by_dst_60s",
    "dst_ip_unique_src_ips_10s",
    "new_dst_ip_ratio_src_300s",
    "new_dst_port_ratio_src_300s",
    "new_dst_ips_per_sec",
    "new_dst_ports_per_sec",
    "dst_ip_entropy_src_300s",
    "dst_port_entropy_src_300s",
    "iat_cv_src_60s",
    "iat_cv_srcdst_300s",
    "iat_autocorr_srcdst_300s",
    "bytes_ratio_fwd_rev",
    "short_flow_ratio_src_300s",
    "avg_bytes_per_flow_src_300s",
    "bytes_per_flow_srcdst",
    "connection_reuse_ratio_srcdst",
    "flow_size_mode_src_300s",
    "retry_rate_same_dstport_300s",
    "retry_rate_same_dstip_300s",
    "dst_port_reuse_ratio_src_300s",
    "syn_heavy_ratio_src_60s",
    "syn_to_established_ratio",
    "rst_ratio_src_60s",
    "rst_to_syn_ratio_src_60s",
    "tcp_flag_entropy_src_60s",
    "ack_presence_ratio",
    "small_response_ratio_src_60s",
    "incomplete_flow_duration_ratio_src_300s",
    "low_data_rate_long_flow_ratio_src_300s",
    "src_contribution_to_dst_ratio_60s",
    "rst_micro_flow_ratio_src_60s",
    "single_dst_port_focus_src_60s",
    "rst_after_ack_ratio_src_60s",
    "dst_src_ip_entropy_60s",
    "avg_flow_per_src_to_dst_10s",
    "iat_regularity_src_60s",
    "has_tcp",
]

# Must equal Rust `eve_extractor::extractor::N_FEATURES` and `eve_extractor.N_FEATURES` (PyO3).
N_UNIFIED_BEHAVIORAL_FEATURES: int = len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)

# Bounds for SanityCheck: feature_name -> (min, max); use None for no bound
FEATURE_BOUNDS: Dict[str, Tuple[Optional[float], Optional[float]]] = {
    "flow_rate_src_10s": (0.0, None),
    "flow_rate_src_60s": (0.0, None),
    "flow_rate_dst_10s": (0.0, None),
    "rate_ratio_src_10s_60s": (0.0, None),
    "rate_ratio_src_60s_300s": (0.0, None),
    "concurrent_flows_src_10s": (0.0, None),
    "concurrent_flows_dst_10s": (0.0, None),
    "concurrent_flows_per_dst_port_10s": (0.0, None),
    "unique_src_ips_by_dst_60s": (0.0, None),
    "dst_ip_unique_src_ips_10s": (0.0, None),
    "new_dst_ip_ratio_src_300s": (0.0, 1.0),
    "new_dst_port_ratio_src_300s": (0.0, 1.0),
    "new_dst_ips_per_sec": (0.0, None),
    "new_dst_ports_per_sec": (0.0, None),
    "dst_ip_entropy_src_300s": (0.0, None),
    "dst_port_entropy_src_300s": (0.0, None),
    "iat_cv_src_60s": (0.0, None),
    "iat_cv_srcdst_300s": (0.0, None),
    "iat_autocorr_srcdst_300s": (-1.0, 1.0),
    "bytes_ratio_fwd_rev": (0.0, None),
    "short_flow_ratio_src_300s": (0.0, 1.0),
    "avg_bytes_per_flow_src_300s": (0.0, None),
    "bytes_per_flow_srcdst": (0.0, None),
    "connection_reuse_ratio_srcdst": (0.0, 1.0),
    "flow_size_mode_src_300s": (0.0, None),
    "retry_rate_same_dstport_300s": (0.0, 1.0),
    "retry_rate_same_dstip_300s": (0.0, 1.0),
    "dst_port_reuse_ratio_src_300s": (0.0, 1.0),
    "syn_heavy_ratio_src_60s": (0.0, 1.0),
    "syn_to_established_ratio": (0.0, None),
    "rst_ratio_src_60s": (0.0, 1.0),
    "rst_to_syn_ratio_src_60s": (0.0, None),
    "tcp_flag_entropy_src_60s": (0.0, None),
    "ack_presence_ratio": (0.0, 1.0),
    "small_response_ratio_src_60s": (0.0, 1.0),
    "incomplete_flow_duration_ratio_src_300s": (0.0, 1.0),
    "low_data_rate_long_flow_ratio_src_300s": (0.0, 1.0),
    "src_contribution_to_dst_ratio_60s": (0.0, 1.0),
    "rst_micro_flow_ratio_src_60s": (0.0, 1.0),
    "single_dst_port_focus_src_60s": (0.0, 1.0),
    "rst_after_ack_ratio_src_60s": (0.0, 1.0),
    "dst_src_ip_entropy_60s": (0.0, None),
    "avg_flow_per_src_to_dst_10s": (0.0, None),
    "iat_regularity_src_60s": (0.0, None),
    "has_tcp": (0.0, 1.0),
}

# Default fill for invalid values (NaNs, missing, Inf)
DEFAULT_FILL = 0.0

# Label column name for ML (0 = benign, 1 = attack) https://tinyurl.com/CompetitiveEventRC
LABEL_KEY = "label"
