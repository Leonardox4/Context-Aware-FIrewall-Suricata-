# Feature Derivation from Suricata EVE (eve.json)

> **Flow-only behavioral IDS (current):** **34** features in fixed order (`UNIFIED_BEHAVIORAL_FEATURE_NAMES` in `ingestion/unified_behavioral_schema.py`). Only **`event_type == "flow"`** lines are ingested for training/extraction. There are **no** alert-derived features, **no** HTTP/payload entropy, **no** anomaly-event aggregates, and **no** TLS handshake history (JA3 / rolling SNI counts).

This document describes how each feature is derived from Suricata **flow** events. All features are computed during streaming parse; missing fields → **0** (or conservative defaults).

**Design notes:**
- **IAT (`iat_min` / `iat_max` / `iat_avg`):** flow-level proxy from totals (not per-packet); see Rhythms section.
- **ttl_variance:** 0 when fewer than two TTL samples; non-zero can indicate insertion / inconsistent pathing.
- **Service buckets:** port/proto classification only (no HTTP content).

---

## Flow basics (6)

| Feature | EVE source | Calculation | Notes |
|--------|------------|-------------|-------|
| **duration** | `flow.age` | Seconds as-is. | 0 if missing or ≤0. |
| **src_bytes** | `flow.bytes_toserver` | Integer. | 0 if missing. |
| **dst_bytes** | `flow.bytes_toclient` | Integer. | 0 if missing. |
| **src_pkts** | `flow.pkts_toserver` | Integer. | 0 if missing. |
| **dst_pkts** | `flow.pkts_toclient` | Integer. | 0 if missing. |
| **avg_pkt_size** | Derived | `(src_bytes + dst_bytes) / (src_pkts + dst_pkts)` | 0 when total pkts = 0. |

---

## Rhythms & temporal (5)

| Feature | EVE source | Calculation | Notes |
|--------|------------|-------------|-------|
| **pkt_rate** | Derived | `(src_pkts + dst_pkts) / duration` | 0 when duration ≤ 0. |
| **byte_rate** | Derived | `(src_bytes + dst_bytes) / duration` | 0 when duration ≤ 0. |
| **iat_min** | Approximation | Same as **iat_avg** (flow-level single IAT). | Bot / beacon proxy. |
| **iat_max** | Approximation | Same as **iat_avg**. | |
| **iat_avg** | Approximation | `duration / (pkts - 1)` when pkts > 1 and duration > 0; else 0. | Not true per-packet IAT. |

**IAT caveat:** EVE flow records lack per-packet timestamps. The pipeline uses one effective IAT per flow; the model treats it as an automation / pacing signal.

---

## TCP flags on flow record (2)

| Feature | EVE source | Calculation | Notes |
|--------|------------|-------------|-------|
| **tcp_flag_count** | `tcp.syn`, `tcp.ack`, `tcp.fin`, `tcp.rst`, `tcp.psh` | Count of flags set (0–5). | 0 for non-TCP or missing. |
| **urg_flag_count** | `tcp.urg` | 1 if set, else 0. | |

---

## Contextual 60s / 120s (9)

Sliding windows; state updated per flow; entries older than the window are pruned.

| Feature | Calculation | Notes |
|--------|-------------|-------|
| **src_ip_flow_count_60s** | Flows in last 60s with same `src_ip`. | Count **before** adding current flow. |
| **dst_ip_flow_count_60s** | Flows in last 60s with same `dest_ip`. | Before current. |
| **src_port_count_60s** | Distinct `src_port` for this `src_ip` in 60s. | |
| **dst_port_count_60s** | Distinct `dest_port` for this `src_ip` in 60s. | |
| **service_freq_http** | Flows in 60s for this `src_ip` with HTTP class (TCP + dst in 80, 443, 8080, 8000, 8443). | Port-based only. |
| **service_freq_dns** | Flows with dst_port 53. | |
| **service_freq_ssh** | Flows with dst_port 22. | |
| **service_freq_other** | Flows not in http/dns/ssh classes. | |
| **src_flow_count_120s** | Flows in last **120s** with same `src_ip`. | Separate 120s window. |

---

## Advanced behavioral (3)

| Feature | Source | Calculation | Notes |
|--------|--------|-------------|-------|
| **src_pkts_ratio** | Flow | `src_pkts / (src_pkts + dst_pkts)` | Clamped [0, 1]. |
| **dst_port_entropy** | 60s window | Shannon entropy (base 2) over destination ports for this `src_ip`. | 0 if window empty. |
| **tls_sni_count** | `tls.sni` on flow | **1** if SNI string present, else **0**. | Presence flag, not distinct-SNI history. |

---

## Evasion / network (3)

Only fields present in the event; missing → 0.

| Feature | EVE source | Calculation | Notes |
|--------|------------|-------------|-------|
| **ttl_variance** | `ip.ttl`, `inner.ttl`, `flow.ttl`, etc. | Variance of all TTL values found (≥2 samples). | 0 if <2 values. |
| **tcp_window_size_avg** | `tcp.window` | Single window value used as “avg”. | |
| **ip_fragment_count** | `ip.fragments`, `inner.fragments` | Integer sum when present. | |

**Removed:** `retransmission_rate` — not reliably available on standard flow EVE and was misleading (often 0).

---

## TLS on flow record only (2)

| Feature | Source | Notes |
|--------|--------|-------|
| **is_tls** | `event_type == "tls"` or `app_proto == "tls"` | Binary. |
| **tls_version** | `tls.version` string | Mapped to 1.0–1.3 numeric; unknown → 0. |

No JA3 frequency, handshake rate, or rolling unique SNI — those required separate TLS event streams and are out of scope for this pipeline.

---

## Recon / scan / stealth (3)

| Feature | Calculation | Notes |
|--------|-------------|-------|
| **failed_connection_ratio** | Per-flow **failed** flag × 60s window | `_is_failed_connection(ev)` marks each flow 0/1 (SYN-only, no reply, strong asymmetry, non-established + failure-like `reason`, etc.). Ratio = (# prior flows with failed=1 in last 60s for this src_ip) / (prior flow count); computed **before** the current flow is appended. |
| **unique_dst_ips_60s** | Distinct `dest_ip` for this `src_ip` in 60s | Before current flow. |
| **tcp_flag_entropy** | Rolling 60s per `src_ip` | Shannon entropy over SYN/ACK/FIN/RST/PSH/URG **counts** in window (not raw flag strings). |

---

## Optional DNS mix (1)

| Feature | Calculation | Notes |
|--------|-------------|-------|
| **dns_flow_ratio_per_src** | `service_freq_dns / n60_src` for prior flows | Share of DNS-classified flows in the **prior** 60s window for `src_ip` (same pass as context; before current flow is added); clamped [0, 1]. |

---

## Removed from legacy schema (intentional)

| Removed | Reason |
|--------|--------|
| **ja3_freq_60s**, **tls_handshake_rate**, **tls_unique_sni_60s** | TLS handshake history / JA3 tracking — not flow-only; dropped for speed and scope. |
| **anomaly_event_count_60s** | Depended on non-flow `anomaly` events. |
| **retransmission_rate** | Unreliable or zero on flow EVE. |
| **payload_entropy** | Payload / HTTP body — explicit non-goal for this IDS. |
| **Alert / rule IDs** | Signature-style; excluded by design. |

---

## Summary of approximations

- **IAT:** One value per flow from duration and packet count.
- **Service / DNS ratio:** Port-based service classes only.
- **Sliding windows:** Correct if EVE is roughly time-ordered; small drift if not.
- **tcp_flag_entropy:** Uses **previous** window state before the current flow’s flags are appended (see pipeline).
