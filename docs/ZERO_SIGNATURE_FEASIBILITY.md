# Zero-Signature Behavioral IDS: Runtime Feature Extraction Feasibility

> **Current product scope:** **34** flow-only features (see `unified_behavioral_schema.py`). No payload/HTTP-body features, no Suricata alerts as features, no `anomaly` event aggregates, no JA3 / TLS-handshake history. Extraction ingests **`flow`** EVE lines for the main pipeline.

## 1. Can all required feature extraction be computed reliably at runtime while parsing eve.json streams?

**Yes**, with the following caveats.

### What can be computed reliably at runtime

| Category | Features | Source in EVE | Runtime reliable? |
|----------|----------|----------------|--------------------|
| **Flow Basics** | duration, src_bytes, dst_bytes, src_pkts, dst_pkts, avg_pkt_size | `flow.age`, `flow.bytes_toserver/toclient`, `flow.pkts_toserver/toclient` | **Yes** – single-event, no lookback. |
| **Rhythms (rates)** | pkt_rate, byte_rate | Same flow | **Yes**. |
| **Rhythms (IAT)** | iat_min, iat_max, iat_avg | **Not per-packet in flow events** | **Approximation only** – see below. |
| **TCP (flow record)** | tcp_flag_count, urg_flag_count | `tcp.*` on flow | **Yes**. |
| **Context 60s** | src_ip_flow_count_60s, dst_ip_flow_count_60s, src_port_count_60s, dst_port_count_60s, service_freq_*, dns_flow_ratio_per_src | Window state (+ DNS share from service counts) | **Yes** – sliding window; purge >60s. |
| **Long-Term** | src_flow_count_120s | Window state | **Yes** – 120s window. |
| **Advanced** | src_pkts_ratio, dst_port_entropy, tls_sni_count | Flow + 60s multiset; `tls.sni` presence | **Yes**. |
| **Evasion** | ttl_variance, tcp_window_size_avg, ip_fragment_count | `tcp.window`, TTL samples, fragment counts | **Partial** – missing → 0. |
| **TLS (flow-level)** | is_tls, tls_version | `app_proto` / `event_type`, `tls.version` | **Yes** when present. |
| **Recon / TCP behavior** | failed_connection_ratio, unique_dst_ips_60s, tcp_flag_entropy | Flow heuristics + 60s distinct dst + rolling flag entropy | **Yes** with ordering caveats. |

### Caveats

1. **IAT (iat_min, iat_max, iat_avg)**  
   Flow events do **not** provide per-packet timestamps. We only have flow-level `start`, `end`, `age` and packet count. So:
   - **True** per-packet IAT min/max/avg **cannot** be computed from flow-only EVE.
   - **Approximation**: one effective IAT per flow = `duration / (packets - 1)` when packets > 1; then set `iat_min = iat_max = iat_avg = that value`. For single-packet flows, use 0 or a small constant. This is **reliable at runtime** in the sense “best we can do from flow events”; it is **not** true per-packet IAT.

2. **Evasion (ttl_variance, ip_fragment_count)**  
   `ttl_variance` needs ≥2 TTL samples in the event; otherwise 0. Fragment counts and TCP window: use only if present. **`retransmission_rate` was removed** from the schema (unreliable on flow EVE).

3. **Ordering**  
   Sliding 60s/120s windows are correct if events are processed in **time order** (e.g. by flow start/end). If EVE is out of order, a flow might be included/excluded from a window by a few seconds—acceptable for behavioral IDS.

**Conclusion:** All requested features **can** be computed in a single pass over an eve.json stream at runtime. IAT is an approximation; Evasion Shield uses only existing EVE fields and defaults otherwise. No batch precomputation is **required** for correctness.

---

## 2. Trade-offs (memory, buffering, accuracy)

| Aspect | Trade-off |
|--------|-----------|
| **Memory** | State = sliding windows keyed by src_ip, dst_ip (and optionally service). Size = O(active IPs × flows per IP in window). With **cleanup** (drop entries older than 60s/120s) and optional **cap** (e.g. max 100k keys per dimension), memory stays bounded. For 800MB+ JSON and high flow rate, hundreds of MB of state is plausible; caps prevent unbounded growth. |
| **Buffering** | No need to buffer the whole file. We only keep: current event + window state (last 60s/120s of flow metadata: ts, ports, bytes, service). No full-history storage. |
| **Accuracy** | (1) **60s/120s**: Accurate if event order is time-ordered; slight drift if not. (2) **IAT**: Approximated from flow duration and packet count, not true per-packet. (3) **Missing EVE fields**: Evasion/L4 metrics default to 0—conservative, no false signal. |

---

## 3. What must be precomputed or batch-processed?

**Nothing is strictly required to be precomputed** for the described feature set on flow-level eve.json.

Optional batch/precomputation could be used if:
- You later switch to **packet-level** EVE or pcap to get **true** per-packet IAT; that would be a different pipeline (packet stream → IAT stats).
- You need **reproducible** 60s/120s aggregates when event order is non-deterministic; then you could sort by timestamp in a batch step—but for a single sequential stream, runtime windows are sufficient.

For **flow-only** eve.json and the requested features, **runtime computation with sliding windows and the IAT/Evasion approximations above is the right approach.**
