# ContextEngine Signals Audit and Implementation Plan

**Scope:** `inference/context_engine.py` and related runtime integration.  
**Purpose:** Evaluate existing correlation signals and plan new ones for scans, bursts, brute force, and DoS.

---

## STEP 1 — Existing vs Missing Signals

### Summary table

| # | Signal | Exists? | Implementation | Variables / counters | Thresholds |
|---|--------|---------|----------------|---------------------|------------|
| 1 | **Flows per source (within time window)** | **No** | — | — | — |
| 2 | **Unique destination ports per source** | **No** | Current logic is **per destination**: unique ports *to* a dst_ip, not *from* a src_ip. | — | — |
| 3 | **Unique destination IPs per source** | **No** | — | — | — |
| 4 | **Failed connection ratio** | **No** | — | — | — |
| 5 | **Flows per destination (DoS)** | **Yes** | `_DstAggregate` per `dst_ip`: sliding window of `(ts, src_ip)`. | `events`, `window_seconds`; `flows_per_dst_ip()` = len(events), `unique_src_ips_per_dst_ip()` = len(set(src_ip)). | `ddos_flow_threshold=100`, `ddos_unique_src_threshold=50`, `ddos_window_seconds=10.0`. Escalate dst to HIGH/BLOCK when both exceeded. |
| 6 | **SYN-only / incomplete connection** | **No** | — | — | — |
| 7 | **Slow scan (long window)** | **Partial** | `_DstPortFanout` is **per dst_ip**: unique ports *to* that host in 120s. Detects “many ports to one victim,” not “one source scanning many ports over 10 min.” | `events` (ts, src_ip, dst_port), `window_seconds=120`; `unique_dst_ports_per_dst_ip()`, `fanout_velocity()`. | `fanout_unique_ports_threshold=20`, `fanout_window_seconds=120`, `fanout_velocity_threshold=0` (disabled). No long-window **per-source** slow scan. |
| 8 | **Repeated medium-alert escalation** | **Yes** | `_ContextEntry` per key `(src_ip, dst_ip, dst_port)`: sliding window of `(ts, risk)`; count events with risk ≥ low_thresh. | `window`, `window_seconds`, `suspicious_count`, `escalation_level`. | `escalate_min_events=3`, `window_seconds=600` (10 min). If `suspicious_count >= escalate_min_events` → set decision to HIGH, action BLOCK. |

### Existing implementation details

**5. Flows per destination (DoS)**  
- **Class:** `_DstAggregate`.  
- **Store:** `self._ddos_store: Dict[str, _DstAggregate]` keyed by `dst_ip`.  
- **Data:** List of `(timestamp, src_ip)`; windowed by `cutoff = now - ddos_window_seconds`.  
- **Escalation:** When `flows_per_dst_ip() >= ddos_flow_threshold` and `unique_src_ips_per_dst_ip() >= ddos_unique_src_threshold`, add `dst_ip` to `_ddos_escalated_dsts`. Any flow with that `dst_ip` gets decision HIGH and action BLOCK (in the second pass over the batch).

**7. Port fan-out (current — per destination)**  
- **Class:** `_DstPortFanout`.  
- **Store:** `self._fanout_store: Dict[str, _DstPortFanout]` keyed by `dst_ip`.  
- **Data:** List of `(ts, src_ip, dst_port)`; window 120s.  
- **Logic:** “Many distinct destination ports *to* this dst_ip” (distributed port sweep toward one host). Not “one src_ip scanning many ports.”

**8. Repeated medium-alert escalation**  
- **Class:** `_ContextEntry` per `(src_ip, dst_ip, dst_port)`.  
- **Store:** `self._store: OrderedDict[key, _ContextEntry]`; LRU eviction when `len(_store) >= max_entries`; TTL expiry per key.  
- **Data:** `window: List[(ts, risk)]` in last `window_seconds` (600s).  
- **Count:** `suspicious_count = number of (ts, risk) in window with risk >= low_thresh`.  
- **Escalation:** If `suspicious_count >= escalate_min_events` (3), set that flow’s decision to HIGH and action to BLOCK; log `event_type: "escalation"`.

---

## STEP 2 — Whether Implementation Is Required

### 1. Flows per source (within time window)

- **Status:** Missing.  
- **Recommendation:** **Implement.**  
- **Reason:** Needed to detect connection bursts from a single source (scanners, brute-force tools). Use a short window (e.g. 10–30 s) and a threshold (e.g. 100 flows). Bounded by a per-src_ip sliding window and optional cap on number of source IPs (e.g. LRU or max_entries).

### 2. Unique destination ports per source

- **Status:** Missing (current “unique ports” is per *destination*).  
- **Recommendation:** **Implement.**  
- **Reason:** Classic port scan: one source hitting many ports. Use per-src_ip sliding window of `(ts, dst_port)`; if `unique_dst_ports(src_ip, window) > threshold` (e.g. 20 in 30 s) → escalate that source (e.g. flows from that src → HIGH/BLOCK).

### 3. Unique destination IPs per source

- **Status:** Missing.  
- **Recommendation:** **Implement.**  
- **Reason:** Subnet scanning / lateral movement: one source contacting many distinct hosts. Per-src_ip window of `(ts, dst_ip)`; e.g. `unique_dst_ips > 10` in 60 s → escalate.

### 4. Failed connection ratio

- **Status:** Missing.  
- **Recommendation:** **Defer** (or implement only if data exists).  
- **Reason:** Requires a notion of “failed” (e.g. RST, timeout, or 4xx/5xx in HTTP). Eve.json flow events do not necessarily expose connection state or HTTP status in a way the current pipeline passes into the context engine. Recommend: (a) add optional failed-connection ratio only if runtime can supply a per-flow “failed” flag or status from Suricata/HTTP; or (b) document as future work and skip for now so we don’t add unused code paths.

### 5. Flows per destination (DoS)

- **Status:** Exists.  
- **Recommendation:** **Keep; optional tuning.**  
- **Reason:** Already implements “flows_to_dst_ip + unique_src_ips” in a 10 s window with configurable thresholds. Defaults (100 flows, 50 unique srcs) are reasonable; no structural change needed.

### 6. SYN-only / incomplete connection

- **Status:** Missing.  
- **Recommendation:** **Defer** (or implement only if data exists).  
- **Reason:** Requires TCP flags or connection state (e.g. SYN-only, no ACK). Flow-level eve.json may not expose this per flow in the current ingestion. Prefer documenting as future work unless the pipeline is extended to pass TCP/flags into context.

### 7. Slow scan (long window)

- **Status:** Partially present (per-dst port fan-out in 120 s). True “slow scan” = one *source*, many ports over a *long* window (e.g. 10 min).  
- **Recommendation:** **Implement per-source long-window port count.**  
- **Reason:** Covers nmap -T0/-T1 style scans. New signal: per-src_ip, window e.g. 600 s, `unique_dst_ports(src_ip) > 30` → escalate. Complements existing per-dst fan-out.

### 8. Repeated medium-alert escalation

- **Status:** Exists.  
- **Recommendation:** **Keep as is.**  
- **Reason:** Already escalates when the same (src_ip, dst_ip, dst_port) has enough high-risk events in the window. No change needed.

---

## STEP 3 — Implementation Plan (After Approval)

Planned new signals and behavior:

### 1. Flows-per-source rate (burst / scanner / brute force)

- **Concept:** `flows_from_src_ip > threshold` in a short window → treat that source as suspicious and escalate its flows (e.g. MEDIUM→HIGH, HIGH→BLOCK).
- **Structure:** New store `_src_flow_count: Dict[str, _SrcFlowWindow]` (or similar). `_SrcFlowWindow` holds a sliding list of timestamps (or `(ts, placeholder)`) in the last `src_burst_window_seconds` (e.g. 10–30 s).  
- **Count:** `flows_in_window = len(window)` after purging `ts < now - window`.  
- **Threshold:** e.g. `src_burst_flow_threshold = 100`.  
- **Escalation:** If a source exceeds threshold, add it to `_src_burst_escalated` (set). In the decision pass, any flow with `src_ip in _src_burst_escalated` gets decision HIGH and action BLOCK (or at least MEDIUM→HIGH).  
- **Memory:** Same pattern as `_DstAggregate`: per-key window, purge by cutoff. Cap number of source IPs (e.g. same `max_entries` or a separate cap) with LRU to avoid unbounded growth.  
- **Config:** `src_burst_window_seconds`, `src_burst_flow_threshold`.

### 2. Unique destination ports per source (port scan)

- **Concept:** `unique_dst_ports(src_ip, window) > threshold` → HIGH.  
- **Structure:** `_SrcPortScan: Dict[str, _SrcPortWindow]`. `_SrcPortWindow`: list of `(ts, dst_port)` in last `src_portscan_window_seconds` (e.g. 30 s); purge by cutoff; `unique_ports()` = len(set(dst_port)).  
- **Threshold:** e.g. 20.  
- **Escalation:** Add src_ip to `_src_portscan_escalated`; flows from that src get HIGH/BLOCK.  
- **Config:** `src_portscan_window_seconds`, `src_portscan_unique_ports_threshold`.

### 3. Unique destination IPs per source (host sweep / lateral)

- **Concept:** `unique_dst_ips(src_ip, window) > threshold` → escalate.  
- **Structure:** `_SrcDstFanout: Dict[str, _SrcDstWindow]`. `_SrcDstWindow`: list of `(ts, dst_ip)` in last `src_dstfanout_window_seconds` (e.g. 60 s); `unique_dsts()` = len(set(dst_ip)).  
- **Threshold:** e.g. 10.  
- **Escalation:** Add src_ip to `_src_dstfanout_escalated`; flows from that src get HIGH/BLOCK.  
- **Config:** `src_dstfanout_window_seconds`, `src_dstfanout_unique_dsts_threshold`.

### 4. Flows per destination (DoS)

- **Action:** No code change. Already implemented; optional CLI/docs tuning (e.g. 500/50 in 10 s as in your example) can be done via existing `--ddos-flow-threshold` and `--ddos-unique-src-threshold`.

### 5. Slow scan (long window, per source)

- **Concept:** `unique_dst_ports(src_ip, 10 min) > 30` → escalate.  
- **Structure:** Reuse same “per-src unique ports” idea but with a **longer** window. Options:  
  - **Option A:** Separate store `_SrcSlowScan` with window 600 s and threshold 30.  
  - **Option B:** Single per-src port window with configurable length; add a second threshold “slow_scan_unique_ports” and “slow_scan_window_seconds” (e.g. 600).  
- **Recommendation:** Option B with two parameter sets (short-window “fast scan”, long-window “slow scan”) or a separate `_SrcSlowScan` (Option A) for clarity.  
- **Escalation:** Add src to `_src_slowscan_escalated`; flows from that src get HIGH/BLOCK.  
- **Config:** `src_slowscan_window_seconds=600`, `src_slowscan_unique_ports_threshold=30`.

### Integration with existing pipeline

- **API:** All new logic lives inside `update_and_escalate()`. No change to `RiskEngine`, ML feature schema, or training.  
- **Order of operations:**  
  1. Update existing stores (per-key escalation, DDoS per dst, fan-out per dst).  
  2. Update **new** stores (flows per src, unique ports per src, unique dsts per src, slow scan per src).  
  3. For each flow, if its `src_ip` is in any “escalated source” set (`_src_burst_escalated`, `_src_portscan_escalated`, `_src_dstfanout_escalated`, `_src_slowscan_escalated`), set decision to HIGH and action to BLOCK (same pattern as DDoS/fan-out for dst).  
- **Logging:** Append to `context_events` with distinct `event_type` (e.g. `source_flow_burst`, `source_port_scan`, `source_dst_fanout`, `source_slow_scan`) and relevant counts/windows for debugging.  
- **CLI:** Add arguments (e.g. `--src-burst-window-sec`, `--src-burst-threshold`, `--src-portscan-window-sec`, `--src-portscan-ports-threshold`, `--src-dstfanout-window-sec`, `--src-dstfanout-hosts-threshold`, `--src-slowscan-window-sec`, `--src-slowscan-ports-threshold`) and pass into `create_context_engine` so operators can tune or disable (e.g. threshold 0 = off).

### Deferred (not in first implementation)

- **Failed connection ratio:** Implement only when the pipeline provides a per-flow “failed” or “connection_state” field.  
- **SYN-only / incomplete connection:** Implement only when TCP flags or connection state are available in the data path.

---

## STEP 4 — Implementation Guidelines (To Apply When Coding)

- Use **time-windowed** structures only: purge events with `ts < now - window_seconds` each update.  
- Use **efficient structures:** e.g. list of `(ts, value)` with in-place purge; or `collections.deque` with bounded size if we cap events per key. Avoid unbounded lists.  
- **Per-src caps:** Either reuse a global `max_entries` (total context keys) or introduce a separate cap for “source-side” stores (e.g. `max_src_entries`) with LRU eviction so a single run cannot grow memory without bound.  
- **Counters:** Derive “flows in window” and “unique ports/unique dsts” from the window contents after purge; no permanent counters that never expire.

---

## STEP 5 — Integration Checklist

- [ ] New signals only affect **decision/action** (HIGH/BLOCK) and **context_events**; they do **not** change risk score computed by RiskEngine or ML features.  
- [ ] `runtime_scoring.py` continues to call `context_engine.update_and_escalate(...)` with the same signature; new logic is internal to ContextEngine.  
- [ ] Decision logging (e.g. `decisions_log.jsonl`) and summary unchanged in format; new context events get new `event_type` values.  
- [ ] New parameters are optional (e.g. threshold 0 = disabled) so existing deployments behave as before.  
- [ ] `create_context_engine()` and `ContextEngine.__init__` accept new kwargs; `runtime_scoring` passes them from new CLI args.

---

## STEP 6 — Output Summary

1. **Analysis:** See Step 1 table and “Existing implementation details” above.  
2. **Missing signals:** (1) Flows per source, (2) Unique destination ports per source, (3) Unique destination IPs per source, (4) Failed connection ratio, (6) SYN-only/incomplete, (7) Slow scan per source (long window). (5) and (8) exist.  
3. **Implementation plan:** Step 3 describes four new signals to implement (flows-per-src, unique-ports-per-src, unique-dsts-per-src, slow-scan-per-src), deferral of failed-ratio and SYN-only, and integration approach.  
4. **Updated code:** Not written until you approve. After approval, changes will be in `inference/context_engine.py` (new classes, stores, and logic inside `update_and_escalate`) and `inference/runtime_scoring.py` (CLI and `create_context_engine` arguments).  
5. **Detection impact:**  
   - **Flows per source:** Burst scanners and brute-force tools that open many connections in a short time.  
   - **Unique ports per source:** Classic port scans from a single IP.  
   - **Unique destinations per source:** Subnet/host sweep and lateral movement.  
   - **Slow scan (long window):** Stealth scans (e.g. nmap -T0/-T1) spread over minutes.  
   Together with existing per-dst DoS and per-dst port fan-out, this gives both “many sources → one victim” and “one source → many ports/hosts” coverage while keeping memory bounded and behavior configurable.

---

**Status:** Implemented. The four source-side signals (flows-per-src, unique-ports-per-src, unique-dsts-per-src, slow-scan-per-src) and CLI/config wiring are in `inference/context_engine.py` and `inference/runtime_scoring.py`.
