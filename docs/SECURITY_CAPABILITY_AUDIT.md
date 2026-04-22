# Security Capability Audit: ML Intrusion Detection Pipeline

**Document:** Real-world detection and blocking capabilities under host-based vs network firewall deployment.  
**Scope:** Model2 hybrid ML pipeline (Isolation Forest + Random Forest + RiskEngine + ContextEngine).  
**Status:** Pipeline operates on **flow-level logs** (Suricata eve.json or CIC CSV); **no inline packet capture or enforcement** in the current codebase.

---

## 1. Pipeline Analysis

### 1.1 Traffic source

| Source | Role | How it reaches the pipeline |
|--------|------|-----------------------------|
| **Suricata eve.json** | Primary runtime input. JSONL: one JSON object per line (flow or http events). | **External.** Suricata runs separately (PCAP replay or live); writes eve.json to disk. Pipeline reads the **file** via `iter_eve_chunks()` — no socket, no NFQUEUE, no live stream. |
| **CIC-style CSV** | Alternative batch input (e.g. CICIDS2017, CICIoT). | File path passed to `runtime_scoring.py --input`. Read in chunks via `pandas.read_csv(chunksize=...)`. |
| **PCAP / raw packets** | Not consumed by this pipeline. | Suricata (or similar) must turn PCAP into eve.json **outside** this project. |
| **NetFlow** | Not supported. | Would require a separate collector/aggregator producing flow records in a format the pipeline accepts (eve-like or CIC-like). |

**Conclusion:** The pipeline is **log-level / file-based**. It does not capture packets, tap the wire, or sit in the forwarding path. It reads **already-generated** flow (and optionally HTTP) logs.

---

### 1.2 Feature extraction

- **Module:** `ingestion/unified_schema.py`
- **Input:** One record per **flow** (eve event with `event_type == "flow"` or one row of CIC CSV).
- **Output:** Fixed 24-dimensional vector (no IP in ML features; IP used only for context/logging).

**Features (FEATURE_NAMES):**

- **Flow:** `src_port`, `dst_port`, `protocol`, `flow_duration`, `packets`, `bytes`, `packet_rate`, `byte_rate`
- **HTTP (when present):** `http_method`, `uri_length`, `query_length`, `path_depth`, `status_code`, `http_content_length`, `response_ratio`, `user_agent_length`, `header_count`, `cookie_length`, `uri_entropy`, `error_ratio`, `unique_uri_ratio`, `request_rate_window`
- **Temporal:** `hour_of_day`, `day_of_week`

**Process:**

- **Suricata:** `normalize_suricata_features(events)` — from each eve dict reads `flow`, `http`, `timestamp`, `src_port`, `dest_port`, `proto`; missing fields → 0 or safe default.
- **CIC:** `normalize_cic_features(df)` — maps CIC column names to the same schema.
- **Inference:** `enforce_schema(df, schema)` aligns columns to saved `feature_names` and fills missing with 0.

---

### 1.3 Preprocessing

- **Scaling:** `StandardScaler` fit at training time; at inference only `scaler.transform(X)` is used (no fit).
- **Schema:** Same 24 features for IF and RF; order fixed; no IP in the feature vector.
- **Missing/Invalid:** Handled in normalization (safe defaults, no IP encoding in ML path).

---

### 1.4 Model architecture

| Component | Role | Training | Inference |
|-----------|------|----------|-----------|
| **Isolation Forest** | Unsupervised anomaly; “how unusual is this flow?” | Trained on **benign** flows only (stream_suricata_training / IF pipeline). | `decision_function(X)` → mapped to [0,1] via `anomaly_score_to_01` (1 = most anomalous). |
| **Random Forest** | Supervised binary (benign vs attack). | Trained on labeled flows (eve + ground-truth CSV or CIC). | `predict_proba(X)[:, 1]` → attack probability in [0,1]. |
| **RiskEngine** | Combines scores into one risk. | Weights from config (e.g. w1=0.4, w2=0.4, w3=0.2). | `risk = w1*anomaly + w2*attack_prob + w3*severity` (severity from Suricata alert if present, else 0). |
| **ContextEngine** | Post-ML: per-key and destination-level aggregation. | N/A (rule-based thresholds). | Escalation (repeated MEDIUM → HIGH), DDoS-style thresholds (flows + unique srcs per dst), port fan-out (recon) per dst; can override decision to HIGH/BLOCK. |

---

### 1.5 Inference logic

1. **Load** IF, RF, scaler, config once.
2. **Read** input (eve.json or CSV) in chunks (e.g. 50k / 100k rows); no full load.
3. **Per chunk:** normalize → enforce_schema → `scaler.transform(X)` → IF `decision_function` → RF `predict_proba` → RiskEngine.compute → RiskEngine.decision(low=0.3, high=0.6) → LOW/MEDIUM/HIGH → ALLOW/ALERT/BLOCK.
4. **Optional:** ContextEngine.update_and_escalate (per (src_ip, dst_ip, dst_port), DDoS aggregation per dst_ip, port fan-out per dst_ip) can upgrade decisions to HIGH/BLOCK.
5. **Output:** Append to `decisions_log.jsonl` (per-flow); optional `context_engine_log.jsonl`; at end write `runtime_summary.json`.

Detection is **after the fact** relative to the traffic: the pipeline processes a **file** that Suricata (or another process) has already written. There is no “drop packet before it reaches the host” in the current design — only a **decision** (ALLOW/ALERT/BLOCK) written to a log.

---

### 1.6 Blocking logic

- **In code:** `decision_to_action`: HIGH → BLOCK, MEDIUM → ALERT, LOW → ALLOW. Context and RiskEngine only produce a **decision**; they do not touch the network.
- **Firewall adapter:** `inference/firewall_adapter_stub.py` implements `apply_decision(src_ip, decision, risk_score)` but **only logs to stderr**. It is **not** called from `runtime_scoring.py`. Documentation states: “Enforcement (iptables) must be wired by the integrator.”
- **No NFQUEUE, no iptables/nftables, no Suricata drop integration** in the repo. Blocking is **designed but not implemented**; an operator would need to (e.g.) read `decisions_log.jsonl` or call a real firewall API from their own glue code.

---

### 1.7 Level of operation

| Level | Supported? | Notes |
|-------|------------|--------|
| **Packet** | No | Pipeline never sees raw packets. Suricata does; it outputs flow/HTTP logs. |
| **Flow** | **Yes** | One record per flow (eve `event_type flow` or CIC row). Primary granularity. |
| **Session** | Partially | Only insofar as a “flow” is a session; no multi-flow session grouping in the ML. |
| **Log** | **Yes** | Input is log files (eve.json, CSV); output is log files (decisions_log.jsonl, summary). |

**Conclusion:** The pipeline operates at **flow level** and **log level**. It does not operate at packet level and does not perform packet or connection blocking by itself.

---

## 2. Host-Based ML IDS Scenario

**Assumption:** The system runs on a **client machine** (host-based IDS/HIPS). Suricata (or equivalent) runs on the same host and writes eve.json; the ML pipeline reads that file.

### 2.1 What traffic the system can observe

- **Only traffic visible to that host:** flows to/from the host’s IP(s), and flows traversing the host if it is routing (e.g. gateway). For a typical end-user or server machine, that means flows where the host is **src_ip or dst_ip**.
- **Where packets are captured:** By **Suricata** (or similar), not by this repo — e.g. on the host’s NIC(s), loopback, or a mirror/tap. The ML pipeline only sees the **resulting eve.json** (or CSV).
- **When detection occurs:** After Suricata has written flow (and optionally HTTP) events to disk and the pipeline has read and scored them. So detection is **delayed** by file I/O and chunk processing (batch, not per-packet).

### 2.2 Attack categories it could detect and block (in principle)

Given flow + HTTP features and optional context:

- **Port scanning (single host):** Partially. Per-flow features (many short flows, few packets/bytes, many dst_ports) can look anomalous (IF) or match trained patterns (RF). ContextEngine’s **port fan-out** (unique ports per dst in a window) can flag recon toward the host. “Block” requires wiring the stub to a firewall; currently only logging.
- **Brute force (SSH/HTTP etc.):** Yes, if training data includes such flows. Flow duration, packet/byte counts, error_ratio, repeated similar flows; RF can learn and IF can flag outliers. Context escalation (repeated MEDIUM → HIGH) can reinforce.
- **Exploit attempts (e.g. overflow, shellcode):** Only to the extent they show up in **flow/HTTP stats** (e.g. unusual URI length, method, path_depth, packet_rate). No payload inspection in this pipeline; Suricata rules can add severity that feeds into risk.
- **Application/HTTP attacks (SQLi, XSS, path traversal):** Partially. Features like `uri_length`, `query_length`, `path_depth`, `uri_entropy`, `error_ratio` can correlate with such attacks. No deep payload or signature; behavioral only.
- **Malware C2:** Partially. Unusual flow patterns (duration, periodicity, byte_rate) and anomaly score can help; RF if C2 was in the training set. No TLS decryption or payload inspection here.
- **Abnormal traffic patterns:** Yes. IF is trained on benign traffic; deviations (e.g. new protocols, unusual ports, odd rates) can score high anomaly and contribute to risk.

### 2.3 Attack classes it cannot protect against (and why)

- **Network flooding (e.g. volumetric DDoS):** The host sees only **its share** of the flood (flows to/from itself). It cannot see the full picture (e.g. millions of flows to other victims). ContextEngine’s DDoS logic (flows + unique srcs **per dst_ip**) can only protect the **host as victim** when the flood is targeting this host and visible in its flow log. It cannot mitigate floods aimed at **other** hosts.
- **Distributed attacks (many sources, one or many victims):** Same visibility limit. One host sees only flows to/from itself; cross-host aggregation (e.g. “many sources hitting many internal IPs”) is not available on a single host.
- **Attacks targeting other hosts:** The host’s Suricata does not see traffic to other machines (unless it is a central tap/IDS). So the pipeline **cannot** detect or block attacks against other hosts.
- **Infrastructure attacks (e.g. BGP, DNS cache poisoning, ARP spoofing):** No visibility. The pipeline uses flow/HTTP logs; it does not ingest BGP, DNS, or L2 frames. ARP/DHCP are below or outside the flow abstraction used here.
- **Network-layer manipulation (ARP/DHCP spoofing, etc.):** Same. Not in the feature set or data source; would require a different sensor and integration.

**Why these are outside host visibility:** On a single host you only see **that host’s** flows. You do not see traffic between other pairs of hosts, nor L2/L3 control plane or infrastructure data. So distributed, cross-host, and infrastructure attacks are outside the observable set for a host-based deployment.

---

## 3. Network Firewall ML IDS Scenario

**Assumption:** The same ML model runs on a **dedicated firewall VM** (or appliance) **inline** between attacker(s) and victim(s), and that device sees **all** traffic passing through it (e.g. gateway or tap aggregating multiple segments).

### 3.1 How visibility changes

- **Traffic observed:** All flows traversing the firewall (e.g. Internet ↔ DMZ, WAN ↔ LAN). So: many source IPs, many destination IPs, and full cross-host traffic for the segment(s) the firewall sees.
- **Data source:** Suricata (or equivalent) on the **firewall** would produce eve.json for all those flows; the same pipeline would consume that file. So the **granularity** (flow-level, same features) stays the same, but the **set of flows** is network-wide for that path.

### 3.2 Additional attack types that become detectable or blockable

- **Distributed scanning:** Many IPs probing many ports/hosts. ContextEngine’s **DDoS** (flows + unique srcs per dst) and **port fan-out** (unique ports per dst) now see the full picture (e.g. one victim getting probes from many sources, or one host with many distinct ports in a window). Single-host deployment would only see the victim’s own flows.
- **Network reconnaissance campaigns:** Same. Cross-host scanning and probing patterns (e.g. one scanner hitting many internal IPs) are visible at the firewall.
- **SYN flood (and other floods):** The firewall sees all SYN (and other) packets to a victim that go through it. Flow records (e.g. many short flows, high packet rate) can be scored; context “flows per dst + unique srcs” can fire. Mitigation still requires **actual dropping** (e.g. iptables/nftables or Suricata NFQUEUE) wired to the BLOCK decision.
- **Lateral movement:** Flows from one internal host to another (e.g. post-compromise) are visible at the firewall. If such behavior is in the training set or is anomalous, RF/IF can flag it; context can escalate.
- **Botnet scanning patterns:** Many sources, many destinations, similar flow patterns. Again, only visible when the firewall sees that aggregate; the same models and context logic can then detect and (if enforcement is wired) block.

**Why network positioning improves detection:** The device sees **all** flows on the path. So it can aggregate per-destination (and optionally per-source) across the whole segment, instead of one host’s view. That enables the existing ContextEngine logic (DDoS thresholds, port fan-out) and ML (anomaly + classification) to work on a **network-wide** view rather than a single-host view.

---

## 4. Capability Comparison

| Dimension | Host-based ML IDS | Network firewall ML IDS |
|-----------|-------------------|--------------------------|
| **Visibility scope** | Single host (flows to/from that host only). | All flows traversing the firewall (segment or path). |
| **Attack coverage** | Host-centric: brute force, exploit-like flows, app/HTTP abuse, C2-like patterns, single-host recon. | Same plus: distributed scanning, recon campaigns, SYN/volumetric floods (to observed victims), lateral movement, botnet-style scanning. |
| **Scalability** | One host’s load; Suricata + ML file read. | Firewall must handle full segment load; same pipeline, heavier I/O and CPU. |
| **Stop attacks before reaching victim** | No. Detection is post-capture, file-based; no inline drop. Even with blocking wired, the “victim” is this host. | Only if blocking is **implemented** (e.g. NFQUEUE/iptables) and applied **inline**. Current code only outputs decisions to logs. |
| **Susceptibility to bypass** | High: no inline enforcement; attacker can send traffic that is logged and scored after the fact. Evasion of flow/HTTP features (e.g. slow/low-rate, mimicking benign) can reduce scores. | Same model/feature limitations; but with inline enforcement, BLOCK would actually drop. Bypass then requires evading both Suricata’s logging and the ML/context logic. |

**Note:** “Blocking” in both columns assumes an integrator adds real firewall enforcement; the pipeline itself only produces ALLOW/ALERT/BLOCK in logs.

---

## 5. Improvements if Deployed as Firewall IDS

### 5.1 Benefits of firewall deployment

- **Earlier detection in the path:** If the pipeline is fed from Suricata **inline** (e.g. NFQUEUE or stream of flow events) and enforcement is applied on the same device, malicious flows can be dropped before reaching the victim host.
- **Visibility across multiple hosts:** Enables DDoS/recon/fan-out logic to work as intended (per-dst and cross-src aggregation).
- **Better detection of scanning campaigns:** Many-to-many scanning and port sweeps are visible; existing context (port fan-out, flows-per-dst) can trigger.
- **Ability to stop DoS earlier:** With inline blocking, HIGH/BLOCK can result in dropped packets or connections, reducing load on the victim.

### 5.2 Technical improvements recommended

1. **Real blocking integration**
   - **NFQUEUE / iptables / nftables:** Call a real firewall API from the pipeline (or a daemon that reads `decisions_log.jsonl` or a socket) to DROP or REJECT when decision is BLOCK (and optionally ALERT → rate-limit).
   - **Suricata:** Use Suricata’s own blocking (e.g. drop via NFQUEUE) driven by an external script or Suricata rule that consults the ML decision (e.g. by src_ip/dst_ip/flow_id). Requires integration layer (e.g. Suricata Lua or external app reading ML output).

2. **Flow aggregation and time-window correlation**
   - **Pre-ML aggregation:** Aggregate flows by (src_ip, dst_ip) or (src_ip, dst_net) over sliding windows (e.g. 1–5 min) and compute window-level features (flow count, byte sum, distinct ports, failed connections). Feed either per-flow + window features or window-level records to the model to improve scan/DDoS detection.
   - **Time-window correlation:** Use the existing ContextEngine more explicitly (e.g. expose “recon in progress” or “DDoS in progress” as first-class signals) and optionally feed aggregated features back into the ML input in a later version.

3. **Connection-tracking features**
   - Add features that reflect connection state (e.g. SYN-only flows, RST rate, incomplete handshakes) if Suricata or the flow exporter provides them. Improves SYN-flood and scan detection.

4. **Rate-based anomaly detection**
   - Add simple rate limits (e.g. flows/sec or packets/sec per src_ip or per dst_ip) and trigger ALERT/BLOCK when exceeded. Complements ML; can be implemented in ContextEngine or a separate module.

5. **Suricata integration**
   - **Live stream:** Consume Suricata’s eve stream (e.g. Unix socket or tail -f) instead of only reading a static file, to reduce latency.
   - **Severity:** Already supported (w3×severity in risk). Ensure Suricata is configured to emit alert/severity so that rule hits improve risk for known-bad flows.
   - **Drop integration:** Have Suricata (or a companion process) apply drops for BLOCK decisions (e.g. by maintaining a blocklist of src_ip or flow identifiers updated from the pipeline).

6. **NFQUEUE packet inspection**
   - For “see packet → score flow → drop before forwarding” the flow would be: packets go to Suricata → Suricata builds flow and optionally hands packets to NFQUEUE → external process (this pipeline or a wrapper) scores the flow and returns DROP/ACCEPT. That requires either Suricata’s native NFQUEUE use or a custom packet path that builds flow records and calls the ML pipeline with minimal latency (e.g. per-flow cache, then score on flow end or first N packets).

---

## 6. Output Summary

### 6.1 Full attack coverage analysis

- **Detectable in principle (with current features + context):** Single-host and cross-host brute force, many exploit-like and HTTP abuse patterns (behavioral), C2-like flow patterns, port scanning (single host or visible at firewall), abnormal traffic, and (at firewall) distributed scanning, recon campaigns, SYN/volumetric floods to observed victims, lateral movement, botnet-style scanning. **Blocking** requires separate enforcement (not implemented in repo).
- **Not covered:** Attacks against hosts the sensor cannot see, pure L2/L3 infrastructure (ARP/DHCP/BGP/DNS), payload-level attacks without behavioral reflection in flow/HTTP stats, and any attack that evades the 24 flow/HTTP features and context thresholds.

### 6.2 Architecture comparison

- **Host-based:** Single-host visibility; good for that host’s direct abuse and anomaly; cannot see or protect other hosts; no inline stop.
- **Network firewall:** Segment-wide visibility; same ML + context can detect distributed and multi-victim attacks; can stop attacks before the victim only if blocking is implemented and applied inline.

### 6.3 Weaknesses in the current design

1. **No actual blocking:** Only logs ALLOW/ALERT/BLOCK; firewall stub is not called; no iptables/NFQUEUE/Suricata drop.
2. **File-based, batch inference:** Reads eve.json (or CSV) from disk; detection is delayed; not real-time or per-packet.
3. **Single-flow ML input:** No explicit multi-flow or time-window features in the 24-D vector; correlation is in ContextEngine only (post-ML).
4. **No live stream:** No built-in consumption of Suricata stream or NFQUEUE; operator must arrange file tail or custom integration.
5. **Evasion:** Adversary can try to stay within “benign” flow/HTTP statistics; no payload or protocol-deep inspection in this pipeline.

### 6.4 Recommended improvements

- **Short term:** Wire BLOCK to a real firewall (iptables/nftables or Suricata) so that HIGH risk actually drops traffic; document the integration pattern.
- **Medium term:** Add Suricata live stream or socket input; optional flow aggregation and window-level features; expose context “DDoS/recon” state for logging and tuning.
- **Longer term:** NFQUEUE or equivalent for inline drop; rate-based rules; connection-state features; optional payload-aware features (e.g. from Suricata app-layer) if available and privacy allows.

---

*This audit reflects the Model2 codebase as of the review date. Deployment-specific assumptions (e.g. where Suricata runs, which traffic is mirrored) should be validated per environment.*
