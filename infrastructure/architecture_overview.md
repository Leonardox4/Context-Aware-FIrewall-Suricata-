# Model2 — Hybrid ML Firewall: Complete Architecture Blueprint

This document is the **full architectural blueprint** of the ML-based context-aware firewall: from traffic ingestion through ML detection, risk scoring, context memory, and logging. It incorporates behavior-only ML design, NAT-safe context tracking, distributed DDoS mitigation in the context layer, and the logging subsystem.

---

## 1. Full Pipeline Blueprint

End-to-end processing from raw traffic to final decision and telemetry:

```
PCAP / Network Traffic
         ↓
Suricata Flow Generation
         ↓
Feature Extraction (24-feature unified schema)
         ↓
Isolation Forest (anomaly score)
         ↓
Random Forest (attack classification)
         ↓
Risk Scoring Engine
         ↓
Context Memory Engine
         ↓
Final Decision (ALLOW / ALERT / BLOCK)
         ↓
Logging + Dashboard Telemetry
```

### Stage responsibilities

| Stage | Role |
|-------|------|
| **PCAP / Network Traffic** | Raw input: live capture or offline PCAP. Not processed directly by Model2; Suricata (external) consumes it. |
| **Suricata Flow Generation** | Suricata (or equivalent) turns packets into flow records (eve.json JSONL). Each event has flow metadata (bytes, packets, duration, ports, protocol) and optional alert data. Model2 does not run Suricata; it reads its output. |
| **Feature Extraction** | Raw events are normalized to the **unified schema**: 24 web-focused behavioral features (no IP). Same pipeline for training and inference. Source: `ingestion/unified_schema.py`. |
| **Isolation Forest** | Unsupervised anomaly model. Input: 24-feature vector. Output: anomaly score (mapped to 0–1). Trained on benign flows only; flags deviations from normal. |
| **Random Forest** | Supervised binary classifier (benign vs attack). Input: same 24-feature vector. Output: attack probability (0–1). Trained on labeled data (eve + ground-truth CSV or CIC). |
| **Risk Scoring Engine** | Combines anomaly score, attack probability, and optional alert severity into one risk score: `risk = w1*anomaly + w2*attack_prob + w3*severity`. Weights configurable (e.g. 0.4, 0.4, 0.2). |
| **Context Memory Engine** | Short-term behavioral state keyed by (src_ip, dst_ip, dst_port). Runs **after** ML. Uses flow metadata and ML scores to track repeated or distributed patterns; can escalate decisions (e.g. MEDIUM → HIGH/BLOCK). Does not use IP as an ML feature. |
| **Final Decision** | Risk score and context escalation are mapped to ALLOW / ALERT / BLOCK (e.g. via thresholds LOW / MEDIUM / HIGH). |
| **Logging + Dashboard Telemetry** | Model decision logs (per-flow) and context engine smart logs (escalations, pattern events) are written under the logging directory for dashboards and forensics. |

---

## 2. Behavior-Based ML Design (Identity-Agnostic)

### 2.1 ML models must never use IP addresses as features

- The ML feature vector is **fixed** to the **24 canonical features** in the unified schema.
- **src_ip** and **dst_ip** are **never** part of the model input. They are **not** encoded (e.g. hashed or embedded) into the feature vector.
- Models are **identity-agnostic**: they see only behavioral and contextual signals (ports, protocol, duration, packets, bytes, rates, alert context, time-of-day). This avoids identity-based bias and keeps the system portable across networks.

### 2.2 Unified 24-feature web-attack schema

Defined in `ingestion/unified_schema.py` as `FEATURE_NAMES`:

- **Flow-level (behavior only):** `src_port`, `dst_port`, `protocol`, `flow_duration`, `packets`, `bytes`, `packet_rate`, `byte_rate`
- **HTTP request structure:** `http_method`, `uri_length`, `query_length`, `path_depth`
- **HTTP response behaviour:** `status_code`, `http_content_length`, `response_ratio`
- **Header behaviour:** `user_agent_length`, `header_count`, `cookie_length`
- **Payload complexity:** `uri_entropy`
- **Behavioural web attack signals:** `error_ratio`, `unique_uri_ratio`, `request_rate_window`
- **Temporal:** `hour_of_day`, `day_of_week`

All 24 features are behavioral or protocol-level; no IP-derived field is included.

### 2.3 Where IP is used (not in the model)

| Use | Purpose |
|-----|--------|
| **Dataset joins (training)** | 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) and timestamp match Suricata flows to ground-truth CSV rows. Labels are attached to flows; the feature matrix passed to the model contains only the 24 features. |
| **Context memory tracking** | Context keys (see §3–4) use (src_ip, dst_ip, dst_port) to maintain per-flow-context state and destination-level aggregates. This happens **after** the model; the model never sees these keys. |
| **Logging and dashboard** | src_ip, dst_ip, dst_port (and other metadata) are written to decision logs and context logs for visualization, alerting, and forensics. They are not fed back into the model. |

**Summary:** The models remain purely behavior-based. IP exists only for joins, context keying, and telemetry.

---

## 3. Context Memory Engine

### 3.1 Purpose

The context engine provides **short-term behavioral memory across flows** so the system can detect patterns that a single flow cannot reveal. It runs **after** the ML decision stage and does **not** use IP (or any identity) as an ML feature; it uses identity only to **key** state for correlation and escalation.

Examples of patterns it can support:

- **Repeated brute force attempts** from the same source to the same service (e.g. many MEDIUM-risk flows to dst_port 22).
- **Port scanning**: many distinct destination ports from one source in a short window.
- **Multi-stage exploitation**: sequences of flows that individually look weak but together indicate a campaign.
- **Distributed attack patterns**: many sources targeting one destination (DDoS-style), detected via destination-level aggregation (§5).

### 3.2 Operation

- **Input (after ML):** For each flow, the engine receives flow metadata (e.g. src_ip, dst_ip, dst_port), ML risk score, classification result, and decision/action.
- **Role:** Update context state (per key and, for DDoS logic, per destination), then optionally **escalate** the decision (e.g. MEDIUM → HIGH, ALERT → BLOCK) when thresholds are exceeded.
- **Output:** Updated decisions and actions for logging and enforcement; optionally, context-specific log entries when escalation or pattern detection occurs.

The ML models are not retrained on context; context only adjusts the final decision for the current flow based on history.

### 3.3 Context storage structure

**Context key (NAT-safe):**

```
(src_ip, dst_ip, dst_port)
```

Using this triple ensures that different source–destination–port combinations do not share state (see §4).

**Per-key entry (conceptual):**

```json
{
  "suspicious_count":  <number of events in window with risk >= low_thresh>,
  "last_seen_timestamp": <epoch or ISO timestamp>,
  "escalation_level":    <e.g. 0=none, 1=alert, 2=block>
}
```

- **Creation:** When a flow is processed, the key `(src_ip, dst_ip, dst_port)` is computed. If the key is missing, a new entry is created with initial counters and timestamp.
- **Update:** On each flow, the entry’s sliding time window is updated: add (timestamp, risk), drop events older than the window, update `suspicious_count` (e.g. count of events in window with risk ≥ low_thresh), and set `last_seen_timestamp`.
- **Evaluation:** If `suspicious_count` (or other configured metrics) exceeds a threshold (e.g. `escalate_min_events`), the current decision for that flow may be escalated (e.g. to HIGH/BLOCK). Entries beyond TTL or over a max-entries cap are evicted (e.g. LRU).

---

## 4. NAT-Safe Context Tracking

### 4.1 The NAT ambiguity problem

If context is keyed only by **src_ip**, then all hosts behind the same NAT share one logical “source.” Their behavioral history is mixed: one user’s brute force could trigger escalation for every other user behind that NAT (contamination). Conversely, a malicious user could dilute their own history by sharing an IP with many benign users.

### 4.2 Mitigation: key by (src_ip, dst_ip, dst_port)

Context keys **must** use:

```
(src_ip, dst_ip, dst_port)
```

- **Same NAT, different services:** Different (dst_ip, dst_port) pairs yield different keys. One user’s SSH brute force does not affect another user’s HTTP traffic.
- **Same NAT, same service:** If two internal hosts hit the same external (dst_ip, dst_port), they still share one key; this is acceptable when the observable “source” (NAT IP) and target are the same from the engine’s perspective.
- **Different NATs:** Different src_ip ⇒ different keys; no cross-NAT contamination.

So behavioral history is scoped to “this apparent source (possibly NAT) → this destination:port,” which avoids the worst NAT contamination while still allowing per-flow-context memory.

### 4.3 Example

- Host A (behind NAT 10.0.0.1) brute-forces ssh to server S (port 22) → key `(10.0.0.1, S, 22)` gets high `suspicious_count` → escalation for that key only.
- Host B (same NAT 10.0.0.1) browses to server S (port 443) → key `(10.0.0.1, S, 443)` is separate; no escalation from A’s SSH behavior.

---

## 5. Distributed DDoS Mitigation in the Context Layer

Destination-level aggregation is implemented **inside the context engine**, without adding identity-based features to the ML model. The model still sees only the 13 behavioral features per flow; “many sources → one destination” is detected by the context layer.

### 5.1 Aggregation metrics (sliding time windows)

- **flows_per_dst_ip:** Count of flows (in the current sliding window) whose destination IP is the given dst_ip.
- **unique_src_ips_per_dst_ip:** Number of distinct src_ip values that have sent flows to the given dst_ip in the window.

Both are computed over a **sliding time window** (e.g. 60–300 seconds). Old events are dropped when they fall outside the window so that state stays bounded and recent.

### 5.2 Escalation logic

When **both** of the following exceed configured thresholds:

- `flows_per_dst_ip` > flow_threshold (e.g. high volume to one destination),
- `unique_src_ips_per_dst_ip` > unique_src_threshold (e.g. many distinct sources),

the context engine can treat the destination as under a **distributed** attack and escalate decisions (e.g. mark flows to that destination as HIGH/BLOCK or log a DDoS pattern).

This supports detection of:

- **Distributed HTTP floods** (many IPs, one web server).
- **Amplification attacks** (many sources, one target).
- **Botnet traffic** (many bots, one C2 or victim).

All without putting dst_ip or src_ip into the ML feature vector; the ML model remains behavior-only, and the context layer adds the “many-to-one” logic.

---

## 6. Context Memory Lifecycle

- Context memory is **ephemeral runtime state** held in RAM (e.g. dictionaries/maps keyed by (src_ip, dst_ip, dst_port) and optionally by dst_ip for DDoS aggregates).
- **Restart behavior:** Context memory is **cleared when the system restarts**. There is no persistence of context state to disk. This avoids stale state and unbounded growth in the prototype and keeps the design simple.
- **Role:** Context is used only for **short-term behavioral correlation** (e.g. sliding windows of a few minutes to an hour). Long-term visibility is provided by **persistent logs** (§7), not by context storage.
- **Startup:** Context memory is **initialized empty** when the engine is created; `clear()` is called so that no stale state is carried across restarts.

---

## 7. Logging Architecture

### 7.1 Log directory

All system logs are stored under a dedicated directory:

```
/logs/
```

(Runtime can be configured to use a project-relative path such as `Model2/logs/` or an absolute path; the important point is one designated place for all logs.)

### 7.2 Two major log types

#### A. Model Decision Logs (dashboard logs)

Produced by the **ML decision layer** (after risk scoring; context may have updated decisions). Used for the monitoring dashboard and for attack/risk visualization.

**Suggested fields (per record):**

| Field | Description |
|-------|-------------|
| `timestamp` | Event time (ISO or epoch). |
| `src_ip` | Source IP (for display only; not an ML feature). |
| `dst_ip` | Destination IP (for display only). |
| `dst_port` | Destination port. |
| `classification` | Attack classification or “benign” (from RF or label). |
| `risk_score` | Combined risk score (0–1). |
| `decision` | LOW / MEDIUM / HIGH (or ALLOW / ALERT / BLOCK). |
| `model_source` | e.g. “IF+RF” or “RF” to indicate which model(s) contributed. |

The dashboard can prioritize **attack classifications** and visualize attack types, risk scores, blocked events, and attack frequency. These logs are the main input for operational visibility.

#### B. Context Engine Smart Logs

Produced by the **context engine** when it escalates a decision or detects a pattern. They record **behavioral correlation events**, not every flow.

**Example fields:**

| Field | Description |
|-------|-------------|
| `timestamp` | When the escalation or pattern was detected. |
| `context_key` | e.g. (src_ip, dst_ip, dst_port) or dst_ip for DDoS. |
| `event_type` | e.g. “escalation”, “repeated_brute_force”, “port_scan”, “distributed_attack”. |
| `escalation_reason` | Short reason (e.g. “suspicious_count >= threshold”). |
| `suspicious_count` | Value that triggered the rule. |

These logs support later investigation of behavioral patterns (brute force, scanning, DDoS) without logging every flow.

---

## 8. Separation: Runtime State vs Historical Records

| Concept | Nature | Purpose |
|--------|--------|---------|
| **Runtime context memory** | In-memory (RAM), temporary, cleared on restart | Decision-making: escalation and pattern detection over short windows. Bounded by TTL and max_entries. |
| **Persistent security logs** | On-disk (e.g. under `/logs/`), durable | Long-term forensic visibility, dashboards, alerting, compliance. |

Context memory is **not** a substitute for logs; it only holds recent state to improve real-time decisions. Logs provide the lasting record of what the model and context layer did.

---

## 9. Final Architecture Summary

The system combines four concerns without contaminating the ML model with identity:

1. **Behavior-based ML detection**  
   A single 13-feature vector (no IP) is used for IF (anomaly) and RF (classification). Risk is computed from anomaly score, attack probability, and optional alert severity. Decisions are identity-agnostic at the model level.

2. **Contextual behavioral correlation**  
   The context engine keys state by (src_ip, dst_ip, dst_port) and optionally by dst_ip for DDoS. It uses flow metadata and ML scores **after** the model to escalate decisions when repeated or distributed patterns are observed. Identity is used only for keying and aggregation, not as model input.

3. **Distributed attack detection**  
   Destination-level metrics (flows_per_dst_ip, unique_src_ips_per_dst_ip) in sliding windows allow the context layer to detect many-to-one attacks and escalate without adding IP to the ML feature space.

4. **Persistent telemetry logging**  
   Model decision logs support dashboards (attack types, risk, blocks). Context engine smart logs support investigation of behavioral patterns and escalations. Both are stored under the logging directory and provide long-term visibility.

**Invariant:** The ML feature vector remains strictly behavioral (13 features). IP is used only for joins, context keying, and logging.

---

## 10. Conceptual Sanity Check

After applying the above design:

| Check | Result |
|-------|--------|
| **ML models operate only on behavioral features** | Yes. The unified schema exposes exactly 13 features; src_ip and dst_ip are never in the feature vector and are not encoded into it. |
| **Context memory is NAT-safe** | Yes. Keys (src_ip, dst_ip, dst_port) prevent users behind the same NAT from contaminating each other’s history for different destinations/ports. |
| **Distributed attacks detectable** | Yes. Destination-level aggregation (flows_per_dst_ip, unique_src_ips_per_dst_ip) in the context layer detects many-to-one patterns without feeding identity into the model. |
| **Logging covers model and context** | Yes. Model decision logs capture per-flow risk and decisions for dashboards; context engine smart logs capture escalations and pattern events for forensics. |
| **Context reset vs forensic visibility** | Yes. Context memory resets on restart; logs persist. No long-term state in context; full visibility remains in logs. |

The pipeline remains coherent: behavior-only ML → risk → context (identity used only for keying and aggregation) → final decision → dual logging (decisions + context events).

---

## 11. Random Forest Training: eve.json + Ground Truth (Implementation Reference)

This section describes **precisely** how Random Forest training works when using Suricata `eve.json` together with a ground-truth CSV. All references are to the current codebase.

### 11.1 Training pipeline (steps from eve.json to RF)

**Entry point:** `training/Randomforest_training_pipeline.py` → `main()`.

| Step | What happens | Module / function |
|------|----------------|-------------------|
| 1. Load ground truth | CSV is read and normalized: required columns validated, types set, `ts_bucket` computed from `timestamp`. If CSV has `flow_key`, a label map (and optional subclass map) is built for O(1) lookup. | `_prepare_labels_csv(path, time_tolerance)` in same file |
| 2. Stream eve.json | Flow events are read in chunks; **no full-file load**. Only events with `event_type == "flow"` are kept. | `utils.streaming.iter_eve_chunks(eve_path, chunk_size, event_type_filter="flow", ...)` |
| 3. Extract join keys / match | **Flow_key path (if CSV has `flow_key`):** For each event build `flow_key = src_ip:src_port-dst_ip:dst_port-proto`, lookup in label_map; collect matched indices and labels. **5-tuple path:** Build keys DataFrame `(src_ip, dst_ip, src_port, dst_port, protocol_str, ts_bucket)` from eve; same from labels; inner-merge. | `_join_flows_with_labels()`: flow_key or keys_df + merge |
| 4. Normalize features | Each chunk of raw eve dicts is converted to the canonical feature schema (FEATURE_NAMES). **IP addresses are not included** in the feature matrix. | `ingestion.unified_schema.normalize_suricata_features(chunk_events)` |
| 5. Write matched rows to Parquet | For matched rows only: build a small DataFrame (FEATURE_NAMES + binary_label [+ attack_subclass]), convert to PyArrow Table, **append to Parquet** via `ParquetWriter`. No in-memory accumulation of full X/y; memory-safe for millions of flows. | `_join_flows_with_labels()`: `pq.ParquetWriter(output_parquet_path, schema)`; `writer.write_table(table)` per chunk |
| 6. Load Parquet and train | After streaming finishes, **load** the Parquet from disk. Train/test split, scale with existing or new scaler, fit RF, evaluate, save artifacts. If the Parquet already existed (e.g. from a prior run) and `--rebuild-features` is not set, **skip** steps 2–5 and load it directly (feature dataset cache). | `main()`: `pd.read_parquet(feats_path)`; `train_test_split`; `scaler.transform`; `rf.fit()` |
| 7. (Optional) Eval-only | With `--eval-only`: load artifacts and the feature dataset (from existing Parquet or build from another eve + labels → write to `eval_dataset.parquet`). Scale, predict, print metrics. No training, no artifact write. Use to **test the trained model on another labeled eve.json**. | `main()`: early branch when `args.eval_only` |

**Note:** The pipeline does **not** use `ingestion/suricata_loader.py` for loading. It uses **`utils.streaming.iter_eve_chunks`** directly. Normalization is **`ingestion.unified_schema.normalize_suricata_features`**. All join and Parquet write logic is inside **`_join_flows_with_labels`**; the script uses **pyarrow.parquet.ParquetWriter** for incremental writes so that multi-million-flow eve.json files can be processed with bounded RAM.

### 11.2 Ground truth join mechanism

- **Matching fields:** The join uses exactly six fields:
  - `src_ip` (string, trimmed)
  - `dst_ip` (string, trimmed)
  - `src_port` (int)
  - `dst_port` (int)
  - `protocol_str` (canonical string: from eve `proto`, from CSV `protocol` via `_canonical_proto_str` — e.g. "TCP", "UDP", "6", "17")
  - `ts_bucket` (int): `floor(timestamp_epoch / time_tolerance_seconds)`

- **Eve side:** From each event: `ev.get("src_ip")`, `ev.get("dest_ip")`, `ev.get("src_port")`, `ev.get("dest_port")`, `ev.get("proto")`, `ev.get("timestamp")`. Timestamp is parsed with `pd.to_datetime(..., utc=True)` then converted to seconds; `ts_bucket = floor(ts_epoch / time_tolerance)`.

- **Labels side:** CSV must have columns `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `timestamp`. The script adds `protocol_str` and `ts_bucket` in `_prepare_labels_csv`.

- **Join type:** **Inner** merge on the six columns above. A flow in eve.json gets a label only if there exists a row in the ground truth with the same 5-tuple **and** the same time bucket.

- **Time window:** Matching is **not** exact timestamp equality. It is **5-tuple + time bucket**: two flows match if they agree on (src_ip, dst_ip, src_port, dst_port, protocol_str) and their timestamps fall in the same bucket. Bucket size is `--time-tolerance-sec` (default 1.0 second). So it is **5-tuple + time-window (bucket)** matching.

### 11.3 Required ground truth schema

The labels CSV **must** contain the following columns (exact names):

| Column | Type | Purpose |
|--------|------|---------|
| `binary_label` | int (0 or 1) | Target for RF: 0 = benign, 1 = attack. |
| `src_ip` | string | Join key (and logging); not a feature. |
| `dst_ip` | string | Join key (and logging); not a feature. |
| `src_port` | int | Join key. |
| `dst_port` | int | Join key. |
| `protocol` | string or int | Join key; normalized to `protocol_str` (e.g. TCP, UDP, 6, 17). |
| `timestamp` | datetime-parsable | Used to compute `ts_bucket` for join. Any format accepted by `pd.to_datetime(..., utc=True)` (e.g. ISO, epoch). |

**Optional:**

| Column | Type | Purpose |
|--------|------|---------|
| `attack_subclass` | string | Preserved for analytics and stored in `config["attack_subclass_counts"]`; **not** used as the model target (RF stays binary). |

**Example minimal CSV structure:**

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,binary_label
2024-01-15T10:00:00Z,192.168.1.1,10.0.0.1,54321,80,TCP,0
2024-01-15T10:00:01Z,192.168.1.2,10.0.0.1,54322,443,TCP,1
```

With optional subclass:

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,binary_label,attack_subclass
2024-01-15T10:00:00Z,192.168.1.1,10.0.0.1,54321,80,TCP,0,benign
2024-01-15T10:00:01Z,192.168.1.2,10.0.0.1,54322,443,TCP,1,brute_force
```

The script does **not** require a column named `label` or `attack_type`; the target is **`binary_label`**. If your dataset has `label` (e.g. "Benign"/"Attack") or `attack_type`, you must add a pre-processing step to derive `binary_label` (0/1) and ensure the join columns exist with the names above.

### 11.4 Label handling

- **RF expects:** A **binary** target: `y` is integer 0 (benign) or 1 (attack). No multi-class target in this pipeline.

- **Source of `y`:** After the inner join, `y_chunk = merged["binary_label"].astype(int).values`. The final `y` is the concatenation of all chunks. So **the label comes only from the ground truth CSV** (`binary_label`); Suricata alerts are **not** used for labeling.

- **Multi-class / attack_type:** The pipeline does **not** use `attack_type` or any multi-class column as the model target. If the CSV includes `attack_subclass`, it is stored in config for analytics and logging only; the model is always trained with `y = binary_label` (0/1).

### 11.5 Feature extraction and Parquet write (streaming)

- After matching (flow_key lookup or 5-tuple + ts_bucket merge), only **matched** rows are kept per chunk. For those rows, a DataFrame is built with columns **FEATURE_NAMES** (from normalized Suricata features), **binary_label**, and optionally **attack_subclass**. This DataFrame is converted to a PyArrow Table and **appended** to the output Parquet via `ParquetWriter`. No `X_list`/`y_list` or `np.vstack`/`np.concatenate`; peak memory is bounded by chunk size.
- **FEATURE_NAMES** (in `ingestion/unified_schema.py`) define the canonical behavioral feature set (flow, HTTP, temporal, etc.). **IP addresses are not in FEATURE_NAMES** and are never passed to the model. They are used only for the join and (elsewhere) for logging/context.
- **Feature dataset cache:** The output Parquet (default `output_dir/training_dataset.parquet` or `--features-parquet`) is written during the first run. On subsequent runs, if that file exists and `--rebuild-features` is not set, the pipeline loads it with `pd.read_parquet` and skips eve.json streaming.

### 11.6 Training output (artifacts)

Saved via `utils.serialization.save_artifacts(if_model, rf_model, scaler, config, path_dir)`:

| Artifact | File | Content |
|----------|------|---------|
| Random Forest | `random_forest.joblib` | Trained sklearn RandomForestClassifier (binary). |
| Scaler | `scaler.joblib` | Fitted StandardScaler (same feature order as FEATURE_NAMES). |
| Config | `config.joblib` | Dict with at least `feature_names` (list matching FEATURE_NAMES), optionally `weights`, `attack_subclass_counts`. |
| Isolation Forest | `isolation_forest.joblib` | Reused from `--artifacts-in` if provided; otherwise may be None (RF-only run). |

- **Feature ordering:** The scaler and RF both expect the same column order as **`config["feature_names"]`**, which is set to **`FEATURE_NAMES`** from unified_schema (fixed order). No label encoding is stored; labels are 0/1 only.

### 11.6a Eval-only: testing the trained model on another labeled eve.json

To **evaluate the trained model on a different labeled dataset** (e.g. a held-out test set or another capture) without retraining:

- Run with **`--eval-only`** and **`--artifacts-in`** pointing to the saved model directory.
- **Dataset:** Either pass **`--features-parquet`** to an existing Parquet (e.g. a pre-built eval set), or pass **`--eve`** and **`--labels-csv`** for the other eve.json; the pipeline will stream and build the feature dataset and write it to **`--eval-output-parquet`** (default: `output_dir/eval_dataset.parquet`) so the training parquet is not overwritten.
- The script loads the model, loads or builds the feature dataset, runs `scaler.transform` and `rf.predict` / `predict_proba`, and prints metrics (confusion matrix, accuracy, classification report, ROC-AUC, FPR). No training, no artifact write.

### 11.7 Custom dataset compatibility: exact required CSV schema

For a custom ground truth table to work with this pipeline:

1. **Required columns (exact names):**  
   `binary_label`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `timestamp`.

2. **Types:**  
   `binary_label` integer 0 or 1; `src_ip`/`dst_ip` strings (trimmed); `src_port`/`dst_port` integers; `protocol` string or number (will be canonicalized to string for join); `timestamp` any pandas-parsable datetime (preferably UTC).

3. **Semantics:**  
   Each row should represent one flow. The 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) plus the timestamp (mapped to a time bucket) must be able to match the same 5-tuple and time bucket from Suricata eve.json. So the custom table must be built from the **same** traffic (or aligned capture) that produced the eve.json, with the same notion of flow and time (or within the chosen `time_tolerance` bucket).

4. **Optional:**  
   `attack_subclass` (string) for analytics only.

5. **No alert-derived labels:**  
   The pipeline does not use Suricata `alert` for labels; labels come only from this CSV.

**Exact required CSV schema (minimal):**

```
timestamp, src_ip, dst_ip, src_port, dst_port, protocol, binary_label
```

Optional: `attack_subclass`.

### 11.8 Safety of optional and extra columns (e.g. `attack_subclass`)

Adding an **`attack_subclass`** column (or other optional metadata) to the ground truth CSV is **safe** and does not affect training or inference:

| Check | Result |
|-------|--------|
| **Label extraction** | Only **`binary_label`** is used as the model target. Optional columns are not used as labels. |
| **Join keys** | The merge uses only **`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol_str`, `ts_bucket`**. `attack_subclass` is not a join key; it is only carried through when present and stored in config as summary counts. |
| **Feature matrix** | **X** is built strictly from **`feats_matched[FEATURE_NAMES]`**, where `feats_matched` comes from **`normalize_suricata_features(chunk_events)`** (eve.json only). No column from the ground truth CSV is ever used as a feature. |
| **Isolation Forest** | IF is trained in a separate pipeline (e.g. on benign MAWI data) and never reads the ground truth CSV. Adding or removing columns in the RF ground truth table has **no effect** on the IF model or scaler. |
| **Scaler / artifact compatibility** | The scaler and RF expect exactly **FEATURE_NAMES** (canonical count from unified_schema). Optional CSV columns do not change feature count or order. |
| **Config / serialization** | When `attack_subclass` is present, only a **summary** (`attack_subclass_counts`) is written to **`config.joblib`** for analytics. It is not used by the model or by inference for scoring. |

**Summary:** `attack_subclass` (and any other extra columns not used as join keys) can be added to the ground truth CSV as **dataset metadata / analytics** only. The RF continues to train on **`binary_label`** only; IF and scaler remain unchanged.

---

## Appendix: Training vs Inference (concise)

**Training:** CIC and/or Suricata data are normalized to the same 24 features. IF is trained on benign flows; RF on labeled data (eve + ground-truth CSV). For RF with eve.json, labels are joined by **5-tuple + time bucket** (see §11); the feature matrix contains only the 24 behavioral/web features (no IP). Artifacts: IF, RF, scaler, config (joblib).

**Inference:** Suricata eve.json (or CIC-style CSV) → normalize to 24 features → scaler.transform → IF + RF → risk formula → thresholds → context engine (update state, optional escalation) → final decision → write model decision log (+ context smart log when applicable).

---

## Implementation Status

This section summarizes what is currently implemented in the codebase. The architecture document serves as both the **target blueprint** and an **implementation progress tracker**.

| Component | Status | Notes |
|-----------|--------|--------|
| **Context key** | Implemented | NAT-safe key `(src_ip, dst_ip, dst_port)` in `inference/context_engine.py`. |
| **Context entry** | Implemented | Each entry stores `suspicious_count`, `last_seen_timestamp`, `escalation_level`; sliding window and TTL reset. |
| **Context memory lifecycle** | Implemented | Ephemeral (RAM only). `clear()` on create; state lost on process restart. |
| **DDoS aggregation** | Implemented | `flows_per_dst_ip`, `unique_src_ips_per_dst_ip` in sliding window (configurable, e.g. 10 s). Thresholds: `--ddos-flow-threshold`, `--ddos-unique-src-threshold`. Escalation when both exceeded. |
| **Logging directory** | Implemented | Default output directory is `logs/`; `--output-dir` can override. |
| **Model decision logs** | Implemented | `logs/decisions_log.jsonl` (or `output_dir/decisions_log.jsonl`). Fields: `timestamp`, `src_ip`, `dst_ip`, `dst_port`, `classification`, `risk_score`, `decision`, `action`, `model_source`. |
| **Context engine smart logs** | Implemented | `logs/context_engine_log.jsonl`. Fields: `timestamp`, `context_key`, `event_type`, `escalation_reason`, `suspicious_count` (and `unique_src_ips` for DDoS events). |
| **Behavior-based ML** | Implemented | 13-feature unified schema; `src_ip`/`dst_ip` only for joins, context keying, and logging (see §2 and sanity check docs). |

**Pipeline order in code:** Traffic → Suricata (external) → Feature extraction (unified schema) → IF + RF → Risk engine → Context memory engine → Final decision → `write_decisions` + `write_context_events`.

**CLI (runtime):** `--output-dir` defaults to `logs`; `--no-context` disables context engine; `--ddos-window-sec`, `--ddos-flow-threshold`, `--ddos-unique-src-threshold` control DDoS detection.
