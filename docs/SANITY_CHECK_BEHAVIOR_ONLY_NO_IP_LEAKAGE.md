# Sanity Check: Behavior-Only ML Features and No IP Leakage

This document records a full sanity check of the ML firewall pipeline to confirm that (1) the 13-feature unified schema is strictly behavioral, (2) **src_ip** and **dst_ip** are never used as model features and are not implicitly encoded, and (3) IP addresses are used only for flow identification, joins, and dashboard/logging. It also confirms that context awareness (per-host behavior over time) is preserved without feeding IPs into the model.

---

## 1. `src_ip` and `dst_ip` are never model features

### 1.1 Canonical feature set

The single source of truth for model input is `ingestion/unified_schema.py`:

```python
FEATURE_NAMES: List[str] = [
    "src_port", "dst_port", "protocol",
    "flow_duration", "packets", "bytes", "packet_rate", "byte_rate",
    "alert_severity", "alert_category", "alert_signature_present",
    "hour_of_day", "day_of_week",
]
```

There are exactly 13 names; **src_ip** and **dst_ip** are not in `FEATURE_NAMES`.

### 1.2 Training paths

- **Random Forest** (`training/Randomforest_training_pipeline.py`):  
  - Labels CSV and eve.json are joined by 5-tuple (or `flow_key` when present) and time.  
  - Matched rows are written incrementally to Parquet (FEATURE_NAMES + binary_label only); then the feature matrix is loaded as `X = feats_df[cols].values` where `cols` are from FEATURE_NAMES.  
  - So `src_ip`/`dst_ip` are used only for the **join key**; they are not in the feature columns and never enter `X`.

- **Isolation Forest** (`training/stream_suricata_training.py`):  
  - `chunk_to_feature_matrix(events)` calls `normalize_suricata_features(events)` and then keeps only `cols = [c for c in FEATURE_NAMES if c in df.columns]`.  
  - The buffer and model are fed only this matrix; no IP columns exist in it.

### 1.3 Inference path

- **Runtime** (`inference/runtime_scoring.py`):  
  - `schema = config.get("feature_names", FEATURE_NAMES)` (the 13 names).  
  - After normalization, `feature_cols = [c for c in schema if c in df.columns]`, then `X = enforce_schema(df[feature_cols], schema).values`.  
  - So the model input `X` has only the schema columns.  
  - `src_ip` is read from raw events **only** for `write_decisions(..., src_ips, ...)` and, when present, `context_engine.update_and_escalate(src_ips, ...)`. It is never part of `df[feature_cols]` or `X`.

### 1.4 No implicit IP encoding

- **`_encode_ip`** in `unified_schema.py` converts an IP string to an integer. It is **never called** anywhere in the codebase (grep confirms). The docstring states it is "Not used in ML feature matrix; kept for potential non-ML use." So no IP-derived value is added to the feature vector.
- **Normalization outputs**:  
  - `normalize_cic_features()` builds a record with only the keys in `FEATURE_NAMES` plus `LABEL_KEY`; it reads `Source IP`/`Src IP` only to satisfy `_get_cic()` for other logic (e.g. row handling), and does **not** add any IP field to the returned DataFrame columns.  
  - `normalize_suricata_features()` builds a record from eve fields (flow, alert, timestamp); the record contains only the 13 feature names plus optional `LABEL_KEY`/`HAS_ALERT_KEY`. No IP is written into the normalized record.
- **`build_feature_vector(record)`** returns `[float(record.get(k, 0)) for k in FEATURE_NAMES]`; no other keys (and no IP) are used.

**Conclusion:** `src_ip` and `dst_ip` are **not** included as model features in RF or IF training, and they are **not** implicitly encoded in preprocessing. They are used only for joins, logging, and context state keying.

---

## 2. The 13 canonical features are strictly behavioral

Each of the 13 features is behavioral or contextual in a non-identity sense:

| Feature | Role | Identity-related? |
|--------|------|--------------------|
| `src_port`, `dst_port` | Port numbers (0–65535); many hosts can use the same port | No |
| `protocol` | Protocol (e.g. TCP=6, UDP=17, ICMP=1) | No |
| `flow_duration` | Duration of the flow (seconds) | No |
| `packets` | Total packet count in the flow | No |
| `bytes` | Total byte count in the flow | No |
| `packet_rate`, `byte_rate` | Derived from packets/bytes and duration | No |
| `alert_severity`, `alert_category`, `alert_signature_present` | Suricata alert context (or 0 when no alert) | No |
| `hour_of_day`, `day_of_week` | Time of day / day of week from timestamp | No |

None of these are functions of IP address. Ports and protocol describe *type* of traffic; duration, packets, bytes, and rates describe *volume and timing*; alert fields describe *rule match*; temporal fields describe *when*. There is no categorical or hashed encoding of IP in the schema, and no feature is derived from `src_ip` or `dst_ip`.

**Conclusion:** The 13 canonical features are strictly behavioral (and optional alert/temporal context) and do not introduce identity-based bias.

---

## 3. IP addresses used only for identification, joins, and logging

Verified uses of IP in the pipeline:

| Use | Where | Purpose |
|-----|--------|--------|
| Join key (5-tuple) | RF training: match eve flows to labels CSV | Identify which flow a label applies to |
| Join key (5-tuple) | RF training: build `keys_df` from eve (src_ip, dst_ip, ports, proto, ts_bucket) | Same |
| Logging | `write_decisions(..., src_ips, log_path)`: each log line includes `src_ip` | Dashboard / monitoring |
| Context state key | `ContextEngine.update_and_escalate(src_ips, ...)`: `ip = src_ips[i]` used as key in `_store` | Per-IP sliding window and escalation |
| CSV runtime | Extract `src_ip` from CSV column for `write_decisions` and context | Same as above |

At no point is `src_ip` or `dst_ip` passed into `enforce_schema`, `build_feature_vector`, `records_to_matrix`, or into the scaler or models. The model input vector is always built from the 13-feature schema only.

**Conclusion:** IP addresses are used only for flow identification, dataset joins, and dashboard/logging (and as the key for per-IP context state). They are never fed into the model input vector.

---

## 4. No feature engineering or preprocessing leaks IP

Checked for accidental IP leakage:

- **Unified schema:** Only `FEATURE_NAMES` (and optionally `LABEL_KEY`/`HAS_ALERT_KEY`) are produced for the model; no IP, no `_encode_ip` in the feature path.
- **CIC normalization:** Uses `_get_cic(..., "Source IP", "Src IP", ...)` only to read fields; the constructed `rec` does not include any IP key; the returned DataFrame is `out[FEATURE_NAMES + [LABEL_KEY]]`.
- **Suricata normalization:** Uses `ev.get("src_port")`, `ev.get("dest_port")`, `flow`, `alert`, `timestamp`; no IP is added to the record.
- **Enforce_schema:** Takes a list of column names (`schema`) and the DataFrame; outputs only those columns. Schema is `FEATURE_NAMES` (or from config); no IP column is ever in the schema.
- **Dataset prep** (`scripts/optimize_cicids_merged_for_rf.py`): DROP_PATTERNS and `_is_drop_column` explicitly drop columns whose normalized name matches IP-related patterns (e.g. "src ip", "dst ip", "ip_src", "ip_dst"), so IP columns are stripped from training data and not used as features.

There is no hashing of IP, no embedding of IP, and no derived categorical that encodes identity. Alert fields are from Suricata’s rule/signature, not from IP.

**Conclusion:** No feature engineering, normalization, or preprocessing step introduces IP into the ML feature space. No indirect or derived IP leakage was found.

---

## 5. Context awareness without IP as a model feature

The **ContextEngine** (`inference/context_engine.py`) provides per-IP state (sliding window of risk, event count) and can escalate a decision (e.g. MEDIUM → HIGH) when a **host** has multiple medium/high-risk events in a time window. This supports scenarios like:

- Repeated suspicious behavior from the same host (e.g. brute force over time).
- Scanning or probing patterns that manifest as many flows from one source.

Mechanism:

- **Input to the model:** Only the 13 behavioral features; the model does not see IP.
- **After scoring:** For each event, the pipeline has `(risk, decision, action, src_ip)`. The context engine uses **src_ip only as a key** into a store of per-IP state (e.g. `_store[ip]`). It updates that state (e.g. `state.add(ts, risk, low_thresh)`) and, based on **count of high/medium events in the window for that key**, may escalate the decision. The escalated decision is still based on the same risk score and the same 13-feature input; the only change is a post-hoc rule: “if this host has had N such events recently, treat this decision as HIGH/BLOCK.”

So:

- **Behavioral anomaly / classification** is done purely on the 13 features (no IP).
- **Context awareness** is implemented by grouping events by IP **outside** the model and applying escalation rules on top of model outputs. Identity is used only to *key* state for correlation and escalation, not as a predictive feature.

**Conclusion:** The design preserves context awareness (e.g. recognizing repeated or scanning behavior from the same host) without feeding IP addresses into the model. The model remains behavior-based; IP is used only for correlation and dashboard logging.

---

## 6. Separation between behavioral detection and contextual awareness

- **Behavioral anomaly detection (IF) and classification (RF):**  
  - Input: 13-feature vector (ports, protocol, duration, packets, bytes, rates, alert context, temporal).  
  - No IP in the feature vector.  
  - Output: anomaly score and attack probability per flow; combined into risk and then LOW/MEDIUM/HIGH.

- **Contextual awareness (ContextEngine):**  
  - Input: after-the-fact (risk, decision, action, src_ip) per event.  
  - Uses **src_ip only as a key** to maintain per-IP state and to apply escalation rules.  
  - Output: possibly updated decision/action (e.g. escalate to HIGH/BLOCK) for logging and enforcement.  
  - The model is not retrained on IP; the same 13-feature model is used for every flow.

So:

- **Behavioral layer:** model sees only behavior (13 features); decisions are purely behavior-based.
- **Context layer:** uses identity (IP) only to correlate events and adjust decisions (e.g. escalation) for monitoring and enforcement, not as model input.

**Conclusion:** The architecture maintains a clear separation: behavioral anomaly detection and classification are identity-agnostic at the model level; contextual awareness is an optional post-processing layer that uses IP only for state and escalation, not for prediction.

---

## 7. Summary and direct answers

### Do model decisions remain purely behavior-based?

**Yes.** The model (IF + RF) receives only the 13 canonical features. Every path that builds the feature matrix (training and inference) uses exactly `FEATURE_NAMES` (or the same list from config). No IP or IP-derived value is included. Decisions (LOW/MEDIUM/HIGH and ALLOW/ALERT/BLOCK) are driven by risk computed from anomaly score, attack probability, and alert severity only.

### Is IP context preserved only for correlation, labeling, and dashboard logging (not prediction)?

**Yes.** IP is used for: (1) joining flows to labels in RF training (5-tuple), (2) keying per-IP state in the context engine, (3) writing `src_ip` to the decisions log for dashboards. It is never passed into the scaler or into IF/RF. So IP is used only for correlation, labeling, and dashboard/logging, not for prediction.

### Are any changes required to prevent identity leakage into the ML feature space?

**No.** No identity leakage was found. The schema is fixed to 13 behavior-only features; normalization and inference use only those columns; `_encode_ip` is unused; dataset prep drops IP-like columns. No code changes are required for this goal. Optional hardening: remove or clearly mark `_encode_ip` as “not for ML” to avoid future misuse.

### Does the system still support attack scenarios that require remembering host behavior over time without using IP as a model feature?

**Yes.** The context engine maintains per-IP state (sliding window of risk/events) and can escalate decisions when a host exceeds a threshold of medium/high-risk events. So “repeated behavior from the same host” (e.g. brute force, scanning) is handled by **post-model** correlation keyed by IP, not by feeding IP into the model. The model stays behavior-only; host-level memory is entirely in the context layer.

---

## 8. References (code locations)

| Topic | File / symbol |
|-------|----------------|
| Canonical 13 features | `ingestion/unified_schema.py`: `FEATURE_NAMES` |
| No IP in feature vector | `ingestion/unified_schema.py`: `build_feature_vector`, `records_to_matrix` |
| Unused IP encoding | `ingestion/unified_schema.py`: `_encode_ip` (defined, never called) |
| CIC normalization output | `ingestion/unified_schema.py`: `normalize_cic_features` (return `out[FEATURE_NAMES + [LABEL_KEY]]`) |
| Suricata normalization output | `ingestion/unified_schema.py`: `normalize_suricata_features` |
| RF training feature matrix | `training/Randomforest_training_pipeline.py`: `cols = [c for c in FEATURE_NAMES ...]`, `X_chunk = feats_matched[cols].values` |
| IF training feature matrix | `training/stream_suricata_training.py`: `chunk_to_feature_matrix` → `df[cols]` with `cols` from `FEATURE_NAMES` |
| Runtime schema and X | `inference/runtime_scoring.py`: `load_models` → `schema`, `enforce_schema(df[feature_cols], schema)`, `X = df_schema.values` |
| Runtime use of src_ip | `inference/runtime_scoring.py`: `write_decisions(..., src_ips)`, `context_engine.update_and_escalate(src_ips, ...)` |
| Context engine (IP as key only) | `inference/context_engine.py`: `_store[ip]`, `update_and_escalate(src_ips, ...)` |
| Risk engine (no IP) | `models/risk_engine.py`: `compute(anomaly_scores, attack_proba, severity_scores)` |
| Dataset prep drop IP columns | `scripts/optimize_cicids_merged_for_rf.py`: `_is_drop_column`, DROP_PATTERNS |
