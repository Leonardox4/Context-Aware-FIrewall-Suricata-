# Technical Audit: ML Firewall Training Pipeline — Feature Schema and Suricata Alert Impact

**Scope:** Feature schema consistency across IF training, RF training, and runtime; impact of Suricata alert-derived features when runtime runs without rules.

**Conclusion summary:** No schema drift (single 13-feature list everywhere). IF trained on flow-only data sees alert features as constant 0 → **SAFE**. RF trained on CIC-only sees alert features as 0 → **SAFE**. RF trained on CIC + Suricata-with-rules can learn from alert_* → **NEEDS RETRAINING** if runtime is flow-only.

---

## 1. IF Training Schema Verification

### 1.1 Scripts and code paths

- **Hybrid pipeline:** `training/hybrid_training_pipeline.py`  
  Suricata → `load_suricata_eve` + `map_eve_event` → `records_to_matrix(rows)` → `X_suricata`. Then `X_all = vstack(X_cic, X_suricata)`, `y_all = concat(y_cic, y_suricata)`. IF is fit on `X_benign = X_scaled[benign_mask]` where `benign_mask = (y_all == 0)`. So IF sees **only benign rows**; those from Suricata have `has_alert=0` → no `"alert"` in event → alert_* are 0.
- **Streaming Suricata-only:** `training/stream_suricata_training.py`  
  `iter_eve_chunks(..., event_type_filter="flow")` → `filter_benign_flows(chunk_events)` (drops `flow.alerted == True`) → `chunk_to_feature_matrix(benign)` → `normalize_suricata_features(events)` then `df[FEATURE_NAMES]`. So IF is trained **only on benign flows**. With Suricata run **without rules**, no event has `"alert"` → all rows have alert_* = 0.

### 1.2 Exact feature list used during IF training

**Both training paths use the same schema from `ingestion/unified_schema.py`:**

```text
FEATURE_NAMES (13 features, fixed order):
 1. src_port
 2. dst_port
 3. protocol
 4. flow_duration
 5. packets
 6. bytes
 7. packet_rate
 8. byte_rate
 9. alert_severity
10. alert_category
11. alert_signature_present
12. hour_of_day
13. day_of_week
```

So **alert-derived features (9–11) are included in the IF training matrix** in code. The important point is their **values** at training time.

### 1.3 Were alert-derived features present during IF training?

- **Streaming script (eve from Suricata without rules, e.g. 4GB flow-only):**  
  Only flow events; no event has `"alert"`. In `normalize_suricata_features`: `has_alert = 1 if "alert" in ev else 0` → 0; then `alert_severity = 0.0`, `alert_category = 0`, `alert_signature_present = 0`. So **all training rows have alert_* = (0.0, 0, 0)**. The columns are present but constant.
- **Hybrid pipeline with Suricata:**  
  IF is fit on **benign only** (`y_all == 0`). Suricata benign events have no `"alert"` → alert_* = 0. CIC benign also has alert_* = 0 (hardcoded in `normalize_cic_features`). So **again, alert_* are always 0 for IF training data**.

**Conclusion:** Alert-derived features **are in the IF feature list** but **were always zero** in the data used to train IF (flow-only or benign-only). No non-zero alert values are seen by IF during training.

### 1.4 IF trained strictly on benign only?

- **Hybrid:** `X_benign = X_scaled[benign_mask]` with `benign_mask = (y_all == 0)`. So yes, **benign only** (and if no benign, fallback to all data with a warning).
- **Streaming:** `filter_benign_flows(chunk_events)` keeps only events where `flow.get("alerted") is not True`, then `chunk_to_feature_matrix(benign)`. So **benign flows only**.

**Conclusion:** IF is trained strictly on benign flows in both pipelines.

---

## 2. Feature Pipeline Comparison

### 2.1 Current FEATURE_NAMES (single source of truth)

**File:** `ingestion/unified_schema.py`

```python
FEATURE_NAMES = [
    "src_port", "dst_port", "protocol", "flow_duration",
    "packets", "bytes", "packet_rate", "byte_rate",
    "alert_severity", "alert_category", "alert_signature_present",
    "hour_of_day", "day_of_week",
]
```

Length 13; order fixed. No IP in ML input.

### 2.2 IF training feature schema

- **Source:** Same `FEATURE_NAMES` via `records_to_matrix(rows)` (hybrid) or `chunk_to_feature_matrix()` → `normalize_suricata_features` + `df[FEATURE_NAMES]` (streaming).
- **Values at training:** For IF, effectively **alert_* = 0** (flow-only or benign-only). Flow features vary.

### 2.3 RF training feature schema

- **Source:** Same `FEATURE_NAMES`; matrix from `records_to_matrix(rows)` (CIC and/or Suricata).
- **CIC:** `normalize_cic_features` sets `alert_severity=0.0`, `alert_category=0`, `alert_signature_present=0` for every row.
- **Suricata:** If the eve.json was produced **with rules**, some events have `"alert"` → non-zero alert_* and `label=1`. So **RF can see non-zero alert_* when trained on Suricata-with-rules**.

### 2.4 Runtime feature extraction schema

- **Source:** `inference/runtime_scoring.py` loads `schema = config.get("feature_names", FEATURE_NAMES)`. Then `normalize_suricata_features(chunk_events)` or `normalize_cic_features(chunk_df)` → `enforce_schema(df, schema)` so column order and presence match the saved schema (missing columns filled with 0).
- **Suricata flow-only (no rules):** No event has `"alert"` → `alert_severity=0`, `alert_category=0`, `alert_signature_present=0` for every row.

### 2.5 Schema drift?

- **Column set and order:** No drift. One list (`FEATURE_NAMES`) used everywhere; runtime uses the same list from config (or fallback).
- **Value distribution:**  
  - **IF:** Training = alert_* always 0; Runtime flow-only = alert_* always 0 → **no distribution drift**.  
  - **RF:** If trained on **CIC only** → alert_* always 0; runtime 0 → **no drift**. If trained on **CIC + Suricata-with-rules** → RF saw some non-zero alert_*; runtime always 0 → **distribution drift** (RF may rely on alert_* as a signal).

---

## 3. Suricata Logging Mode Impact

### 3.1 Does enabling Suricata rules change flow feature values?

- **Flow-level fields** (e.g. `flow.pkts_toserver`, `flow.bytes_toserver`, `src_port`, `dest_port`, `proto`, `timestamp`) come from the same flow record. Enabling or disabling rules does **not** change these values for the same flow.
- **Alert fields** are set only when the event has an `"alert"` key. With rules **off**, no event has `"alert"` → alert_* are always 0. With rules **on**, some flow events (or linked alert events) have `"alert"` → those rows get non-zero alert_*.

So: **Enabling rules does not change flow feature values; it only adds alert context (and possibly more event volume) where a rule fired.**

### 3.2 Does 4GB vs 16GB affect ML features?

- **4GB (flow-only, no rules):** Only flow events; no `"alert"` in any event. All rows: alert_* = 0. Flow features (ports, bytes, packets, rates, etc.) are normal.
- **16GB (with rules):** More events (alert events + flow events). If we use only `event_type == "flow"`, we still get flow events; some of them may contain `"alert"` when that flow triggered a rule. So **some** rows have non-zero alert_*. File size difference is mainly from extra event types and volume, not from changing the flow feature extraction.

So: **The 4GB vs 16GB difference does not change flow feature extraction logic.** It changes whether **alert_* are ever non-zero** (4GB: never; 16GB: sometimes, for events with `"alert"`).

---

## 4. Alert Feature Dependency Analysis

### 4.1 Does RF training currently depend on alert-derived features?

- **Code:** RF is trained on the same 13-column matrix as IF; no code path drops alert_* for RF only.
- **Data:**  
  - If training data is **CIC only:** alert_* are always 0; RF cannot learn from them (zero variance).  
  - If training data includes **Suricata-with-rules:** Some rows have non-zero alert_* and label=1 (has_alert). RF can learn that high alert_severity / alert_signature_present correlate with attack. So **RF can depend on alert_* when Suricata-with-rules was used in training.**

### 4.2 Risk if runtime sensor runs without rules

- **Runtime:** Flow-only → no `"alert"` → alert_* = 0 for every row.
- **If RF was trained on CIC only:** Training and runtime both have alert_* = 0 → **no risk**.
- **If RF was trained on CIC + Suricata-with-rules:** At runtime, alert_* are always 0. So:
  - The model may have learned “alert present → attack”. At runtime that signal is always off → **possible under-prediction of attack** (lower P(attack)).
  - Or, if the only “attack” examples from Suricata were those with alerts, RF may have over-weighted alert_*; then at runtime **attack probability could be systematically lower** than intended.

So: **Risk of probability drift or mismatch exists only when RF was trained with Suricata data that included events with alerts, and runtime has no alerts.**

### 4.3 Summary table

| Training data for RF              | Runtime (flow-only) | Alert feature risk                    |
|----------------------------------|---------------------|----------------------------------------|
| CIC only                         | alert_* = 0         | None                                   |
| CIC + Suricata flow-only (4GB)   | alert_* = 0         | None                                   |
| CIC + Suricata with rules (16GB) | alert_* = 0         | Possible under-prediction / drift      |

---

## 5. Retraining Requirement Assessment

### 5.1 Isolation Forest

- IF is trained on benign only; in practice (flow-only or benign-only) alert_* were always 0. Runtime (flow-only) also has alert_* = 0. Schema and distribution align.
- **Conclusion: IF retraining is NOT required** after “removing” alert features, because in practice they were already constant 0 for IF. Keeping them in the schema with 0 at runtime is consistent.

### 5.2 Random Forest

- **If current RF was trained on CIC only (or CIC + Suricata flow-only):** alert_* were always 0; runtime 0. **No retraining needed.**
- **If current RF was trained with Suricata eve that had rules enabled (events with `"alert"`):** RF may rely on alert_*; runtime has no alerts → **retraining is recommended.** Retrain RF on data where alert_* are 0 for all samples (e.g. CIC only, or Suricata flow-only, or Suricata-with-rules but with alert_* zeroed out in code so RF does not see them).

### 5.3 SAFE / NEEDS RETRAINING

| Scenario | IF | RF |
|----------|----|----|
| IF trained on 4GB flow-only; RF trained on CIC only; runtime flow-only | **SAFE** | **SAFE** |
| IF trained on 4GB flow-only; RF trained on CIC + Suricata (16GB with rules); runtime flow-only | **SAFE** | **NEEDS RETRAINING** |
| IF trained via hybrid on benign-only (CIC+Suricata); RF on CIC only; runtime flow-only | **SAFE** | **SAFE** |
| IF trained via hybrid; RF on CIC + Suricata with rules; runtime flow-only | **SAFE** | **NEEDS RETRAINING** |

---

## 6. Final Recommendations

### 6.1 Cleanest architecture (IF + RF, Suricata without rules at runtime)

- **Single schema:** Keep one 13-feature list. All components (IF, RF, scaler, runtime) use the same order and names. No schema drift.
- **Behavioral anomaly detection:** IF trained on benign flow-only (or benign-only) data so that “normal” is defined by flow behavior only; alert_* are 0 in that training set. Runtime flow-only matches that.
- **RF not dependent on alerts:** Train RF on data where alert_* are always 0: e.g. **CIC only**, or CIC + Suricata flow-only (no rules). Then at runtime (flow-only), RF input distribution matches training.
- **Optional hardening:** If you want to make the “no alert dependency” explicit, you could zero out alert_* in the training path for RF (e.g. after normalization, set those columns to 0) so that RF never sees non-zero alert values even if Suricata-with-rules data is ever mixed in. That would be a minimal code change and would make RF robust to any future mix of data sources.

### 6.2 Minimal fixes (no overengineering)

1. **Document training data for artifacts:** Record in `config.joblib` or a small metadata file whether RF was trained with “Suricata-with-alerts” (e.g. `rf_trained_with_suricata_alerts: bool`). That way you can decide whether to retrain when moving to flow-only runtime.
2. **If current RF was trained with Suricata-with-rules:** Retrain RF using only CIC, or CIC + Suricata flow-only (4GB), or the same Suricata data but with alert_* forced to 0 after normalization. Then redeploy artifacts.
3. **No need to remove alert_* from the schema:** Keeping them with value 0 at runtime preserves schema consistency and avoids changing artifact format or inference code. IF and RF both already accept 13 features; runtime just feeds 0 for alert_* when there are no alerts.
4. **Streaming IF training (4GB):** Already correct: flow-only → benign only → alert_* = 0. No code change required for IF.

### 6.3 Action plan for resolving inconsistencies

| Step | Action |
|------|--------|
| 1 | Confirm how current RF was trained: CIC only, or CIC + Suricata, and whether that Suricata eve had rules enabled (any events with `"alert"`). |
| 2 | If RF was trained with Suricata-with-rules: Retrain RF on CIC only, or CIC + Suricata flow-only, or zero out alert_* in training data so RF never sees non-zero alert features. Save new `random_forest.joblib` (and optionally re-save scaler/config if you want consistency). IF and scaler can be left as-is if IF was trained on flow-only/benign-only. |
| 3 | Optionally add to config at save time: `"rf_trained_with_alert_features": False` (or True) so deployment can check. |
| 4 | Run inference with flow-only eve; compare risk distribution and HIGH/MEDIUM counts to a baseline if available. |

---

## Explicit Answers (Output Requirements)

| Question | Answer |
|----------|--------|
| **Explicit feature list used by IF** | `src_port`, `dst_port`, `protocol`, `flow_duration`, `packets`, `bytes`, `packet_rate`, `byte_rate`, `alert_severity`, `alert_category`, `alert_signature_present`, `hour_of_day`, `day_of_week` (13 features, `ingestion/unified_schema.py` FEATURE_NAMES). |
| **Were alert fields present during IF training?** | Yes in the **schema** (columns 9–11). In the **data**, they were **always 0** for IF (flow-only or benign-only Suricata + CIC benign). |
| **Schema mismatch currently?** | No column or order mismatch. **Value distribution mismatch** for RF only if RF was trained with Suricata data that included events with alerts and runtime is flow-only (alert_* always 0). |
| **Action plan** | See §6.3: confirm RF training data; if it included Suricata-with-rules, retrain RF on data with alert_* = 0; optionally record in config; validate with flow-only inference. |
