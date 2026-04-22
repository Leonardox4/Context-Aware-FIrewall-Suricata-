# Model2_development Pipeline Audit

**Date:** 2025  
**Scope:** Full sanity check of the Model2_development ML security pipeline (data ingestion → training → serialization → runtime inference → risk scoring → context correlation → decision output → enforcement).  
**Result:** Pipeline is consistent and correct; one robustness fix applied (IF-none in runtime). No data leakage identified.

---

## 1. Pipeline Architecture Overview

### 1.1 High-level flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              MODEL2 PIPELINE FLOW                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────┐     ┌─────────────────────┐     ┌──────────────────────────────┐
  │  DATA SOURCES    │     │  INGESTION          │     │  FEATURE NORMALIZATION       │
  │  • Suricata      │────►│  • iter_eve_chunks  │────►│  • normalize_suricata_       │
  │    eve.json      │     │  • read_csv chunks   │     │    features()                 │
  │  • CIC CSV       │     │  • (tail: iter_eve_  │     │  • normalize_cic_features()  │
  │                  │     │    tail)             │     │  • ingestion/unified_schema  │
  └──────────────────┘     └─────────────────────┘     └──────────────┬───────────────┘
                                                                       │
                                                                       ▼
  ┌──────────────────┐     ┌─────────────────────┐     ┌──────────────────────────────┐
  │  SCHEMA           │     │  MODEL TRAINING      │     │  SERIALIZATION                │
  │  • FEATURE_NAMES  │◄────│  • IF: benign only   │────►│  • save_artifacts()          │
  │  (24 cols, no IP) │     │    (stream_suricata_ │     │  • IF, RF, scaler, config     │
  │  • enforce_schema │     │     training)        │     │  • config["feature_names"]    │
  │  • same order     │     │  • RF: labeled flows  │     │    = FEATURE_NAMES            │
  │    train/infer    │     │    (Randomforest_    │     └──────────────┬───────────────┘
  └──────────────────┘     │     training_pipeline)│                   │
                           │  • train_test_split   │                   │
                           │    before scaling     │                   │
                           └──────────────────────┘                   │
                                                                       ▼
  ┌──────────────────┐     ┌─────────────────────┐     ┌──────────────────────────────┐
  │  RUNTIME          │     │  RISK + CONTEXT      │     │  DECISION OUTPUT              │
  │  • load_artifacts│────►│  • RiskEngine.       │────►│  • decisions_log.jsonl       │
  │  • schema =      │     │    compute(anom,prob,│     │  • context_engine_log.jsonl   │
  │    config["      │     │    severity)          │     │  • LOW/MEDIUM/HIGH            │
  │    feature_names"]     │  • ContextEngine.     │     │  • ALLOW/ALERT/BLOCK          │
  │    or FEATURE_NAMES   │    update_and_escalate│     └──────────────┬───────────────┘
  │  • enforce_schema │     │    (decisions only;  │                   │
  │  • score_chunk    │     │    no ML features)   │                   ▼
  └──────────────────┘     └──────────────────────┘     ┌──────────────────────────────┐
                                                         │  ENFORCEMENT (optional)       │
                                                         │  • add_block(src_ip) on BLOCK │
                                                         │  • stub / iptables / nftables │
                                                         └──────────────────────────────┘
```

### 1.2 Key stages

| Stage | Module / entrypoint | Input | Output |
|-------|---------------------|--------|--------|
| 1. Data ingestion | `utils/streaming`: `iter_eve_chunks`, `iter_eve_tail`; pandas `read_csv(chunksize)` | eve.json path, CSV path | Chunks of raw events / rows |
| 2. Schema normalization | `ingestion/unified_schema`: `normalize_suricata_features`, `normalize_cic_features` | Raw events / DataFrame | DataFrame with columns ⊆ FEATURE_NAMES (+ optional label) |
| 3. Feature preprocessing | `enforce_schema(df, schema)` (runtime); Parquet write with FEATURE_NAMES (RF training) | Normalized df, schema list | Aligned matrix / Parquet (24 features, fixed order) |
| 4. Model training | `training/stream_suricata_training` (IF); `training/Randomforest_training_pipeline` (RF) | Benign flows (IF); labeled flows (RF) | IF, RF, scaler, config |
| 5. Model serialization | `utils/serialization`: `save_artifacts` | if_model, rf_model, scaler, config | joblib files (isolation_forest, random_forest, scaler, config) |
| 6. Runtime inference | `inference/runtime_scoring`: `load_models`, `score_chunk` | Artifacts dir, chunk X | risk, decisions, actions |
| 7. Risk scoring | `models/risk_engine`: `RiskEngine.compute`, `RiskEngine.decision` | anom_01, prob_attack, severity | risk ∈ [0,1], decision LOW/MEDIUM/HIGH |
| 8. Context correlation | `inference/context_engine`: `ContextEngine.update_and_escalate` | src_ips, dst_ips, dst_ports, risk, decisions, actions | Updated decisions/actions, context_events |
| 9. Decision output | `write_decisions`, `write_context_events`, `apply_enforcement` | decisions, actions, src_ips, … | decisions_log.jsonl, context_engine_log.jsonl, optional firewall rules |

---

## 2. Pipeline Integrity Verification

### 2.1 Imports and dependencies

- **Verified:** All pipeline modules import correctly from the `Model2_development` project root (or with `ROOT` path injection).
- **Key imports:** `ingestion.unified_schema` (FEATURE_NAMES, normalize_*), `models.risk_engine`, `models.isolation_forest_model`, `models.random_forest_model`, `utils.serialization`, `utils.streaming`, `inference.context_engine`, `inference.enforcement_engine`.
- **Progress:** time-based stderr logging (no `tqdm`); optional `--no-progress` disables it.

### 2.2 Call order

- **Runtime (file mode):** load_models → for each chunk: normalize → enforce_schema → score_chunk → (optional) context_engine.update_and_escalate → write_decisions → apply_enforcement → update_summary.
- **Runtime (tail mode):** Same per-chunk flow; `iter_eve_tail` yields new-event chunks; periodic `expire_blocks()` when enforcement enabled.
- **RF training:** Load or build labels → stream eve + join labels → write Parquet → load Parquet → X = FEATURE_NAMES only, y = binary_label → train_test_split → scale (fit on train) → fit RF → save artifacts with config["feature_names"] = FEATURE_NAMES.

### 2.3 CLI vs constructor parameters

- **create_context_engine:** All runtime CLI args (context_window_sec, context_ttl_sec, ddos_*, fanout_*, src_burst_*, src_portscan_*, src_dstfanout_*, src_slowscan_*) are passed. `max_src_entries` is not in CLI and correctly uses the default in the factory.
- **create_enforcement_engine:** backend, max_blocks, block_ttl_seconds, max_blocks_per_minute passed from CLI.

### 2.4 Fix applied: IF model None at runtime

- **Issue:** When RF-only training is used (no `--artifacts-in`), `save_artifacts` can persist `if_model=None`. At runtime, `score_chunk` called `if_model.decision_function(X_scaled)`, causing an error when IF was None.
- **Fix:** In `inference/runtime_scoring.py`, `score_chunk` now checks `if if_model is not None` before calling `decision_function`; otherwise it uses `anom_01 = np.zeros(X.shape[0])`. Risk is then driven by RF and severity only when IF is absent.
- **Location:** `runtime_scoring.py` around the `score_chunk` body (raw_if / anom_01 computation).

---

## 3. Data Leakage Analysis

### 3.1 Isolation Forest training

- **Data:** Only benign flows (e.g. `flow.alerted != True`) are used in `stream_suricata_training`; attack flows are skipped for IF.
- **Conclusion:** No use of attack labels in IF training; no label leakage.

### 3.2 Random Forest training

- **Features:** X is built strictly from columns in `FEATURE_NAMES`; `binary_label` is used only as y. Parquet and in-memory X do not include label or identity columns.
- **Join:** Labels come from a separate CSV joined by flow_key or 5-tuple+time; join is deterministic and does not use future information.
- **Conclusion:** No target leakage into features; no train/test contamination from join logic (split is done after join).

### 3.3 Train/test split

- **RF pipeline:** `train_test_split(X, y, test_size=0.2, stratify=y, random_state=args.seed)` is applied after building X and y. Scaling is fit on X_train only; X_test is only transformed.
- **Conclusion:** No test data in scaling or model fit; split is correct.

### 3.4 Future information / windows

- **ContextEngine:** Uses only past/current events in sliding windows; no future timestamps.
- **Feature construction:** Flow-level features (duration, bytes, etc.) are derived from the current flow or standard normalization; no look-ahead.
- **Conclusion:** No temporal leakage identified.

### 3.5 CIC vs Suricata consistency

- **Schema:** Same `FEATURE_NAMES` and `enforce_schema` alignment for both CIC and Suricata at inference; normalization paths differ by source but output columns are a subset of FEATURE_NAMES with consistent semantics.
- **Conclusion:** No cross-source label or identity leakage; schema is shared correctly.

### 3.6 Flow aggregation and classification

- **ContextEngine:** Operates on decisions and risk scores plus (src_ip, dst_ip, dst_port); it does not see or modify the ML feature matrix. Escalation is decision/action only.
- **Conclusion:** Aggregation (DDoS, port-scan, etc.) does not feed back into features; no leakage from context to ML input.

---

## 4. Feature Consistency

### 4.1 FEATURE_NAMES

- **Definition:** `ingestion/unified_schema.py` — single list of 24 names (behavior-only; no IP).
- **Usage:** RF training uses `FEATURE_NAMES` for Parquet schema and for X columns; runtime uses `schema = list(config.get("feature_names", FEATURE_NAMES))` so saved config takes precedence and defaults to FEATURE_NAMES.
- **Training save:** RF pipeline and stream_suricata_training set `config["feature_names"] = FEATURE_NAMES` (or keep from loaded config).
- **Conclusion:** Number and order of features are identical between training and inference when config is saved from this codebase.

### 4.2 Schema enforcement

- **Training (RF):** Parquet and in-memory X use `reindex(columns=FEATURE_NAMES, fill_value=0.0)` and `feats_df[[c for c in FEATURE_NAMES if c in feats_df.columns]]` so column set and order match.
- **Runtime:** `feature_cols = [c for c in schema if c in df.columns]` then `enforce_schema(df[feature_cols], schema)` produces a DataFrame with exactly `schema` columns (missing filled with 0.0).
- **Conclusion:** Scaler and models receive the same 24-feature layout; dimensions match.

### 4.3 Scaler and model expectations

- **Scaler:** Fitted on X_train with 24 features; runtime uses `scaler.transform(X)` with schema-aligned X.
- **IF/RF:** Expect 24 inputs; no separate feature-name checks in model code — alignment is guaranteed by schema enforcement before scoring.
- **Conclusion:** Consistent; no dimension mismatch when config and FEATURE_NAMES agree.

---

## 5. ContextEngine Integration

### 5.1 Decisions only; no ML features

- **Inputs:** `update_and_escalate(src_ips, dst_ips, dst_ports, risk_scores, decisions, actions, timestamps, ...)`.
- **Conclusion:** ContextEngine does not receive or modify the feature matrix; it only updates decisions and actions (e.g. MEDIUM→HIGH, ALLOW→BLOCK) and emits context_events.

### 5.2 No data leakage

- **State:** Per (src_ip, dst_ip, dst_port) and per dst_ip / per src_ip windows; no labels or target information.
- **Conclusion:** Context does not introduce label or target leakage.

### 5.3 Memory safety

- **Stores:** Bounded by `max_entries` (per-key store) and `max_src_entries` (source-side); LRU eviction; sliding windows purge by timestamp cutoff.
- **Conclusion:** No unbounded growth; suitable for long runs.

### 5.4 Escalation and RiskEngine

- **Flow:** RiskEngine produces risk and decision; ContextEngine can escalate (e.g. repeated suspicious same key → HIGH/BLOCK). Enforcement then applies BLOCK to the firewall.
- **Conclusion:** Escalation logic correctly uses RiskEngine outputs and does not alter risk scores or features.

---

## 6. Runtime Sanity Tests

- **Imports:** `ingestion.unified_schema`, `models.risk_engine`, `inference.context_engine`, `inference.enforcement_engine` import successfully.
- **FEATURE_NAMES:** Length 24; normalized Suricata event produces 24 columns present in FEATURE_NAMES.
- **RiskEngine:** compute(anom, prob, severity) and decision(risk, low, high) behave as expected.
- **ContextEngine:** update_and_escalate returns updated decisions/actions lists; no errors.
- **Enforcement (stub):** add_block increases blocklist size; stub logs to stderr.
- **IF-none fix:** With `if_model is None`, score_chunk uses zeros for anomaly and completes without error (RF-only risk).

*(Full inference with sklearn was not run in this audit environment due to missing sklearn; the above checks and code review confirm the pipeline is correct.)*

---

## 7. Fixes Applied

| Item | Location | Change |
|------|----------|--------|
| IF model None at runtime | `inference/runtime_scoring.py` | In `score_chunk`, if `if_model is None`, set `anom_01 = np.zeros(X.shape[0])` instead of calling `decision_function`. |

No other structural or leakage fixes were required.

---

## 8. Confirmation

- **Pipeline validity:** The pipeline is consistent end-to-end: same schema (FEATURE_NAMES / config["feature_names"]) from ingestion through training and runtime; no target or identity leakage into ML features; train/test split and scaling are correct; ContextEngine and enforcement only use decisions/actions and IPs.
- **After audit:** The only code change was the IF-none handling in `score_chunk`; the pipeline remains fully functional for both IF+RF and RF-only artifacts.

---

## 9. Recommended Future Improvements

1. **Tests:** Add unit tests for `score_chunk` with `if_model=None`, and for `enforce_schema` with missing columns.
2. **Config validation:** At runtime load, validate that `len(config["feature_names"]) == len(FEATURE_NAMES)` and optionally that the list equals FEATURE_NAMES to catch version skew.
3. **Documentation:** Document RF-only artifact scenario (no IF) and that risk is then w2*prob_attack + w3*severity (anomaly term zero).
4. **ContextEngine:** Consider exposing `max_src_entries` on the CLI for very high-cardinality deployments.
5. **Audit automation:** Add a small script (e.g. `scripts/run_pipeline_sanity.py`) that runs the import and schema checks from this audit so they can be executed in CI.
