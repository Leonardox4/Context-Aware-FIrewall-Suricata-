# Model2_development — ML Firewall Infrastructure (Complete Reference)

Single reference for the **Hybrid ML-based Context-Aware Firewall**: architecture, data flow, artifacts, deployment, and operations. All paths are relative to **`Model2_development/`** (primary repo) unless stated otherwise. A legacy **`Model2/`** tree may exist in the same workspace; do not mix Rust `eve_extractor` builds between them—see **`docs/EVE_EXTRACTOR_SOURCE_OF_TRUTH.md`**.

---

## 1. High-Level Overview

### Project goal

**Hybrid ML-based Context-Aware Firewall:** combine unsupervised anomaly detection and supervised attack classification into one risk score that drives ALLOW / ALERT / BLOCK. The system is designed for a learning-stage but production-aware IDS/firewall pipeline.

### Why Isolation Forest + Random Forest

- **Isolation Forest (IF):** Unsupervised anomaly detection. Trained on **benign traffic only** (Suricata flows or CIC benign). Detects deviations from “normal” without attack labels. Handles zero-day and novel patterns.
- **Random Forest (RF):** Supervised binary classifier (benign vs attack). Trained on **labeled CIC (and optionally Suricata)** data. Provides interpretable attack probability and works well with the same flow-level features.
- **Together:** Anomaly score (IF) + attack probability (RF) + optional Suricata alert severity are combined into one **risk score**. This gives both “unusual” (IF) and “known-bad” (RF) signals, plus rule-based alert context.

### How anomaly and classification integrate

- Both models consume **the same 13 behavior-only features** from `ingestion/unified_schema.py`. No per-model feature logic.
- At inference: flow → unified schema → scaler (transform only) → IF `decision_function` → RF `predict_proba` → risk formula → decision (LOW/MEDIUM/HIGH) → action (ALLOW/ALERT/BLOCK).
- **Risk formula:** `risk = w1*anomaly + w2*attack_prob + w3*severity` (default weights 0.4, 0.4, 0.2). Decision thresholds map risk to LOW / MEDIUM / HIGH.

### Where the system fits

- **Input:** Labeled datasets (CIC) for training; at runtime, **Suricata eve.json** (from PCAP replay or live) or **CIC-style CSV** for batch scoring.
- **Output:** Risk score and decision per flow; logs (e.g. `decisions_log.jsonl`); optional integration with a firewall (iptables/nftables) via a small adapter. PCAP → Suricata → eve.json is **external**; this pipeline starts from eve.json or CSV.

---

## 2. Full Pipeline — Step-by-Step

### A. Data sources

| Source | Role | Benign vs attack |
|--------|------|------------------|
| **CICIDS2017 / CICIoT2023** | CSV with flow columns + label. Primary source for **RF** (attack labels). | CIC: `Label` (or attack-type column) → 0 = benign, 1 = attack. `unified_schema` maps “BENIGN”/“Normal Traffic” → 0. |
| **Suricata eve.json** | JSONL from Suricata (PCAP or live). Used for **IF** training (benign flows), for **RF features**, and for **runtime inference**. | Suricata: no explicit “attack” label; in the new RF pipeline labels come only from external CSV; in the legacy hybrid pipeline `has_alert` was used as a surrogate label when combined with CIC. |
| **Balanced/merged datasets** | `Datasets/AttackHeavy/CICIDS_merged/` and `CICIDS_merged_optimized/` (scripts: `merge_cicids_datasets.py`, `optimize_cicids_merged_for_rf.py`). | Unified taxonomy (e.g. benign, dos_ddos, recon, brute_force); binary `label_binary` 0/1 for RF. |

No synthetic data generation in the core pipeline; balancing is done by downsampling (e.g. cap per attack class) in the merge/optimize scripts.

### B. Data ingestion

- **CSV (CIC):**
  - **Small files:** `ingestion/cic_loader.load_cic_csv(path, max_rows=None)` → yields canonical records (dicts) via `unified_schema.record_from_cic_row(row)`.
  - **Large files:** `training/chunk_loader.iter_cic_chunks(filepath, chunk_size=50_000, max_total_rows=None)` → yields `(list of records, list of labels)` per chunk. Uses same `map_cicids_row` → `record_from_cic_row`. Memory-safe.
- **eve.json (Suricata):**
  - **Training:** `ingestion/suricata_loader.load_suricata_eve(filepath, max_events=None)` → raw eve dicts; each mapped with `map_eve_event(ev)` → `unified_schema.record_from_eve_event(ev)`.
  - **Streaming (training + inference):** `utils/streaming.iter_eve_chunks(filepath, chunk_size, event_type_filter="flow", ...)` → yields lists of raw eve dicts. No full-file load; progress callback by bytes/events.
- **Schema mapping:** All records are normalized to the **unified feature structure** (see §2C). Missing columns/fields → 0 or safe default. CIC column variants (e.g. “Source IP”, “ Flow Duration”) are handled in `unified_schema.normalize_cic_features()`; eve fields in `normalize_suricata_features()` / `record_from_eve_event()`.

### C. Unified feature engineering

- **Single source of truth:** `ingestion/unified_schema.py`. **Behavior-only:** no IP in the ML feature vector. IP is used only for context correlation, logging, and dashboard (from raw events).
- **Canonical features (13, fixed order):**  
  `src_port`, `dst_port`, `protocol`, `flow_duration`, `packets`, `bytes`, `packet_rate`, `byte_rate`, `alert_severity`, `alert_category`, `alert_signature_present`, `hour_of_day`, `day_of_week`.
- **Encoding:** Protocol → 6 (TCP), 17 (UDP), 1 (ICMP), else 0. Alert severity normalized to [0,1]; category → small int (hash); temporal from timestamp (CIC often 0). Missing → 0.
- **Scaling:** `StandardScaler` fit on combined (CIC + Suricata) training matrix; at inference only `transform` is used. Same scaler for IF and RF.
- **Consistency:** Both IF and RF receive the same matrix columns (order = `FEATURE_NAMES`). Built via `records_to_matrix(records)` or `build_feature_vector(record)`; runtime uses `enforce_schema(df, schema)` to align to saved `feature_names` and fill missing with 0.

### D. Isolation Forest (anomaly model)

- **Training data:** Benign only. Mask `y_all == 0` on the combined scaled matrix; IF is fit on `X_scaled[benign_mask]`. If no benign samples, pipeline falls back to fitting on all data (with a warning).
- **Sampling:** No explicit “sampling from X million”; full benign set (or chunked benign from CIC/Suricata) is used. For very large benign sets, training uses the in-memory combined array (chunked CIC + Suricata loaded in chunks then concatenated).
- **Parameters:** `contamination=0.1`, `n_estimators=100`, `random_state=42` (from `utils/config.py`: `DEFAULT_IF_CONTAMINATION`, `DEFAULT_IF_ESTIMATORS`).
- **Threshold:** No fixed “anomaly threshold” in the model; raw `decision_function(X)` (negative = more anomalous) is converted to [0,1] by `models/isolation_forest_model.anomaly_score_to_01()` (1 = most anomalous). That [0,1] score is then combined with RF and severity in the risk engine.
- **Output:** Anomaly score in [0,1] per sample. Interpretation: higher = more anomalous; combined with RF and severity for final risk.

### E. Random Forest (attack classifier)

- **Primary RF pipeline (eve + CSV ground truth):**
  - **Features:** 13 canonical features from `normalize_suricata_features` applied to eve.json flow events (same schema as IF).
  - **Labels:** Binary `binary_label` (0 = benign, 1 = attack) from an external CSV joined by 5‑tuple + timestamp bucket. Suricata alerts are **not** used as labels.
  - **Attack subclasses:** Optional `attack_subclass` column in the CSV is preserved for analytics (stored in config) but RF remains binary.
- **Legacy hybrid RF pipeline (CIC + Suricata):**
  - **Features:** Same 13-feature schema, built from CIC CSV and Suricata eve.json.
  - **Labels:** CID CSV `Label` → 0/1; Suricata label derived from `has_alert`. This path is kept for backward compatibility but is no longer the recommended way to train RF.
- **Class balancing:** `class_weight="balanced"` in `build_random_forest()`. Dataset-level balancing (e.g. ~55% benign, cap per attack class) is handled in dataset prep scripts, not in the RF trainer.
- **Evaluation (legacy hybrid):** `train_test_split` on combined data; accuracy, confusion matrix, classification report (Benign/Attack); IF anomaly score distribution on test set.

### F. Risk scoring engine

- **Location:** `models/risk_engine.py`. `RiskEngine(w1, w2, w3)`. `compute(anomaly_scores, attack_proba, severity_scores=None)` → risk array in [0,1]. `decision(risk_score, low_thresh, high_thresh)` → "LOW" | "MEDIUM" | "HIGH".
- **Combination:** `risk = w1*anomaly + w2*attack_prob + w3*severity` (all in [0,1]; result clipped to [0,1]). Default weights 0.4, 0.4, 0.2 (`utils/config.py`).
- **Thresholds:**  
  - **Config default:** `LOW_THRESH=0.3`, `HIGH_THRESH=0.7` (`utils/config.py`; `risk_engine.decision()` defaults).  
  - **Runtime default:** `inference/runtime_scoring.py` uses `DEFAULT_LOW_THRESH=0.30`, `DEFAULT_HIGH_THRESH=0.60` (CLI `--low`, `--high`).
- **Decision boundaries:** risk &lt; low → LOW; low ≤ risk &lt; high → MEDIUM; risk ≥ high → HIGH. Actions: LOW → ALLOW, MEDIUM → ALERT, HIGH → BLOCK (mapping in runtime, not in RiskEngine).

---

## 3. Model Artifacts

- **Directory:** Configurable; default **`artifacts/`** (training writes here with `--output-dir`).
- **Files (joblib):**
  - `isolation_forest.joblib` — fitted IsolationForest.
  - `random_forest.joblib` — fitted RandomForestClassifier.
  - `scaler.joblib` — fitted StandardScaler (same feature order as FEATURE_NAMES).
  - `config.joblib` — dict: `weights` (w1, w2, w3), `feature_names` (list, length 13).
- **No separate threshold file:** Thresholds are passed at inference (CLI or API). Config can store defaults but runtime overrides with `--low` / `--high`.
- **Loading:** `utils/serialization.load_artifacts(path_dir)` → (if_model, rf_model, scaler, config). Runtime uses `config.get("feature_names", FEATURE_NAMES)` so old artifacts without `feature_names` still work. **Never re-fit scaler at inference.**

---

## 4. Deployment Architecture

- **Training:** Typically run on a **host** with enough RAM/CPU for the training dataset (CIC + Suricata). No GPU. Python 3.8+, numpy, scikit-learn, joblib, pandas (see `docs/requirements.txt`; optional pyarrow for parquet in dataset scripts).
- **Runtime (inference):** Can run on the same host or a **separate VM** (e.g. firewall VM). Memory-safe: chunked streaming; no full-file load. Artifacts are loaded once per process.
- **Model transfer:** Copy the artifacts directory (all four joblib files) to the runtime machine. Same Python/env and feature schema required. No separate “deployment package” in the repo; directory layout is the same (e.g. `Model2_development/` with `ingestion/`, `models/`, `utils/`, `inference/`).
- **Relevant layout:**  
  `Model2_development/artifacts/` (or custom path) for joblibs; `inference_runtime_score/` default output for runtime (decisions log + summary). Firewall VM would run e.g. `python inference/runtime_scoring.py --artifacts /path/to/artifacts --input /path/to/eve.json --output-dir /path/to/output`.

---

## 5. Runtime Inference Pipeline

End-to-end flow:

```
PCAP (external) → Suricata (external) → eve.json
       OR
CIC-style CSV (batch)
        ↓
[Chunked read: iter_eve_chunks or pd.read_csv(chunksize)]
        ↓
Feature extraction: normalize_suricata_features(chunk) or normalize_cic_features(chunk)
        ↓
enforce_schema(df, schema) → X (float32, correct column order)
        ↓
scaler.transform(X)  (no fit)
        ↓
Isolation Forest: decision_function(X) → anomaly_score_to_01 → anom_01
        ↓
Random Forest: predict_proba(X)[:,1] → attack_prob
        ↓
RiskEngine.compute(anom_01, attack_prob, severity) → risk
        ↓
RiskEngine.decision(risk, low_thresh, high_thresh) → LOW|MEDIUM|HIGH
        ↓
decision_to_action(decision) → ALLOW|ALERT|BLOCK
        ↓
Optional: ContextEngine.update_and_escalate(src_ips, risk, decisions, actions, ...) → escalated decisions/actions
        ↓
write_decisions(risk, decisions, actions, src_ips, log_path) → decisions_log.jsonl
        ↓
(Optional) Firewall enforcement: apply_decision(src_ip, decision, risk) — stub logs only; replace with iptables/nftables
        ↓
At end: write_runtime_summary(stats, output_dir) → runtime_summary.json
```

- **Entry point:** `inference/runtime_scoring.py` (not `runtime_pipeline.py`). CLI: `--artifacts`, `--input` (CSV or eve.json), `--output-dir`, `--format auto|csv|json`, `--chunk-size`, `--low`, `--high`, `--no-progress`, `--no-context`, plus context options (`--context-window-sec`, `--context-ttl-sec`, `--context-max-entries`, `--context-escalate-min`).
- **Real-time processing:** Per-chunk batch: normalize → enforce_schema → score_chunk (scaler + IF + RF + risk + decisions) → write_decisions; then optional context escalation; no accumulation of full predictions in memory.
- **Whitelisting:** Not implemented in code; would be an external step (e.g. filter src_ips before or after scoring, or in firewall adapter).
- **Logging/telemetry:** See §6.

---

## 6. Logging & Monitoring

- **Prediction logs:** `inference_runtime_score/decisions_log.jsonl` (or `--output-dir`). One JSON object per flow: `timestamp`, `src_ip`, `risk_score`, `decision`, `action`.
- **Summary:** `runtime_summary.json`: `total_processed`, `count_low`, `count_medium`, `count_high`, `avg_risk`, `max_risk`, `duration_sec`, `throughput_events_per_sec`.
- **Stderr:** `[LEVEL] message` via Python logging (e.g. INFO for progress, parallelism, errors). Runtime logs CPU cores and IF/RF `n_jobs` at startup.
- **Failure:** Exceptions logged with `logger.exception()`; process exits with non-zero. No built-in deadlock detection; “training freeze” or “runtime crash” are observed via process exit and lack of new log lines / summary file.
- **Debug:** Use `--no-progress` and `--progress-every N` for periodic INFO lines (events processed, avg risk, HIGH count) instead of time-based stderr progress.

---

## 7. Operational Considerations

- **Hardware:** CPU-only. No GPU. RAM: training holds combined CIC+Suricata matrices after load (chunked load reduces peak for CIC); runtime is streamed (bounded by chunk size).
- **Memory limits:** Very large CIC CSVs: use `--chunked-cic` and `iter_cic_chunks`. Eve: always streamed via `iter_eve_chunks`. Runtime uses fixed chunk sizes (default 100k CSV, 50k JSON) and explicit `gc.collect()` after each chunk.
- **Streaming vs batch:** Training can be chunked (CIC) and/or streamed (eve); data is concatenated in memory for scaler fit and model fit. Inference is strictly streaming (no full load).
- **Bottlenecks:** RF inference can be single-threaded if models were trained with older code; current `build_random_forest()` uses `n_jobs=-1`. Runtime logs n_jobs at startup. Disk I/O and JSON parsing can dominate for large eve files.
- **Recovery:** No checkpointing; restart from scratch. For training, re-run with same data and seed for reproducibility.
- **Safe retraining:** Train on a copy of data; save artifacts to a new directory; validate (e.g. run runtime_scoring on a small input); then swap artifact directory for production.

---

## 8. Consistency Check (Doc vs Code)

- **Inference script name:** Documentation previously referred to `inference/runtime_pipeline.py`. **Actual entry point is `inference/runtime_scoring.py`.** CLI uses `--input` (not `--eve`) and `--output-dir`; format auto-detected from extension.
- **Feature set:** README and some older docs may mention `src_ip_encoded`/`dst_ip_encoded` in the feature list. **Current code (unified_schema) uses behavior-only 13 features; no IP in ML input.** Update any doc that still lists IP as a feature.
- **Risk thresholds:** `utils/config.py` has `HIGH_THRESH=0.7`; `inference/runtime_scoring.py` defaults to `DEFAULT_HIGH_THRESH=0.60`. Runtime CLI defaults (0.3 / 0.6) take precedence when using the script; config is used by training and by RiskEngine when not overridden.
- **Firewall stub:** `inference/firewall_adapter_stub.apply_decision()` exists for integration; **runtime_scoring.py does not call it**. Enforcement (iptables) must be wired by the integrator (e.g. read decisions_log.jsonl or add a call after write_decisions).

---

## 9. RF Training Pipeline — Architectural Mapping

- **Primary RF entry point:** `python training/Randomforest_training_pipeline.py --eve <eve.json> --labels-csv <labels.csv> [--artifacts-in artifacts_if] --output-dir artifacts`.
- **Data sources:**
  - **eve.json (`--eve`):** read via `utils.streaming.iter_eve_chunks` (flow events only), normalized by `unified_schema.normalize_suricata_features` into the canonical features. Eve.json is never modified. **Streaming:** matched rows are written **incrementally to Parquet** (pyarrow `ParquetWriter`); no in-memory accumulation of full X/y. Memory-safe for millions of flows.
  - **Ground-truth CSV (`--labels-csv`):** provides `binary_label` (0/1), `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `timestamp`, and optional `attack_subclass`, optional `flow_key` for O(1) join when aligned with the eve source. Labels come **only** from this CSV.
- **Feature dataset cache:**
  - First run: stream eve, join with labels, write `(FEATURE_NAMES, binary_label[, attack_subclass])` to `output_dir/training_dataset.parquet` (or `--features-parquet`). Then load that Parquet, train/test split, scale, train RF, save artifacts.
  - If that Parquet exists and `--rebuild-features` is not set, the pipeline **loads it directly** and skips eve parsing.
- **Matching and feature matrix:**
  - When CSV has `flow_key`: build flow_key per eve event (`src_ip:src_port-dst_ip:dst_port-proto`), lookup in a dict; matched rows are written to Parquet per chunk.
  - Otherwise (5-tuple + time bucket): for each eve chunk, build key DataFrame `(src_ip, dst_ip, src_port, dst_port, protocol_str, ts_bucket)`; inner-merge with labels; matched rows written to Parquet. Features from normalized eve using `FEATURE_NAMES` only.
- **Scaler and artifacts:**
  - If `--artifacts-in` is provided (typically from the Isolation Forest pipeline), existing scaler and IF are loaded; RF is trained on `scaler.transform(X)` from the Parquet.
  - Otherwise, a new StandardScaler is fit on training split and only RF + scaler + config are saved (IF may be `None`).
  - Artifacts are saved with `feature_names = FEATURE_NAMES`, keeping runtime schema identical.
- **Eval-only mode (`--eval-only`):**
  - Load artifacts from `--artifacts-in`; load or build the feature dataset (from `--features-parquet` or from `--eve` + `--labels-csv` → written to `--eval-output-parquet` or default `output_dir/eval_dataset.parquet`). Scale, predict, print metrics (confusion matrix, accuracy, ROC-AUC, FPR). No training, no artifact write. Use this to **test the trained model on another labeled eve.json** (e.g. test set or different capture).
- **Legacy hybrid RF pipeline:**
  - `training/hybrid_training_pipeline.py` is retained for backward compatibility and still trains RF from CIC + optional Suricata labels (using CIC `Label` and Suricata `has_alert`). It is no longer the recommended path for RF training.

This mapping ensures the recommended RF training path uses eve.json features plus external CSV ground truth, never alert-derived labels, with memory-safe streaming and optional feature cache and eval-only evaluation on other datasets.

---

## Quick reference

| Item | Location / value |
|------|------------------|
| Unified schema (13 features) | `ingestion/unified_schema.py` — FEATURE_NAMES |
| IF training (streaming) | `python training/Isolationforest_training_pipeline.py --dataset <eve.json> --output-dir artifacts_if` |
| RF training (eve + CSV) | `python training/Randomforest_training_pipeline.py --eve <eve.json> --labels-csv <labels.csv> --artifacts-in artifacts_if --output-dir artifacts` |
| RF eval-only (another eve) | `python training/Randomforest_training_pipeline.py --eval-only --artifacts-in artifacts --eve <other_eve.json> --labels-csv <other_labels.csv> --output-dir artifacts` |
| Legacy hybrid training | `python training/hybrid_training_pipeline.py --cic <path> --suricata <path> --output-dir artifacts` |
| Inference entry | `python inference/runtime_scoring.py --artifacts <dir> --input <csv_or_eve> --output-dir inference_runtime_score` |
| Artifacts | `artifacts/isolation_forest.joblib`, `random_forest.joblib`, `scaler.joblib`, `config.joblib` |
| Runtime logs | `inference_runtime_score/decisions_log.jsonl`, `runtime_summary.json` |
| Context engine | `inference/context_engine.py` — per-IP state, optional escalation (MEDIUM→HIGH after N events in window) |

This document reflects the codebase as of the last review. If you find a mismatch, update the doc or flag it in the consistency section.

---

## Directory layout (Model2_development/)

```
Model2_development/
├── docs/
│   ├── INFRASTRUCTURE.md   # This file
│   ├── MANUAL.md
│   └── requirements.txt
├── artifacts/              # Default output for training (joblibs)
├── ingestion/              # unified_schema.py, cic_loader.py, suricata_loader.py
├── feature_engineering/    # basic_flow_features.py, alert_features.py (optional)
├── models/                 # isolation_forest_model.py, random_forest_model.py, risk_engine.py
├── training/               # Randomforest_training_pipeline.py, Isolationforest_training_pipeline.py, hybrid_training_pipeline.py (legacy), chunk_loader.py, stream_suricata_training.py (legacy)
├── inference/              # runtime_scoring.py, context_engine.py, firewall_adapter_stub.py
├── utils/                  # config.py, logging.py, serialization.py, streaming.py
├── infrastructure/         # architecture_overview.md, data_flow_diagram.md
├── Datasets/               # CICIDS, CICIoT, AttackHeavy (CICIDS_merged, CICIDS_merged_optimized)
└── scripts/                # analyze_cicids1_csv.py, merge_cicids_datasets.py, optimize_cicids_merged_for_rf.py
```

Default runtime output: `inference_runtime_score/` (decisions_log.jsonl, runtime_summary.json).
