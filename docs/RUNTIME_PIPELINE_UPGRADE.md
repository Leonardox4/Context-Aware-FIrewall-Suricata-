# Runtime Pipeline After Upgrade

This document describes the runtime pipeline after the behavioral-feature, multiclass-RF, and extended-logging upgrades.

## Pipeline Overview

1. **Input**: Suricata `eve.json` (streamed by chunk or tail) or CSV (CIC).
2. **Feature extraction**: Canonical 24 features from `ingestion.unified_schema` (unchanged). Optional behavioral feature extractor updates sliding-window state per event (used for future extensions; state is maintained for JSON streams).
3. **Scoring**:
   - **Isolation Forest**: anomaly score → `anomaly_score` (0–1).
   - **Binary Random Forest**: P(attack) → `malicious_probability`.
   - **Multiclass Random Forest** (optional): predicted class → `attack_type`, max probability → `attack_confidence`. Classes: `benign`, `bot`, `backdoor`, `dos`, `ddos`, `bruteforce`, `scan`.
   - **RiskEngine**: combines anomaly, binary prob, and optional severity → `risk_score`; derives LOW/MEDIUM/HIGH.
4. **Context engine**: Unchanged. Can override ML decisions when behavioral thresholds (DDoS, fanout, source burst, port scan, etc.) are triggered.
5. **Logging**: Each event is written to `decisions_log.jsonl` with extended fields.
6. **Enforcement**: BLOCK actions are passed to the enforcement engine (stub/iptables/nftables) as before.

## New Modules

- **`inference/behavioral_features.py`**: Sliding-window feature extractor. Produces 9 behavioral features (e.g. `src_flow_count_60s`, `src_unique_dst_ports_60s`, `is_internal_src`, `tcp_flag_score`) with O(1) amortized updates and bounded memory (LRU eviction). Used to maintain state during JSON streaming; features can be logged or fed to a future model.

## Modified Files

- **`inference/runtime_scoring.py`**: Loads optional `rf_multiclass.joblib`; `score_chunk` returns `malicious_probability`, `attack_type`, `attack_confidence`, `anomaly_score`; `write_decisions` extended with new JSONL fields; behavioral extractor instantiated and updated for JSON streams.
- **`utils/serialization.py`**: `load_multiclass_rf(artifacts_dir)` and `MULTICLASS_ATTACK_TYPES`.
- **`models/random_forest_model.py`**: `multiclass_predict(model, X, class_names)` for attack_type and confidence.

## JSONL Decision Log Format

Each line is a JSON object with:

- `src_ip`, `dst_ip`
- `malicious_probability` (binary RF)
- `attack_type` (multiclass RF or `"benign"`/`"attack"` fallback)
- `attack_confidence` (multiclass max prob or 0)
- `anomaly_score` (IF 0–1)
- `context_signals`: list of context event types that apply to this flow (e.g. `source_flow_burst`)
- `decision`: `"block"` | `"alert"` | `"allow"`
- Legacy: `timestamp`, `dst_port`, `classification`, `risk_score`, `action`, `model_source`

## Multiclass RF Training

To use `attack_type` and `attack_confidence`, train a multiclass classifier on the same 24-feature schema and same train/test split as the binary RF, with a label column mapping to `MULTICLASS_ATTACK_TYPES` (e.g. `benign`, `bot`, `backdoor`, `dos`, `ddos`, `bruteforce`, `scan`). Save the model as `artifacts/rf_multiclass.joblib`. If the file is absent, the runtime uses `attack_type="benign"` and `attack_confidence=0` and continues to work.

## Compatibility

- **Streaming**: Chunked and tail modes unchanged; no full-file load.
- **Context engine**: Unchanged; still overrides decisions when thresholds are triggered.
- **Existing artifacts**: Binary RF, IF, scaler, and config are unchanged; multiclass is optional.
