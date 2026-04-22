# Behavior-Only Model Refactor — Evaluation Report

**Date:** 2025  
**Goal:** Make the ML pipeline purely behavior-based by removing `src_ip_encoded` and `dst_ip_encoded` from the model input. IP remains available only for context correlation, logging, and dashboard output.

---

## 1. Audit Summary

### 1.1 unified_schema.py

- **FEATURE_NAMES** (lines 24–43): List of 15 feature names in fixed order. First two entries are `src_ip_encoded` and `dst_ip_encoded`; they are produced by `_encode_ip(ip_str)` → `int(ipaddress.ip_address(...))`.
- **Normalization:** `normalize_cic_features` and `normalize_suricata_features` build a record dict that includes `src_ip_encoded` and `dst_ip_encoded` (CIC: lines 176–177; Suricata: 241–242). The returned DataFrame is `out[[c for c in FEATURE_NAMES] + [LABEL_KEY]]` (or equivalent), so the ML matrix is exactly the columns in FEATURE_NAMES.
- **build_feature_vector(record)** (line 279): Returns `[float(record.get(k, 0)) for k in FEATURE_NAMES]` — dimension = len(FEATURE_NAMES).
- **records_to_matrix(records)** (line 287): Builds (n, n_features) from build_feature_vector; n_features = len(FEATURE_NAMES).

**Where src_ip_encoded and dst_ip_encoded enter:** They are (1) in FEATURE_NAMES, (2) written into the record dict in both normalizers, (3) included in the DataFrame returned by normalizers, (4) included in the vector from build_feature_vector and thus in every matrix passed to the scaler and models.

### 1.2 Normalization functions

- **normalize_cic_features:** Reads Source IP / Dst IP from row, sets `rec["src_ip_encoded"] = _encode_ip(src_ip)`, `rec["dst_ip_encoded"] = _encode_ip(dst_ip)`. Returns DataFrame with columns FEATURE_NAMES + LABEL_KEY.
- **normalize_suricata_features:** Same for `ev.get("src_ip")`, `ev.get("dest_ip")`; rec has src_ip_encoded and dst_ip_encoded. Returns DataFrame with FEATURE_NAMES (+ LABEL_KEY/HAS_ALERT_KEY).
- Raw `src_ip` / `dest_ip` are not stored in the canonical record; they exist only in the raw event. Context engine and logging use `src_ip` from the **raw** event (e.g. `ev.get("src_ip")` in runtime_scoring), not from the normalized DataFrame.

### 1.3 FEATURE_NAMES usage (project code, excluding .venv)

| Location | Use |
|----------|-----|
| `ingestion/unified_schema.py` | Definition; used in normalizers’ return columns, build_feature_vector, records_to_matrix. |
| `inference/runtime_scoring.py` | `config.get("feature_names", FEATURE_NAMES)` → schema for enforce_schema; no hardcoded 15. |
| `training/stream_suricata_training.py` | `len(FEATURE_NAMES)`, `[c for c in FEATURE_NAMES if c in df.columns]`, config `"feature_names": FEATURE_NAMES`, dummy RF shape `(2, len(FEATURE_NAMES))`, `n_features = len(FEATURE_NAMES)`. |
| `training/hybrid_training_pipeline.py` | Imports FEATURE_NAMES; uses `records_to_matrix` (so dimension comes from FEATURE_NAMES); `config["feature_names"] = FEATURE_NAMES`; empty matrix `(0, len(FEATURE_NAMES))`. |

All usages are dimension-agnostic (len(FEATURE_NAMES) or schema from config). No literal 15.

### 1.4 Scaler expectations

- **Training:** `StandardScaler().fit_transform(X_all)` where X_all has shape (n, len(FEATURE_NAMES)). So scaler expects **15** features with current schema.
- **Runtime:** `scaler.transform(X)`; X comes from enforce_schema(df, schema) and schema = config["feature_names"]. So the scaler expects the same number of features as in the saved config.
- **After refactor:** New artifacts will be trained with 13-feature data; config will store the new feature_names (length 13). Scaler and models will expect 13. **Old artifacts (15 features) will be incompatible** with the new pipeline: normalization will produce 13 columns and scaler.transform will expect 15 → shape mismatch. Retraining is required; backward compatibility with 15-feature artifacts is not preserved.

### 1.5 runtime_scoring feature construction

- **JSON path:** `src_ips = [ev.get("src_ip") or "UNKNOWN" for ev in chunk_events]` (from raw events). `df = normalize_suricata_features(chunk_events)` → DataFrame. `feature_cols = [c for c in schema if c in df.columns]`; `df_schema = enforce_schema(df[feature_cols], schema)`; `X = df_schema.values`. So X has shape (chunk_size, len(schema)). Schema comes from config; no hardcoded count.
- **CSV path:** Same idea: src_ips from DataFrame column; normalize_cic_features → enforce_schema → X.
- **Conclusion:** Model input matrix is built from schema (config["feature_names"]). If we remove two features from FEATURE_NAMES and save new config with 13 names, runtime will use schema of length 13 and the DataFrame from the updated normalizers will have 13 columns. No change needed in runtime_scoring logic beyond ensuring we do not reintroduce IP columns; the normalizers will stop producing them once they are removed from FEATURE_NAMES and from the record dict.

### 1.6 Artifact dimensionality expectations

- **config.joblib:** Contains `feature_names` (list). Loaded at runtime and used as schema. Models and scaler are fitted on matrices with shape (n, len(feature_names)); they expect that dimension at predict/transform.
- **After refactor:** New training will write config with 13 feature names. New scaler and models will expect 13. Old artifacts (15) must not be used with the new code without a compatibility layer (not in scope). **Removing features breaks artifact compatibility** until models and scaler are retrained and saved with the new schema.

### 1.7 Context engine and IP

- Context engine receives `src_ips` (list of strings from raw events) and uses them for per-IP state and escalation. It does **not** read from the feature matrix. So removing IP from FEATURE_NAMES does not affect the context engine. No change required in context_engine.py.

---

## 2. What must be updated (Phase 2)

| Component | Change |
|-----------|--------|
| **unified_schema.py** | Remove `src_ip_encoded` and `dst_ip_encoded` from FEATURE_NAMES. In normalize_cic_features and normalize_suricata_features, do not add these keys to the record dict (so they are not in the DataFrame). Optionally keep _encode_ip for non-ML use or remove if unused. |
| **runtime_scoring.py** | No structural change. Schema from config; normalizers will return 13 columns; enforce_schema and X construction remain the same. src_ips continue to come from raw events. |
| **training (hybrid + stream_suricata)** | No structural change. They use FEATURE_NAMES and len(FEATURE_NAMES); after refactor they will produce and consume 13-feature matrices and save config with 13 names. |
| **Artifacts** | Retrain and save new IF, RF, scaler, config (manual). Old 15-feature artifacts are incompatible. |
| **Documentation** | Update INFRASTRUCTURE.md: new feature list (13), removal of IP-based features, separation of ML detection vs context tracking, note on dimensionality. |

---

## 3. Model input dimensionality

- **Current:** 15 (FEATURE_NAMES length).
- **After refactor:** 13 (same list without src_ip_encoded and dst_ip_encoded).
- **Runtime:** Always uses len(schema) from config; no hardcoded 15 or 13.

---

## 4. Artifact compatibility

- **Removing the two features makes existing artifacts incompatible.** The scaler and both models expect 15-dimensional input. After refactor, training and normalization produce 13-dimensional data. Loading old artifacts and passing 13-dim input will cause sklearn to raise (e.g. shape mismatch on transform/predict). Therefore **retraining and saving new artifacts is required** after the refactor; no code change can preserve compatibility with 15-feature artifacts.

---

## 5. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Accidentally leaving IP in the record | Remove the two keys from the record in both normalizers; remove from FEATURE_NAMES so build_feature_vector never asks for them. |
| Schema drift | Single source of truth: FEATURE_NAMES in unified_schema.py. Training and runtime use it or config derived from it. |
| Hardcoded feature count | Audit confirmed no literal 15; all use len(FEATURE_NAMES) or len(schema). |
| Context engine losing src_ip | src_ips are taken from raw events (ev.get("src_ip")) before normalization; unchanged. |

---

*Phase 1 complete (evaluation only; no code modified).*

**Phase 2 completed:** `unified_schema.py` updated (13 FEATURE_NAMES, no src_ip_encoded/dst_ip_encoded; normalizers no longer add IP to the ML record). Runtime and training use schema/len(FEATURE_NAMES) dynamically. `docs/INFRASTRUCTURE.md` updated with behavior-only feature list, dimensionality 13, and separation of ML vs context. Retraining and saving new artifacts must be done manually before using the pipeline with new artifacts.
