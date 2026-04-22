# Feasibility: Upgrading ML Feature Vector from 24 to 33 Features

## 1. Current System (24 features)

### Where the 24 features are defined

- **Single source of truth:** `ingestion/unified_schema.py` → `FEATURE_NAMES` (list of 24 strings, fixed order).
- **Used by:** training (RF and IF), inference schema, scaler, and all models.

### How the feature vector is constructed

- **Suricata:** `normalize_suricata_features(events)` → DataFrame with columns exactly `FEATURE_NAMES` (plus optional `label` / `has_alert`). No behavioral state.
- **CIC/CSV:** `normalize_cic_features(df)` → same 24 columns.
- **Runtime:** `enforce_schema(df[feature_cols], schema)` aligns to `schema` (from `config["feature_names"]` or `FEATURE_NAMES`). `X = df_schema.values` → shape `(n, 24)`.

### Where models expect input shape

| Component | Expectation |
|-----------|-------------|
| **Scaler** | Fit/transform on `(n, 24)`. Saved in `artifacts/scaler.joblib`. |
| **Binary RF** | Trained on scaled `(n, 24)`. `predict_proba(X)` expects 24 features. |
| **Multiclass RF** | Optional; if present, same 24-feature input. |
| **Isolation Forest** | Trained on scaled `(n, 24)`. `decision_function(X)` expects 24 features. |
| **Config** | `config["feature_names"]` = list of 24 names; runtime uses it as `schema`. |

So: **all current artifacts (scaler, binary RF, IF, config) are tied to 24 features.** Using 33 at inference without retraining would break (scaler/model shape mismatch).

---

## 2. Is Option B (33 features) feasible?

**Yes, it is feasible**, provided:

1. **Training and inference both use the same deterministic 33-feature schema** (24 canonical + 9 behavioral, fixed order).
2. **All models and the scaler are retrained/re-fitted on 33 features** and new artifacts are deployed.
3. **Behavioral features are computed in training** by replaying a stateful extractor over the same (or equivalent) event stream so train and inference see the same schema and semantics.

No change to the context engine is required; it does not consume the ML feature vector.

---

## 3. Required changes by component

### 3.1 Feature extraction and schema

| File | Change |
|------|--------|
| **`ingestion/unified_schema.py`** | Define extended schema, e.g. `FEATURE_NAMES_EXTENDED = FEATURE_NAMES + BEHAVIORAL_FEATURE_NAMES` (import behavioral names from `inference.behavioral_features` or a shared constants module to avoid circular imports). Alternatively define `BEHAVIORAL_FEATURE_NAMES` in `unified_schema` and keep a single 33-name list. Document that order is fixed for training and inference. |

- **Single source of truth:** Either `unified_schema` holds both 24 and 33 (or 24 + 9) so training and inference import one canonical list.

### 3.2 Behavioral feature extractor

| File | Change |
|------|--------|
| **`inference/behavioral_features.py`** | Already implements the 9 features and `BEHAVIORAL_FEATURE_NAMES`. Ensure `update_batch(events)` returns a list of dicts that can be converted to a matrix in the same order as `BEHAVIORAL_FEATURE_NAMES`. No API change required; runtime and training will call the same extractor. |

- Behavioral updates are already O(1) amortized and bounded (LRU); no change needed for feasibility.

### 3.3 Runtime scoring

| File | Change |
|------|--------|
| **`inference/runtime_scoring.py`** | (1) Schema: use 33-feature schema when loading artifacts (e.g. `schema = config.get("feature_names", FEATURE_NAMES_EXTENDED)`). (2) Build X: for each chunk, get 24 columns from `normalize_suricata_features`, get 9 from `behavioral_extractor.update_batch(chunk_events)`, concatenate in canonical order (24 then 9) so that `X = np.hstack([X_24, X_9])` has shape `(n, 33)`. (3) Always run the behavioral extractor for JSON flow so state is consistent. (4) CSV path: behavioral features are not available unless we have per-row state; either require 33-column CSV or fill 9 columns with 0 and document that CSV mode runs with zeroed behavioral features. |

### 3.4 Model loading

| File | Change |
|------|--------|
| **`utils/serialization.py`** | No change. `load_artifacts` and `load_multiclass_rf` already load whatever is saved. New artifacts will contain `config["feature_names"]` of length 33 and models trained on 33 features. |
| **`inference/runtime_scoring.py`** | `load_models` already uses `config.get("feature_names", FEATURE_NAMES)`. When config has 33 names, `schema` will have 33 and `enforce_schema` will expect 33 columns. |

- Backward compatibility: if you need to support both 24- and 33-feature artifacts, gate on `len(schema) == 24` vs `33` and build X accordingly (24-only path vs 24+9 path). Otherwise, deploy only 33-feature artifacts after retraining.

### 3.5 Training pipeline (RF)

| File | Change |
|------|--------|
| **`training/Randomforest_training_pipeline.py`** | (1) Use 33-feature schema: e.g. `FEATURE_NAMES_EXTENDED` or `FEATURE_NAMES + BEHAVIORAL_FEATURE_NAMES` for Parquet columns and for `X`. (2) In `_join_flows_with_labels`: when building each chunk, run the same `BehavioralFeatureExtractor` over the chunk events (in stream order), get 9 columns per row, and append to the 24 from `normalize_suricata_features` so each written row has 33 columns. (3) Parquet schema: include the 9 behavioral column names. (4) `X = feats_df[FEATURE_NAMES_EXTENDED].values` (or equivalent). (5) Save `config["feature_names"] = FEATURE_NAMES_EXTENDED` so runtime and scaler see 33. |

- Training data must be built in stream order so that the behavioral state (e.g. counts in 60s/120s windows) is consistent with inference (same event order and same extractor).

### 3.6 Training pipeline (IF)

| File | Change |
|------|--------|
| **`training/stream_suricata_training.py`** | (1) Use 33-feature schema: `n_features = len(FEATURE_NAMES_EXTENDED)`. (2) For each chunk: normalize to 24 columns, run `BehavioralFeatureExtractor.update_batch(chunk_events)` to get 9 columns per row, concatenate to form 33-feature matrix, then push into the training buffer. (3) Fit scaler and IF on (n, 33). (4) Save config with `feature_names = FEATURE_NAMES_EXTENDED`. (5) Dummy RF in artifacts must be fit on 33-feature dummy data. |

| File | Change |
|------|--------|
| **`training/Isolationforest_training_pipeline.py`** | No logic change; it delegates to `stream_suricata_training`. |

### 3.7 Dataset builders

| Component | Change |
|-----------|--------|
| **`build_ground_truth.py`** | No change. It produces attack/benign labels and flow keys, not feature vectors. |
| **`merge_ground_truth_table.py`** | No change. It produces `rf_labels.csv`, not features. |
| **`build_balanced_eve.py`** | No change. It filters eve by flow_key. |
| **RF training dataset** | Built by `_join_flows_with_labels` in the RF pipeline; that function must be extended to output 33 columns (24 + 9) as above. |

---

## 4. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| **Model incompatibility** | Existing 24-feature artifacts (scaler, RF, IF) will not work with 33-feature input. Either retrain everything and deploy only 33-feature artifacts, or add a version/schema-length check and support both 24 and 33 (two code paths for building X). |
| **Feature ordering mismatch** | Use a single ordered list (e.g. `FEATURE_NAMES_EXTENDED = FEATURE_NAMES + BEHAVIORAL_FEATURE_NAMES`) everywhere: Parquet columns, training `X`, inference `X`, config. Never reorder or subset by different names. |
| **Training vs inference state divergence** | Use the same `BehavioralFeatureExtractor` and same event order. In training, stream eve once in order and append behavioral features per chunk; do not shuffle before adding behavioral columns. |
| **Increased latency** | Behavioral extractor is already O(1) per event and bounded memory. Extra work per chunk: one pass over events for `update_batch` and one `np.hstack`. Likely negligible compared to model inference; profile if needed. |
| **Memory growth** | Sliding windows are already bounded (LRU, max entries per key). No change required for 33-feature feasibility. |
| **CSV / CIC path** | No per-row state for behavioral features unless you simulate it. Options: (a) require 33 columns in CSV and read them, or (b) fill the 9 behavioral columns with 0 and document that CSV mode does not use behavioral features. |

---

## 5. Retraining steps (for 33-feature deployment)

1. **Define 33-feature schema** in one place (e.g. `unified_schema.FEATURE_NAMES_EXTENDED`).
2. **Retrain IF:** Run `stream_suricata_training` (or IF pipeline) with 33-feature construction (24 + behavioral extractor over benign stream). Save new IF + scaler + config (and dummy RF) under a new artifacts dir.
3. **Retrain binary RF:** Run RF training with `_join_flows_with_labels` producing 33 columns (24 + 9 from behavioral extractor over eve stream). Use the same scaler/IF artifacts (33-feature) or refit scaler on the 33-feature training set. Save RF + scaler + config (+ IF) as 33-feature artifacts.
4. **Optional:** Train multiclass RF on the same 33-feature dataset; save as `rf_multiclass.joblib`.
5. **Deploy:** Point runtime at the new artifacts directory. Ensure runtime builds X with 33 columns (24 from normalization + 9 from behavioral extractor) in the same order as `config["feature_names"]`.

---

## 6. Summary

- **Feasible:** Yes. Option B (33 features) is feasible with a single deterministic schema, stateful behavioral features in both training and inference, and full retrain + new artifacts.
- **Files to change:**  
  - `ingestion/unified_schema.py` (define extended 33-name schema),  
  - `inference/runtime_scoring.py` (build 33-column X for JSON; handle CSV),  
  - `training/Randomforest_training_pipeline.py` (build and use 33-column dataset and schema),  
  - `training/stream_suricata_training.py` (33-feature matrix, scaler, IF, config).  
  - `inference/behavioral_features.py` can stay as-is (already provides the 9 features).
- **Retraining:** Required for IF, binary RF, scaler, and optionally multiclass RF; all on 33 features. Old 24-feature artifacts will not work with the 33-feature path unless you add explicit backward compatibility (24-only path).
- **Performance:** Expected to remain acceptable (O(1) behavioral updates, bounded memory, one extra concatenation per chunk). Context engine unchanged.
