# Inference — HYBRID runtime (IF + LGBM Stage 1 + Stage 2)

## Command

From `Model2_development/` with venv active:

```bash
python -m inference.runtime_scoring \
  --artifacts artifacts/Saved_models/HYBRID \
  --input /path/to/eve.jsonl \
  --output-dir logs/score_run
```

`--artifacts-dir` is an alias for `--artifacts`.

---

## Decision flow

1. **Features** — Unified 39-column behavioral matrix (raw); same column order as training (`UNIFIED_BEHAVIORAL_FEATURE_NAMES`).
2. **IF** — `scaler.transform(X)` → `IsolationForest.decision_function` → sigmoid anomaly score.
3. **LGBM Stage 1** — `predict_proba` on **raw** columns selected by `lgbm_stage01_config["feature_names"]` (no scaling).
4. **LGBM Stage 2** — If present, multiclass `predict` / `predict_proba` on raw features; class names from `config["classes"]`.
5. **Tiers** — If `random_forest.joblib` is missing in the bundle, **Stage 1 `P(attack)`** drives the same ML-first thresholds as RF `P(attack)` would. Hybrid IF+LGBM tier merge unchanged when IF + Stage 1 load.

---

## Schema safety

- **HYBRID load** calls `validate_lgbm_feature_schema`: Stage 1 (and Stage 2 if present) must list exactly **39** features matching the unified schema; Stage 1 and Stage 2 `feature_names` must match each other.
- **Mismatch** → load raises `ValueError` before scoring.

---

## JSONL output (`decisions.jsonl`)

Legacy fields are preserved. **Primary IDS fields** (HYBRID / LGBM-centric):

| Field | Meaning |
|-------|---------|
| `is_attack` | `lgbm_probability >= ml_alert_threshold` (Stage 1 binary) |
| `attack_probability` | LGBM Stage 1 P(attack) |
| `anomaly_score` | IF-derived score (sigmoid-normalized in ML-first mode) |
| `attack_type` | **LGBM Stage 2** class when loaded and confident; else **multiclass RF** family |
| `attack_type_confidence` | Max `predict_proba` for the resolved `attack_type` |
| `multiclass_rf_attack_type` / `multiclass_rf_confidence` | RF multiclass path (always filled when RF multiclass exists) |
| `lgbm_probability` | Same as Stage 1 P(attack) (dashboards) |
| `if_decision_function_raw` | Raw IF `decision_function` (lower = more anomalous) |

`model_source` is like `IF+RF+LGBM+S2` when Stage 2 is loaded (`+S2` suffix).

---

## Optional paths

- **Legacy bundle:** `--artifacts` = IF or RF directory; `--lgbm-artifacts` sibling `LGBM/` or `LGBM_STAGE01/` as before.
- **Packaged LGBM fallback:** `models/bundled/` when trained Stage 1 missing (`--no-packaged-lgbm-fallback` to disable).

See **[MANUAL.md](MANUAL.md)** for context engine, enforcement, and thresholds.
