# Training — IF + LGBM Stage 1 + Stage 2

## Pipeline overview

```text
Isolation Forest (benign EVE)     → anomaly
        +
LGBM Stage 1 (binary, Parquet)    → P(attack) on raw 39 features
        +
LGBM Stage 2 (multiclass, attacks) → attack_type on raw features
```

Random Forest (EVE + labels) remains supported for legacy bundles and scaler alignment; the **HYBRID** deployment layout is IF-centric with LGBM stages in one directory.

---

## Stage 1 — Binary LGBM

- **Module:** `python -m training.lgbm_stage01_training_pipeline`
- **Data:** `artifacts/Cached_Training_Dataset/rf_training_dataset.parquet` (default)
- **Split:** `GroupShuffleSplit` on `identity_key` → `flow_key` → `src_ip`
- **Output:** `artifacts/Saved_models/LGBM_STAGE01/` (`lgbm_stage01_model.joblib`, `config.joblib`)

### Default audits (auto, `[AUDIT]` logs)

- GroupKFold (5 folds), shuffle-label test, weak LGBM, noise σ=0.1 and σ=0.5, drop top features, uniqueness scan, separability stats
- Disable with `--skip-audit` (faster iteration only)

### Config fields

`feature_names`, `label_column`, `model_type`, `num_classes` (2), `training_params` (includes `verbose=-1`, `min_gain_to_split`), `audit_metrics`, split metadata.

---

## Stage 2 — Multiclass LGBM

- **Module:** `python -m training.lgbm_stage02_training_pipeline`
- **Data:** `Stage02_training_dataset.parquet`; rows with `binary_label == 1` only; 6 classes
- **Same audit suite** as Stage 1 (multiclass variant)
- **Output:** `artifacts/Saved_models/LGBM_STAGE02/`

### Why 100% accuracy is suspicious

Perfect holdout accuracy often means **group leakage** (same flow/session in train and test), **label proxies in features**, or a **trivially separable** corpus. Audits (shuffle near chance, weak model drop, noise sensitivity) help flag this; **external Parquet** (`--external-test-parquet`) tests domain shift.

---

## HYBRID bundle assembly

After training IF, Stage 1, and optionally Stage 2:

```bash
python -m training.assemble_hybrid_bundle \
  --if-dir artifacts/Saved_models/IF \
  --stage01-dir artifacts/Saved_models/LGBM_STAGE01 \
  --stage02-dir artifacts/Saved_models/LGBM_STAGE02 \
  --out-dir artifacts/Saved_models/HYBRID
```

**Layout:**

| File | Role |
|------|------|
| `isolation_forest.joblib`, `scaler.joblib`, `IF_config.joblib` | IF + scaler + IF feature config |
| `random_forest.joblib` | Copied from IF dir (placeholder OK) |
| `lgbm_stage01_model.joblib`, `lgbm_stage01_config.joblib` | Detection |
| `lgbm_stage02_model.joblib`, `lgbm_stage02_config.joblib` | Optional classification |

**Loader:** `utils.hybrid_bundle.load_hybrid_models(path)`.

At inference, **`validate_lgbm_feature_schema`** requires Stage 1 `feature_names` to match **`UNIFIED_BEHAVIORAL_FEATURE_NAMES`** exactly (order + spelling); Stage 2 must use the same list.

---

## LightGBM log hygiene

Training uses `training.lgbm_audit_utils.silence_lightgbm()` (warnings + `lgb.register_logger`). Models set `verbose=-1` and `min_gain_to_split=1e-3`.

See also **[MANUAL.md](MANUAL.md)** for RF/IF and Rust EVE paths.
