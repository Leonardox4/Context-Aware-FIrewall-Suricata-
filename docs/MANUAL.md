# Model2_development — Training and operations manual

This document is ordered for **fast onboarding**. The **primary** detection stack is **Isolation Forest (anomaly) + LightGBM (supervised attack scoring)** at inference, with **dual-path preprocessing** (scaled features for IF, raw features for LGBM). **Random Forest** remains available as a **secondary** classifier in the same runtime bundle when trained and deployed with the hybrid artifacts layout.

---

## Quickstart

From the **`Model2_development/`** directory (this tree).

### 1) One-shot environment + Rust extension

```bash
cd Model2_development
chmod +x setup.sh
./setup.sh
```

What `setup.sh` does by default:

- **Deletes** existing **`Model2_development/.venv`** (if present) and creates a **fresh** venv — safe for a shipped copy of the tree. Use **`./setup.sh --keep-venv`** to reuse an existing venv.
- Installs **`docs/requirements.txt`**, **maturin**, **patchelf** (pip), verifies **LightGBM** and other core imports
- Installs **Rust stable** via **rustup** if `cargo` is missing; otherwise **`rustup update stable`**
- Runs **`maturin develop --release`** in **`rust/eve_extractor`** and verifies **`import eve_extractor`** (skip with **`SKIP_BUILD=1`**)
- Does **not** download datasets; does **not** train unless you pass **`--train-rf`** / **`--train-if`**

Host prerequisites: **python3**, **curl** (for rustup), and a **C compiler** (gcc/clang) for the native extension.

**Rust:** The `eve_extractor` crate depends on **Arrow/Parquet** and related crates that need **rustc ≥ 1.82** (often **stable** from [rustup](https://rustup.rs)). **Distro `apt install rustc` (e.g. 1.75) is too old.** Use rustup; `rust/eve_extractor/rust-toolchain.toml` pins **`channel = "stable"`** so the right toolchain is selected when building in that directory. After `rustup update stable`, re-run `./setup.sh`.

### 2) Train Isolation Forest (primary — benign / unlabeled EVE)

IF learns normal behavior on **non-alerted** flows. Output directory includes `isolation_forest.joblib`, `scaler.joblib`, `config.joblib`, and a minimal RF placeholder so `load_artifacts` works.

```bash
cd Model2_development
source .venv/bin/activate

python -m training.Isolationforest_training_pipeline \
  --dataset /path/to/benign_eve.jsonl \
  --output-dir artifacts/Saved_models/IF \
  --features-parquet artifacts/Saved_models/IF/if_training_features.parquet \
  --rebuild-features
```

Use **`--external-scaler`** + **`--reference-config`** only when you intentionally align IF scaling with a **separate** RF-trained scaler (optional integration path).

### 3) Train LightGBM (primary — two stages, raw Parquet)

**Stage 1 — detection:** binary **benign vs attack** on the RF-style cache (includes both classes). **Stage 2 — classification:** multiclass **`attack_type`** on **attack-only** rows (`binary_label == 1`). Both use **raw** features (no scaler).

```bash
pip install -r docs/requirements.txt   # includes lightgbm

python -m training.lgbm_stage01_training_pipeline \
  --dataset artifacts/Cached_Training_Dataset/rf_training_dataset.parquet \
  --output-dir artifacts/Saved_models/LGBM_STAGE01

python -m training.lgbm_stage02_training_pipeline \
  --dataset artifacts/Cached_Training_Dataset/Stage02_training_dataset.parquet \
  --output-dir artifacts/Saved_models/LGBM_STAGE02
```

Both stages run **default anti-overfitting audits** (`[AUDIT]` logs: GroupKFold, shuffle-label, weak model, noise, drop-top features, uniqueness, separability). Use **`--skip-audit`** only for quick iteration. Training silences noisy LightGBM messages (`verbose=-1`, `min_gain_to_split`, logger hook).

#### Assemble **HYBRID** bundle (single deploy dir)

```bash
python -m training.assemble_hybrid_bundle \
  --if-dir artifacts/Saved_models/IF \
  --stage01-dir artifacts/Saved_models/LGBM_STAGE01 \
  --stage02-dir artifacts/Saved_models/LGBM_STAGE02 \
  --out-dir artifacts/Saved_models/HYBRID
```

Produces `isolation_forest.joblib`, `scaler.joblib`, `IF_config.joblib`, `random_forest.joblib` (from IF dir), `lgbm_stage01_*`, `lgbm_stage02_*`. Loader: **`utils.hybrid_bundle.load_hybrid_models`**. LGBM configs must list **`feature_names` identical to `UNIFIED_BEHAVIORAL_FEATURE_NAMES`** (order-sensitive); mismatch raises at load.

### 4) Score live traffic (IF + LGBM — primary runtime)

**Recommended (HYBRID):** one directory with IF + LGBM Stage 1 + optional Stage 2:

```bash
python -m inference.runtime_scoring \
  --artifacts-dir artifacts/Saved_models/HYBRID \
  --input /path/to/eve.jsonl \
  --output-dir logs/score_run
```

**Legacy layout:** point **`--artifacts`** at the **IF training output** and pass **`--lgbm-artifacts`** or rely on sibling **`LGBM/`** / **`LGBM_STAGE01/`**.

```bash
python -m inference.runtime_scoring \
  --artifacts artifacts/Saved_models/IF \
  --lgbm-artifacts artifacts/Saved_models/LGBM_STAGE01 \
  --input /path/to/eve.jsonl \
  --output-dir logs/score_run
```

`--artifacts-dir` is an alias for **`--artifacts`**. Hybrid tiers (LGBM P(attack) + raw IF) merge with **RF** when present; without RF, **Stage 1** drives the same ML-first thresholds.

### 5) Random Forest (secondary — labeled EVE + CSV)

Use this when you want a **classic RF** in the artifact directory, a **labeled Parquet cache** for LightGBM, or parity with older hybrid bundles.

Use **module** invocation (required for **`--join-workers`** &gt; 1):

```bash
python -m training.Randomforest_training_pipeline \
  --eve /path/to/suricata_eve.jsonl \
  --labels-csv /path/to/labels.csv \
  --output-dir artifacts/Saved_models/RF \
  --rebuild-features
```

You can copy or merge **`scaler.joblib` / `config.joblib`** into your IF deploy dir if you standardize on one bundle layout.

### 6) Train IF + RF via `setup.sh` (optional)

```bash
./setup.sh --train-rf --train-if \
  --rf-eve /path/to/eve.jsonl \
  --rf-labels-csv /path/to/labels.csv \
  --if-benign-eve /path/to/benign_eve.jsonl \
  --out-base artifacts/Deployment_bundle
```

---

## Rust-first EVE pipeline (default)

End-to-end, **without** legacy raw-stream mode:

```text
raw Suricata JSONL (tcp + flow interleaved)
        │
        ▼  Rust: eve_extractor.enhance_eve_jsonl  (two-pass; tcp_agg by flow_id)
        │
temporary enhanced JSONL (flow rows only, each with tcp_agg)
        │
        ▼  Rust: eve_extractor RustUnifiedExtractor.process_batch
        │        (labeled join → Parquet cache; IF/RF streaming paths)
        │
behavioral feature Parquet (e.g. training_dataset.parquet)
```

- **TCP aggregation** and **enhanced JSONL** are **Rust by default** (`enhance_eve_jsonl`). Pure Python `build_tcp_map` / `emit_enhanced_flows` remain available for debugging (see below).
- **Feature extraction** on that stream is **Rust by default** (`process_batch`). **`--force-python-extract`** switches to the slow Python path.

### Legacy / debug switches

| Goal | How |
|------|-----|
| Single-pass raw EVE (tcp + flow interleaved; TCP row order affects behavior) | **`--legacy-raw-eve-stream`** (sets `EVE_LEGACY_RAW_STREAM=1`) |
| Python-only enhanced JSONL (reference / parity) | **`EVE_ENHANCED_PREPARE_BACKEND=python`** or **`EVE_USE_PYTHON_ENHANCED_PREPARE=1`** |
| Python-only feature extraction | **`--force-python-extract`** |
| Compare Rust vs Python join on a prefix | **`--validate-rust-vs-python`** (requires Rust; no `--force-python-extract`) |
| Entire join in native Rust (disk → Parquet, single call) | **`--native-rust-join`** (incompatible with `--join-workers`&gt;1 and `--max-events`) |

Rebuild the extension after changing Rust:

```bash
cd Model2_development/rust/eve_extractor && maturin develop --release
```

Optional standalone CLI (same as `enhance_eve_jsonl`):

```bash
cargo run --release --bin eve_enhance -- raw.jsonl enhanced_flows.jsonl
```

---

## Dependencies and layout

- **Python 3.8+**; see **`docs/requirements.txt`** (includes **lightgbm** for LGBM train + inference).
- **PyArrow** for Parquet caches (labeled join, IF feature cache).
- **eve_extractor** (PyO3): built from **`rust/eve_extractor`**; required for default training paths.

Run training and inference from **`Model2_development/`** so packages `ingestion`, `training`, `inference`, `utils` resolve (or set `PYTHONPATH`).

---

## Training (detail)

### Isolation Forest (`training/Isolationforest_training_pipeline.py`) — primary anomaly model

- Stream **flow** events; training rows are **non-alerted** flows (`flow.alerted` not true) by default.
- **Output:** `isolation_forest.joblib`, `scaler.joblib`, `config.joblib`, plus placeholder RF for serialization compatibility.
- **`--external-scaler`** — optional: align IF with another bundle’s scaler (e.g. RF-trained).

### LightGBM — primary supervised classifiers (Stage 1 + Stage 2)

Training uses **unscaled** numeric features from Parquet. Pipelines are **independent** of RF training code (no imports from `Randomforest_training_pipeline`).

#### Stage 1 — Detection (`training/lgbm_stage01_training_pipeline.py`)

- **Task:** Binary classification — **benign vs attack** (column **`binary_label`**). The dataset must include **both** classes.
- **Input:** Default **`artifacts/Cached_Training_Dataset/rf_training_dataset.parquet`** (same layout as the RF labeled join cache).
- **Dropped from `X`:** `binary_label`, `attack_subclass`, `attack_type` (if present), `identity_key`, `flow_key`, plus **`--drop-features`**.
- **Output:** **`artifacts/Saved_models/LGBM_STAGE01/lgbm_stage01_model.joblib`**, **`config.joblib`** with `feature_names`, `label_column`, `model_type: lgbm_stage01_binary`. **No scaler.**

```bash
python -m training.lgbm_stage01_training_pipeline \
  --dataset artifacts/Cached_Training_Dataset/rf_training_dataset.parquet \
  --output-dir artifacts/Saved_models/LGBM_STAGE01
```

#### Stage 2 — Classification (`training/lgbm_stage02_training_pipeline.py`)

- **Task:** Multiclass **`attack_type`** on **attack flows only** — rows are filtered with **`binary_label == 1`** (no benign rows). Expects exactly **six** distinct attack classes after filtering.
- **Input:** Default **`artifacts/Cached_Training_Dataset/Stage02_training_dataset.parquet`**. If **`attack_type`** is missing but **`attack_subclass`** exists, the latter is used as the label for training.
- **Dropped from `X`:** `attack_type`, `attack_subclass`, `binary_label`, `identity_key`, `flow_key`, plus **`--drop-features`**.
- **Holdout:** **`GroupShuffleSplit`** on **`identity_key`** (else **`flow_key`**, else **`src_ip`**, else unique row index with an audit warning) so train/test **group overlap is 0**. This split is **not class-stratified**; logs include **normalized train vs test class proportions** and **max |Δ| per class**. Optional **`--group-cv-folds K`** runs **`GroupKFold`** (smaller LGBM) for fold-wise accuracy. Logs label–feature correlations, duplicates, temporal benchmark, stress tests (shuffle-label, drop-top-5, σ=0.1 noise, weak + **ultra-weak** LGBM, **σ=0.5** noise on train+test, class collapse), optional **`--write-audit-plots`** (matplotlib → **`stage02_audit/`**), optional **`--external-test-parquet`**, and a closing **generalization verdict** (also stored in **`config.joblib`**). Use **`--skip-stress-audit`** for a faster run; **`--strict-audit`** exits with code 2 on hard failures (e.g. group overlap, shuffle test).
- **Output:** **`artifacts/Saved_models/LGBM_STAGE02/lgbm_stage02_model.joblib`**, **`config.joblib`** with `feature_names`, `label_column`, `classes`, `model_type: lgbm_stage02_multiclass`. **No scaler.** (Inference wiring for Stage 2 is separate from the IF + Stage-1 LGBM hybrid path.)

```bash
python -m training.lgbm_stage02_training_pipeline \
  --dataset artifacts/Cached_Training_Dataset/Stage02_training_dataset.parquet \
  --output-dir artifacts/Saved_models/LGBM_STAGE02
```

### Random Forest (`training/Randomforest_training_pipeline.py`) — secondary

- **Input:** Suricata JSONL + ground-truth CSV (`binary_label`, flow identifiers).
- **Output:** `random_forest.joblib`, `scaler.joblib`, `config.joblib`, optional **`training_dataset.parquet`** (feeds LightGBM training and eval).
- **Cache:** If `training_dataset.parquet` exists and **`--rebuild-features`** is omitted, EVE is not rescanned.

**Useful flags:** **`--rebuild-features`**, **`--join-workers N`**, **`--join-overlap-mb`**, **`--cv-folds K`**, **`--dedupe-identity-key`**, **`--split-by-identity-group`**.

### Progress

Long JSONL reads log **time-based** progress (~every 5s): byte %, MiB/s, and postfix fields (`csv_cov`, `matched_rows`, etc.).

---

## Inference

**Primary path:** **Isolation Forest + LightGBM** with **separate preprocessing**:

- **IF** (and any **RF** in the same bundle) use **`scaler.transform(X)`** on the projected feature matrix.
- **LightGBM (Stage 1 / legacy bundle)** uses **raw** unified columns ordered by the LGBM **`config.joblib` → `feature_names`** — **never scaled**. The loader accepts **`lgbm_model.joblib`** (legacy **`LGBM/`**) or **`lgbm_stage01_model.joblib`** (**`LGBM_STAGE01/`**).

```bash
python -m inference.runtime_scoring \
  --artifacts artifacts/Saved_models/IF \
  --lgbm-artifacts artifacts/Saved_models/LGBM_STAGE01 \
  --input /path/to/eve.jsonl \
  --output-dir inference_runtime_score
```

If **`--lgbm-artifacts`** is omitted, the runtime tries **`<parent-of--artifacts>/LGBM`** then **`LGBM_STAGE01`**, using the first directory that contains a valid model + config pair.

**Packaged LGBM fallback (`models/bundled/`):** If no trained bundle is found, the loader uses the checked-in **`models/bundled/lgbm_stage01_model.joblib`** + **`config.joblib`** (synthetic training on the unified schema only — **not** a production detector). An **[AUDIT]** log line is emitted when this path is used. Regenerate after schema changes: `python scripts/generate_packaged_lgbm_fallback.py`. Use **`--no-packaged-lgbm-fallback`** to require a real deploy bundle and leave LGBM disabled when it is missing.

- **Input:** `.jsonl` (Suricata) or CSV (CIC-style), auto-detected.
- **Output:** `decisions_log.jsonl`, `runtime_summary.json`; chunked, bounded RAM.
- **Hybrid merge:** When **both** IF and LGBM load, hybrid labels (**ATTACK** / **ANOMALY** / **BENIGN**) map to HIGH/MEDIUM/LOW and merge with the **RF tier** by **stricter** severity (`--hybrid-lgbm-attack`, `--hybrid-if-anomaly`). Use **`--no-hybrid-if-lgbm`** to score LGBM for logs only without merging tiers.
- **Logs:** `lgbm_probability`, `hybrid_label`, `if_decision_function_raw`, `model_source` (e.g. `IF+RF+LGBM` or `IF+RF+LGBM(packaged-fallback)` when the bundled fallback is active).
- **Requires:** `lightgbm` installed for LGBM joblibs. **IF without scaler** in the main bundle errors at load.

### Unified Inference (Detection + Classification + Enforcement)

Compatibility wrapper:

```bash
python run_inference.py \
  --stage1-model artifacts/Saved_models/LGBM_STAGE01/lgbm_stage01_model.joblib \
  --stage2-model artifacts/Saved_models/LGBM_STAGE02/lgbm_stage02_model.joblib \
  --threshold 0.7 \
  --enforce \
  --firewall-backend iptables \
  --block-duration 300 \
  --input /var/log/suricata/master_eve.json \
  --output-dir logs
```

- **Stage 1** performs attack detection.
- **Stage 2** performs attack classification when enabled and available.
- **Enforcement** applies firewall blocking for attack decisions when `--enforce` is set.

### Reset Rules

```bash
python scripts/reset_rules.py --backend iptables
```

### Random Forest at runtime (secondary)

When the **`--artifacts`** directory contains a trained **`random_forest.joblib`** (not only the IF-training placeholder), **RF `predict_proba`** still runs on **scaled** features and participates in **ML-first** thresholds and risk blend. For **IF+LGBM-first** deployments, the IF output directory from `Isolationforest_training_pipeline` is enough; RF remains optional depth in the same loader.

---

## Evaluation (no training)

**RF-centric eval** (secondary — labeled holdout):

```bash
python -m training.Randomforest_training_pipeline --eval-only \
  --artifacts-in artifacts/Saved_models/RF \
  --eve /path/to/test_eve.jsonl \
  --labels-csv /path/to/test_labels.csv \
  --output-dir artifacts/eval_run
```

Full IF + RF + risk report (legacy tooling):

```bash
python -m training.Randomforest_training_pipeline --eval-only --full-eval \
  --artifacts-in artifacts/Deployment_bundle \
  --features-parquet artifacts/eval_run/eval_dataset.parquet \
  --output-dir artifacts/eval_run
```

---

## Operational reference

### Validate a deploy bundle

```bash
python -m training.validate_hybrid_artifacts --artifacts path/to/deploy_bundle
```

### Hybrid scaler audit

```bash
python -m training.audit_scaler_hybrid \
  --if-artifacts artifacts/Saved_models/IF \
  --rf-artifacts artifacts/Saved_models/RF \
  --parquet path/to/features.parquet
```

### Chunk sizes

- Default **50_000** flow events per chunk is a good balance for multi-GB EVE.
- Larger chunks improve throughput if RAM allows; smaller chunks reduce peak memory.

### Threading

IF / LightGBM / RF training may use **all cores** where the library allows (`n_jobs=-1`). At runtime, LGBM and RF may use multiple cores; IF `decision_function` is often single-threaded. See sklearn/joblib docs; use **`JOBLIB_N_JOBS=1`** to cap threads if needed.

---

## Quick command table

| Task | Command |
|------|---------|
| Bootstrap venv + build Rust | `./setup.sh` |
| Train IF (primary) | `python -m training.Isolationforest_training_pipeline --dataset … --output-dir artifacts/Saved_models/IF` |
| Train LGBM Stage 1 (detection) | `python -m training.lgbm_stage01_training_pipeline --dataset …/rf_training_dataset.parquet --output-dir artifacts/Saved_models/LGBM_STAGE01` |
| Train LGBM Stage 2 (attack_type) | `python -m training.lgbm_stage02_training_pipeline --dataset …/Stage02_training_dataset.parquet --output-dir artifacts/Saved_models/LGBM_STAGE02` |
| Runtime IF + LGBM Stage 1 (primary) | `python -m inference.runtime_scoring --artifacts artifacts/Saved_models/IF --lgbm-artifacts artifacts/Saved_models/LGBM_STAGE01 --input …` |
| Train RF (secondary — Parquet + optional classifier) | `python -m training.Randomforest_training_pipeline --eve … --labels-csv … --output-dir …` |
| Train IF with RF scaler (optional alignment) | Add `--external-scaler …/RF/scaler.joblib --reference-config …/RF/config.joblib` to IF training |
| Eval RF / full hybrid eval | `python -m training.Randomforest_training_pipeline --eval-only …` |
| Validate bundle | `python -m training.validate_hybrid_artifacts --artifacts …` |

---

## Troubleshooting

- **`Rust extractor not available`** — Run `./setup.sh` or `cd rust/eve_extractor && maturin develop --release` using the **same venv** as training.
- **`ModuleNotFoundError: sklearn` / `pyarrow` / `lightgbm`** — `source .venv/bin/activate`; `pip install -r docs/requirements.txt`.
- **`--join-workers` errors** — Use `python -m training.Randomforest_training_pipeline` from `Model2_development/`, not `python training/Randomforest_training_pipeline.py`.
- **Parity / debugging** — `EVE_ENHANCED_PREPARE_BACKEND=python` or `--force-python-extract` temporarily; use `--validate-rust-vs-python` to compare backends.
