# Model2_development — Hybrid ML IDS (IF + LGBM + optional RF)

Production-oriented stack: **Isolation Forest** (anomaly on scaled features) + **LGBM Stage 1** (binary attack on raw behavioral features) + **LGBM Stage 2** (optional multiclass `attack_type`). **Random Forest** remains supported for legacy bundles and scaler alignment.

---

## Quickstart

```bash
cd Model2_development
./setup.sh
source .venv/bin/activate

python -m training.Randomforest_training_pipeline \
  --eve /path/to/eve.jsonl \
  --labels-csv /path/to/labels.csv \
  --output-dir artifacts/Saved_models/RF \
  --rebuild-features
```

Full walkthrough, **Rust-first EVE** (`enhance_eve_jsonl` + `process_batch`), flags, inference, and ops live in **[MANUAL.md](MANUAL.md)**.

- **[docs/training.md](training.md)** — LGBM stages, default audits, HYBRID bundle assembly.
- **[docs/inference.md](inference.md)** — HYBRID runtime, `--artifacts-dir`, JSONL fields.

---

## Unified Inference (Detection + Classification + Enforcement)

Use the runtime directly (recommended) or the compatibility wrapper.

Recommended runtime command:

```bash
python -m inference.runtime_scoring \
  --artifacts artifacts/Saved_models/IF \
  --lgbm-artifacts artifacts/Saved_models/LGBM_STAGE01 \
  --input /var/log/suricata/master_eve.json \
  --output-dir logs
```

Compatibility wrapper command:

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

- **Stage 1**: Detects attack behavior and outputs attack probability.
- **Stage 2**: Classifies attack type for attack-likely flows.
- **Enforcement**: Blocks attacker source IP when decision is `BLOCK` and enforcement is enabled.

### Reset Rules

```bash
python scripts/reset_rules.py --backend iptables
```

---

## Architecture (short)

- **Unified behavioral features** — `ingestion/unified_behavioral_schema.py` (fixed column order; must match **`eve_extractor`** in `rust/eve_extractor`).
- **Default EVE path** — Raw Suricata JSONL → **Rust** builds a temporary **enhanced** flow-only JSONL with **`tcp_agg`** → **Rust** extracts features for RF join. Opt out with **`--legacy-raw-eve-stream`** or **`--force-python-extract`** / env vars (see MANUAL).
- **Risk score** — `w1 * anomaly + w2 * P(attack) + w3 * severity` (weights in `config.joblib`).

---

## Directory layout

```text
Model2_development/
  docs/                 # README (this file), MANUAL.md, requirements.txt
  ingestion/          # Behavioral schema, enhanced EVE builder, engines
  training/             # RF / IF pipelines
  inference/            # runtime_scoring
  rust/eve_extractor/   # PyO3: enhance_eve_jsonl, RustUnifiedExtractor, optional native join
  setup.sh              # venv + maturin build
```

---

## Dependencies

- Python: **`docs/requirements.txt`**
- Rust extension: built by **`./setup.sh`** or **`maturin develop --release`** in **`rust/eve_extractor`**.

---

## Further reading

- **[MANUAL.md](MANUAL.md)** — Training, inference, env flags, troubleshooting.
- **`rust/eve_extractor/README.md`** — Extension build notes (if present).
