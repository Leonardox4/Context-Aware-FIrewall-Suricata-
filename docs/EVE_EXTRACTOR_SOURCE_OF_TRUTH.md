# EVE extractor: source of truth and migration audit

**Canonical crate:** `Model2_development/rust/eve_extractor`  
**Legacy / frozen copy:** `Model2/rust/eve_extractor` is deprecated (see `Model2/rust/eve_extractor/DEPRECATED.md`). Do not build both into the same Python environment.

---

## Step 1 — Audit summary (Model2 vs Model2_development)

A recursive diff of **source trees** (excluding `target/`, `Cargo.lock`) shows **no file differences** between the two `eve_extractor` directories except **`README.md`** (wording). Runtime build artifacts under `target/` differ and must not be compared.

### A. Core capabilities (present in canonical tree)

| Capability | Status |
|------------|--------|
| `enhanced_eve_builder.rs` | Present |
| `flow_tcp_behavioral_engine.rs` (tcp_agg, 53 columns) | Present |
| `extractor.rs` with `N_FEATURES = 53` | Present |
| `join_pipeline.rs` (Parquet column count = `N_FEATURES`) | Present |
| PyO3 `enhance_eve_jsonl` | Present in `lib.rs` |
| CLI `eve_enhance` | Present (`bin/eve_enhance.rs`, `Cargo.toml` `[[bin]]`) |
| `serde_json` `preserve_order` | Present in `Cargo.toml` |
| `crate-type = ["cdylib", "rlib"]` | Present |

### B. PyO3 API surface (`lib.rs`)

- `RustUnifiedExtractor`
- `join_eve_labels_to_parquet`
- `enhance_eve_jsonl`
- Module constants: `N_FEATURES`, `FLOW_KEY_BUCKET_SEC`

### C. Schema alignment

- **Rust:** `extractor::N_FEATURES` and `flow_tcp_behavioral_engine::DEV_FEATURE_COUNT` = **53**
- **Python:** `ingestion/unified_behavioral_schema.py` — `N_UNIFIED_BEHAVIORAL_FEATURES` = **53** (length of `UNIFIED_BEHAVIORAL_FEATURE_NAMES`)
- **Guard:** `utils/rust_eve.assert_rust_extractor_matches_python_schema` and `scripts/verify_extractor_sync.py` (plus `hasattr(ee, "enhance_eve_jsonl")`)

---

## Step 2 — Files copied / synchronized

The following were brought in line with the 53-feature + tcp_agg design (historically sourced from the former “Model2 latest” tree, now mirrored in **Model2_development** only):

- `src/enhanced_eve_builder.rs`
- `src/flow_tcp_behavioral_engine.rs`
- `src/extractor.rs`
- `src/join_pipeline.rs`
- `src/lib.rs`
- `src/config.rs`
- `Cargo.toml`
- `bin/eve_enhance.rs`
- `README.md` (Model2_development-specific wording)

---

## Step 3 — Parity tests (Model2_development only)

| Test | Location | What it checks |
|------|----------|----------------|
| Enhanced EVE JSONL | `enhanced_eve_builder::tests::parity_python_rust_enhanced_eve_builder` | Python `build_tcp_map` + `emit_enhanced_flows` vs Rust `enhance_eve_paths`; `tcp_agg` per line |
| Feature vectors | `extractor` integration test (Python engine on enhanced JSONL vs Rust `FlowTcpBehavioralEngineRust`) | Per-feature numeric match (tol 1e-6), count = `DEV_FEATURE_COUNT` |

Run (with Rust toolchain and `python3` on PATH, from `Model2_development/rust/eve_extractor`):

```bash
cargo test
```

---

## Step 4 — Standalone runtime (no Model2 dependency)

All user-facing build hints in **Model2_development** use:

```text
cd Model2_development/rust/eve_extractor && maturin develop --release
```

Parity tests resolve the Python project root as **two parents above** `rust/eve_extractor` (works whether the folder is named `Model2_development` or a checkout that only contains this tree).

---

## Breaking changes

- **43 → 53 features:** Any artifact or Parquet built with an old extension must be **rebuilt** after installing the canonical `eve_extractor`.
- **Single extension in venv:** Installing `maturin develop` from `Model2` after `Model2_development` (or vice versa) overwrites the same `eve_extractor` module — use **only** `Model2_development`.

---

## Final verification checklist

1. `maturin develop --release` in `Model2_development/rust/eve_extractor`
2. `python -c "import eve_extractor as e; assert hasattr(e,'enhance_eve_jsonl'); assert e.N_FEATURES == 53"`
3. `python scripts/verify_extractor_sync.py` from `Model2_development/`
4. `cargo test` in `rust/eve_extractor`
5. RF training: `python -m training.Randomforest_training_pipeline ...` from `Model2_development/`
