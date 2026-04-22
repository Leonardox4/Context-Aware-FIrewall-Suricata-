# eve_extractor (Rust + PyO3)

Accelerates **Suricata EVE JSONL** handling for training:

1. **`enhance_eve_jsonl(in_path, out_path)`** — two-pass **TCP aggregation** by `flow_id`, writes **flow-only** JSONL with **`tcp_agg`** (default preprocess before RF; matches `ingestion/enhanced_eve_builder.py`).
2. **`RustUnifiedExtractor`** — unified behavioral **feature** extraction on that stream (`process_batch` hot path in RF join).

## Prerequisites

- **[rustup](https://rustup.rs/)** + **stable** toolchain (**rustc ≥ 1.82**). Crates such as `indexmap` 2.13 and **Arrow 53** do not build on older compilers (e.g. Debian `rustc` 1.75 from `apt`).
- This directory includes **`rust-toolchain.toml`** (`channel = "stable"`) so `cargo` / `maturin` use a current compiler when run here.
- Python 3.9+
- [`maturin`](https://www.maturin.rs/) — `pip install maturin`

## Build and install into your venv

From **`Model2_development/rust/eve_extractor`**:

```bash
maturin develop --release
```

Or run **`./setup.sh`** from **`Model2_development/`**.

**maturin / rpath:** If you see `Failed to set rpath ... patchelf`, the wheel still installs; for automatic `rpath` patching install **`patchelf`** on the system (`apt install patchelf` / `dnf install patchelf`) or `pip install patchelf` / `pip install 'maturin[patchelf]'`.

Verify:

```python
import eve_extractor as ee
assert hasattr(ee, "enhance_eve_jsonl")
e = ee.RustUnifiedExtractor(if_benign_only=False)
```

## Optional CLI

```bash
cargo run --release --bin eve_enhance -- raw.jsonl enhanced_flows.jsonl
```

## Python escape hatches

| Goal | Flag / env |
|------|------------|
| Python enhanced JSONL prep | `EVE_ENHANCED_PREPARE_BACKEND=python` |
| Python feature extraction | `--force-python-extract` (RF pipeline) |
| Raw interleaved EVE (no `tcp_agg` pass) | `--legacy-raw-eve-stream` |

## Semantics

- **Feature count and order** — must match `ingestion/unified_behavioral_schema.py` / `eve_extractor.N_FEATURES`.
- **Enhanced EVE** — deterministic; duplicate non-empty `flow_id` on second **flow** line is skipped (same as Python builder).
- **Netflow overrides** — not implemented in Rust; use **`--force-python-extract`** if you rely on netflow enrichment.

## API (summary)

- `enhance_eve_jsonl(input_path, output_path) -> (n_flow_lines, n_duplicate_flow_id_skipped)`
- `join_eve_labels_to_parquet(...)` — optional full native disk→Parquet join (`--native-rust-join` in RF CLI)
- `RustUnifiedExtractor` — `process_batch`, `process_line`, `process_line_detailed`
