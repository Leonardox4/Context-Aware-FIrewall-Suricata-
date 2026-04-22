//! Compile-time feature flags for `eve_extractor`.
//!
//! # After any edit here
//!
//! Rebuild the Python extension (same venv you use for training):
//!
//! ```text
//! cd Model2_development/rust/eve_extractor && maturin develop --release
//! ```
//!
//! ---
//!
//! ## ACTIVE PRESET (edit the `bool` lines below only)
//!
//! **PERFORMANCE** is enabled below: faster context + dst-port entropy (incremental), typed JSON
//! parse with automatic fallback to full parse if typed deserialize fails, **no** dual legacy scan.
//! If anything looks wrong, switch to **SAFE** (see comment block at bottom of this file).
//!
//! ## Preset reference
//!
//! | Preset       | `OUTPUT` | `WINDOWS` | `STRICT` | Effect |
//! |--------------|----------|-----------|----------|--------|
//! | SAFE         | `false`  | `false`   | `false`  | Legacy Rust path only (slowest, max parity with older builds). |
//! | VALIDATION   | `true`   | `true`    | `true`*  | Incremental features + legacy recomputed to compare; *STRICT panics on mismatch. |
//! | PERFORMANCE  | `true`   | `false`   | `false`  | Incremental features only; legacy runs only on fallback (desync / NaN). |
//!
//! **Typed parsing:** `USE_TYPED_PARSING` uses a narrow struct first; on failure, full `Value` parse (same as always).
//! **Rust file read:** `USE_RUST_INGESTION` only affects `process_jsonl_file`; the RF pipeline still uses `process_batch` unless you use `--native-rust-join`.
#![allow(dead_code)]

// -----------------------------------------------------------------------------
// PERFORMANCE preset — change these four lines to revert (see SAFE block at EOF).
// -----------------------------------------------------------------------------

/// Typed top-level parse first; on error, full JSON `Value` parse (safe fallback).
pub const USE_TYPED_PARSING: bool = true;

/// Dual-run vs legacy (slower). Keep `false` for speed; set `true` temporarily to validate parity.
pub const USE_INCREMENTAL_WINDOWS: bool = false;

/// Panic if incremental vs legacy mismatch (only meaningful when `WINDOWS` is `true`). Keep `false` for training runs.
pub const INCREMENTAL_STRICT: bool = false;

/// Use incremental aggregates for context + dst-port entropy (fast path when `WINDOWS` is `false`).
pub const USE_INCREMENTAL_OUTPUT: bool = true;

// -----------------------------------------------------------------------------
// Other toggles (usually leave as-is)
// -----------------------------------------------------------------------------

/// `true` when incremental output or validation needs `Src60Agg` maintained alongside the deque.
#[inline]
pub const fn maintain_src60_agg() -> bool {
    USE_INCREMENTAL_WINDOWS || USE_INCREMENTAL_OUTPUT
}

/// Append timing lines under `eve_extractor/benchmarks/optimization_results.txt` every N feature rows.
pub const USE_BENCHMARK_LOGGING: bool = false;

pub const BENCHMARK_EVERY_FLOW_ROWS: u64 = 10_000;

/// Enables `RustUnifiedExtractor.process_jsonl_file` (not used by default RF streaming path).
pub const USE_RUST_INGESTION: bool = false;

// -----------------------------------------------------------------------------
// SAFE revert (copy these values over the PERFORMANCE block above if you need old behavior)
//
//   USE_TYPED_PARSING           = false
//   USE_INCREMENTAL_WINDOWS     = false
//   INCREMENTAL_STRICT          = false
//   USE_INCREMENTAL_OUTPUT      = false
// -----------------------------------------------------------------------------
