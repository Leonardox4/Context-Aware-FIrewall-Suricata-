//! PyO3 module: fast Suricata EVE JSONL → unified behavioral features (flow rows only).
//! Optional: full native pipeline `join_eve_labels_to_parquet` (disk → Rust → Parquet).

mod config;
mod fast_flow_dedupe;
mod extractor;
mod flow_tcp_behavioral_engine;
mod join_pipeline;
mod typed_flow;

use std::collections::HashSet;
use std::path::Path;

use extractor::{flow_key_bucket_sec, ExtractorCore, N_FEATURES};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use pyo3::wrap_pyfunction;

#[pyclass(module = "eve_extractor", name = "RustUnifiedExtractor")]
pub struct RustUnifiedExtractor {
    inner: ExtractorCore,
    if_benign_only: bool,
}

#[pymethods]
impl RustUnifiedExtractor {
    /// When `if_benign_only` is True (Isolation Forest streaming trainer), skip alerted flows
    /// entirely — no feature row and **no** tracker update (matches Python IF path).
    #[new]
    #[pyo3(signature = (if_benign_only=false))]
    fn new(if_benign_only: bool) -> Self {
        Self {
            inner: ExtractorCore::new(),
            if_benign_only,
        }
    }

    /// Parse one JSONL line. Updates sliding-window state for `flow` events only.
    /// Returns `flow_id` (empty if absent), `flow_key`, `timestamp_epoch`, `features`, or `None`.
    fn process_line(&mut self, py: Python<'_>, line: &str) -> PyResult<Option<Py<PyDict>>> {
        Ok(match self.inner.process_line(line, self.if_benign_only) {
            Some((flow_id, flow_key, ts, feat)) => {
                let d = PyDict::new_bound(py);
                d.set_item("flow_id", flow_id)?;
                d.set_item("flow_key", flow_key)?;
                d.set_item("timestamp_epoch", ts)?;
                d.set_item("features", PyList::new_bound(py, feat.as_slice()))?;
                Some(d.unbind())
            }
            None => None,
        })
    }

    /// Returns `(is_flow_event, row_dict_or_none)`. Use for `--max-events` parity with Python chunk iterator.
    fn process_line_detailed(&mut self, py: Python<'_>, line: &str) -> PyResult<(bool, Option<Py<PyDict>>)> {
        let (is_flow, row) = self
            .inner
            .process_line_detailed(line, self.if_benign_only);
        let dict = match row {
            None => None,
            Some((flow_id, flow_key, ts, feat)) => {
                let d = PyDict::new_bound(py);
                d.set_item("flow_id", flow_id)?;
                d.set_item("flow_key", flow_key)?;
                d.set_item("timestamp_epoch", ts)?;
                d.set_item("features", PyList::new_bound(py, feat.as_slice()))?;
                Some(d.unbind())
            }
        };
        Ok((is_flow, dict))
    }

    /// Amortize PyO3 overhead: process `lines` in Rust, return packed bytes + dense keys.
    /// List of 5 elements: `[is_flow_u8, feat_idx_i32_le, flow_ids_tuple, flow_keys_tuple, f64_features_le]`.
    /// `flow_ids[j]` is raw EVE `flow_id` or `""`; Python should set `identity_key = flow_id or flow_key`.
    fn process_batch(&mut self, py: Python<'_>, lines: Vec<String>) -> PyResult<Py<PyList>> {
        let (is_flow, feat_idx, flow_ids, flow_keys, feat_blob) = self
            .inner
            .process_line_batch(&lines, self.if_benign_only);
        let mut idx_bytes = Vec::with_capacity(feat_idx.len() * 4);
        for i in feat_idx {
            idx_bytes.extend_from_slice(&i.to_le_bytes());
        }
        let is_b = PyBytes::new_bound(py, &is_flow);
        let idx_b = PyBytes::new_bound(py, &idx_bytes);
        let id_t: Bound<'_, PyTuple> = PyTuple::new_bound(py, flow_ids);
        let fk_t: Bound<'_, PyTuple> = PyTuple::new_bound(py, flow_keys);
        let fb = PyBytes::new_bound(py, &feat_blob);
        let out = PyList::empty_bound(py);
        let is_any = is_b.as_any();
        let idx_any = idx_b.as_any();
        let id_any = id_t.as_any();
        let fk_any = fk_t.as_any();
        let fb_any = fb.as_any();
        out.append(&is_any)?;
        out.append(&idx_any)?;
        out.append(&id_any)?;
        out.append(&fk_any)?;
        out.append(&fb_any)?;
        Ok(out.unbind())
    }

    /// Read JSONL from disk in Rust (`BufReader` + lines). Same semantics as feeding the same
    /// lines through `process_batch` when `config::USE_RUST_INGESTION` is `true` and rebuilt;
    /// otherwise returns an error (Python keeps using `process_batch`).
    #[pyo3(signature = (path, if_benign_only=None))]
    fn process_jsonl_file(
        &mut self,
        path: String,
        if_benign_only: Option<bool>,
    ) -> PyResult<(u64, u64)> {
        if !crate::config::USE_RUST_INGESTION {
            return Err(PyRuntimeError::new_err(
                "Rust file ingestion disabled: set eve_extractor::config::USE_RUST_INGESTION = true and rebuild",
            ));
        }
        let if_benign = if_benign_only.unwrap_or(self.if_benign_only);
        let (lines, flow_events) = self
            .inner
            .process_jsonl_file(Path::new(&path), if_benign)
            .map_err(|e| PyRuntimeError::new_err(format!("{e}")))?;
        Ok((lines, flow_events))
    }

    #[getter]
    fn n_features(&self) -> usize {
        N_FEATURES
    }

    /// Counts of emitted feature rows: ``(used_flow_id_for_join, used_flow_key_fallback)``.
    /// Matches Python ``identity_key_from_strings`` (non-empty valid ``flow_id`` vs ``flow_key``).
    fn join_key_usage_stats(&self) -> (u64, u64) {
        self.inner.join_key_usage_counts()
    }

    fn reset_join_key_usage_stats(&mut self) {
        self.inner.reset_join_key_usage_counts();
    }

    /// Restrict full feature computation to these `identity_key` strings (from labels).
    /// Pass `None` to compute features for every flow. All flows still update sliding windows.
    #[pyo3(signature = (keys=None))]
    fn set_label_identity_keys(&mut self, keys: Option<Vec<String>>) -> PyResult<()> {
        match keys {
            None => self.inner.set_label_identity_keys(None),
            Some(v) => {
                let mut h = HashSet::with_capacity(v.len());
                for s in v {
                    let t = s.trim().to_string();
                    if !t.is_empty() {
                        h.insert(t);
                    }
                }
                self.inner.set_label_identity_keys(Some(h));
            }
        }
        Ok(())
    }
}

/// Stream EVE JSONL from disk in Rust, join to labels CSV, write Parquet. Releases the GIL for the whole run.
///
/// **Labels CSV** must contain headers `identity_key` and `binary_label` (and `attack_subclass` if
/// `use_subclass` is true), matching Python `_prepare_labels_csv` + export — not raw ground-truth alone.
#[pyfunction]
#[pyo3(signature = (eve_path, labels_csv_path, output_parquet_path, use_subclass=false))]
fn join_eve_labels_to_parquet(
    py: Python<'_>,
    eve_path: String,
    labels_csv_path: String,
    output_parquet_path: String,
    use_subclass: bool,
) -> PyResult<u64> {
    py.allow_threads(|| -> PyResult<u64> {
        join_pipeline::run_join_parquet(
            Path::new(&eve_path),
            Path::new(&labels_csv_path),
            Path::new(&output_parquet_path),
            use_subclass,
        )
        .map_err(|e| PyRuntimeError::new_err(e))
    })
}

#[pymodule]
fn eve_extractor(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RustUnifiedExtractor>()?;
    m.add_function(wrap_pyfunction!(join_eve_labels_to_parquet, m)?)?;
    m.add("N_FEATURES", N_FEATURES)?;
    m.add("FLOW_KEY_BUCKET_SEC", flow_key_bucket_sec())?;
    Ok(())
}
