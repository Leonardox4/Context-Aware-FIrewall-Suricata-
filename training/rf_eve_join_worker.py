"""
Spawn-safe ProcessPool worker for parallel EVE → Rust features → Parquet shards.

Lives in its own module so multiprocessing "spawn" children can import it without
re-running Randomforest_training_pipeline.main().
"""

from __future__ import annotations

import os
import pickle
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pyarrow as pa
from pyarrow import parquet as pq

from ingestion.unified_behavioral_schema import (
    DEFAULT_FILL,
    FEATURE_BOUNDS,
    UNIFIED_BEHAVIORAL_FEATURE_NAMES,
)

# Keep aligned with Randomforest_training_pipeline.DEFAULT_RUST_PROCESS_BATCH_LINES
PARQUET_ROW_BATCH = 65_536
DEFAULT_RUST_PROCESS_BATCH_LINES = 1000


def _restrict_blas_threads() -> None:
    for key in (
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
    ):
        os.environ.setdefault(key, "1")


def _feature_bounds_arrays(
    feature_names: List[str],
    bounds: Dict[str, Tuple[Optional[float], Optional[float]]],
) -> Tuple[np.ndarray, np.ndarray]:
    n = len(feature_names)
    lo = np.full(n, -np.inf, dtype=np.float64)
    hi = np.full(n, np.inf, dtype=np.float64)
    for k, name in enumerate(feature_names):
        b = bounds.get(name)
        if not b:
            continue
        lo_b, hi_b = b
        if lo_b is not None:
            lo[k] = float(lo_b)
        if hi_b is not None:
            hi[k] = float(hi_b)
    return lo, hi


def _rust_join_shard_worker(job: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process [start, end) byte range of JSONL (line-aligned by parent). Writes one Parquet shard.
    """
    _restrict_blas_threads()
    model2_root = Path(job["model2_root"])
    if str(model2_root) not in sys.path:
        sys.path.insert(0, str(model2_root))

    from ingestion.identity_key import (  # noqa: PLC0415
        coerce_parquet_utf8,
        identity_key_from_strings,
        parse_flow_line_for_join_debug,
    )
    from utils.rust_eve import (  # noqa: PLC0415
        assert_rust_extractor_matches_python_schema,
        get_rust_unified_extractor_class,
        unpack_rust_process_batch,
    )

    eve_path = job["eve_path"]
    logical_start = int(job["start"])
    end = int(job["end"])
    out_shard = job["out_shard"]
    shard_id = int(job["shard_id"])
    use_subclass = bool(job["use_subclass"])
    overlap_bytes = int(job.get("overlap_bytes", 0))
    rust_line_batch = int(job.get("rust_line_batch", DEFAULT_RUST_PROCESS_BATCH_LINES))
    if rust_line_batch < 1:
        rust_line_batch = DEFAULT_RUST_PROCESS_BATCH_LINES
    # Read from read_start < logical_start to warm Rust sliding-window state; emit only lines with
    # byte offset >= logical_start (still JSONL-safe: we only cut at newlines).
    read_start = max(0, logical_start - overlap_bytes) if logical_start > 0 else 0

    with open(job["labels_pkl"], "rb") as pf:
        payload = pickle.load(pf)
    label_map: Dict[str, int] = payload["label_map"]
    subclass_map: Dict[str, str] = payload.get("subclass_map", {})

    _lo, _hi = _feature_bounds_arrays(UNIFIED_BEHAVIORAL_FEATURE_NAMES, FEATURE_BOUNDS)

    RustCls = get_rust_unified_extractor_class()
    if RustCls is None:
        return {
            "shard_id": shard_id,
            "matched": 0,
            "path": None,
            "error": "eve_extractor not installed",
            "bytes_read": 0,
            "join_key_flow_id": 0,
            "join_key_flow_key": 0,
            "unmatched_samples": [],
            "unmatched_details": [],
        }
    engine = RustCls(if_benign_only=False)
    _slg = getattr(engine, "set_label_identity_keys", None)
    if callable(_slg):
        _slg(list(label_map.keys()))
    n_feat = assert_rust_extractor_matches_python_schema(engine)

    schema_fields = [(c, pa.float64()) for c in UNIFIED_BEHAVIORAL_FEATURE_NAMES]
    schema_fields.append(("binary_label", pa.int64()))
    if use_subclass:
        schema_fields.append(("attack_subclass", pa.string()))
    schema_fields.append(("identity_key", pa.string()))
    schema_fields.append(("flow_key", pa.string()))
    schema = pa.schema(schema_fields)

    matched_total = 0
    UNMATCHED_DEBUG_LIMIT = int(os.getenv("UNMATCHED_DEBUG_LIMIT", "100"))
    UNMATCHED_DETAIL_LIMIT = int(os.getenv("UNMATCHED_DETAIL_LIMIT", "20"))
    unmatched_samples: List[str] = []
    unmatched_details: List[str] = []
    dim_error: List[Optional[str]] = [None]

    buf_feats = np.zeros((PARQUET_ROW_BATCH, n_feat), dtype=np.float64)
    buf_labels = np.zeros(PARQUET_ROW_BATCH, dtype=np.int64)
    buf_sub: List[str] = [""] * PARQUET_ROW_BATCH if use_subclass else []
    buf_identity: List[str] = [""] * PARQUET_ROW_BATCH
    buf_flow_key: List[str] = [""] * PARQUET_ROW_BATCH
    buf_i = 0
    writer: Optional[pq.ParquetWriter] = None
    bytes_read = 0

    def _sanitize_feats_inplace(x: np.ndarray) -> None:
        m = ~np.isfinite(x)
        x[m] = DEFAULT_FILL
        np.clip(x, _lo, _hi, out=x)

    def _flush_parquet_buffer() -> None:
        nonlocal writer, buf_i
        if buf_i == 0:
            return
        cols: Dict[str, Any] = {
            UNIFIED_BEHAVIORAL_FEATURE_NAMES[k]: buf_feats[:buf_i, k] for k in range(n_feat)
        }
        cols["binary_label"] = buf_labels[:buf_i]
        if use_subclass:
            cols["attack_subclass"] = [coerce_parquet_utf8(x) for x in buf_sub[:buf_i]]
        cols["identity_key"] = buf_identity[:buf_i]
        cols["flow_key"] = buf_flow_key[:buf_i]
        if writer is None:
            writer = pq.ParquetWriter(out_shard, schema)
        writer.write_table(pa.table(cols, schema=schema))
        buf_i = 0

    def _push_matched_rows(X: np.ndarray, identity_keys: List[str], flow_keys_out: List[str]) -> None:
        nonlocal buf_i, matched_total
        for row in range(X.shape[0]):
            ik = identity_keys[row]
            buf_feats[buf_i] = X[row]
            buf_labels[buf_i] = int(label_map[ik])
            if use_subclass:
                buf_sub[buf_i] = subclass_map.get(ik, "")
            buf_identity[buf_i] = ik
            buf_flow_key[buf_i] = flow_keys_out[row]
            buf_i += 1
            matched_total += 1
            if buf_i >= PARQUET_ROW_BATCH:
                _flush_parquet_buffer()

    def flush_rust_lines(entries: List[Tuple[str, int]]) -> None:
        """Run Rust on batch; update state for all lines; emit Parquet only for line_start >= logical_start."""
        if not entries:
            return
        line_buf = [e[0] for e in entries]
        line_starts = [e[1] for e in entries]
        _, idx_b, flow_id_tup, fk_tup, feat_b = unpack_rust_process_batch(engine, line_buf)
        n_lines = len(line_buf)
        feat_idx_np = np.frombuffer(memoryview(idx_b), dtype=np.int32, count=n_lines)
        keys_fid = flow_id_tup
        keys_fk = fk_tup
        n_dense = len(keys_fid)
        if n_dense:
            n_floats = len(feat_b) // 8
            if n_floats != n_dense * n_feat:
                dim_error[0] = (
                    f"feature blob {n_floats} floats vs {n_dense}×{n_feat}; "
                    "rebuild eve_extractor (maturin develop --release)"
                )
                return
            feats_np = np.frombuffer(memoryview(feat_b), dtype=np.float64).reshape(n_dense, n_feat)
        else:
            feats_np = np.empty((0, n_feat), dtype=np.float64)
        js: List[int] = []
        matched_identity: List[str] = []
        matched_flow_key: List[str] = []
        for i in range(n_lines):
            if line_starts[i] < logical_start:
                continue
            j = int(feat_idx_np[i])
            if j < 0:
                continue
            ik = identity_key_from_strings(keys_fid[j], keys_fk[j])
            if ik not in label_map:
                if len(unmatched_samples) < UNMATCHED_DEBUG_LIMIT:
                    unmatched_samples.append(ik)
                if len(unmatched_details) < UNMATCHED_DETAIL_LIMIT:
                    d = parse_flow_line_for_join_debug(line_buf[i])
                    unmatched_details.append(
                        f"identity_key={ik!r} flow_id={keys_fid[j]!r} flow_key={keys_fk[j]!r} "
                        f"ts={d.get('ts', '')!r} src_ip={d.get('src_ip', '')!r} "
                        f"dest_ip={d.get('dest_ip', '')!r} src_port={d.get('src_port', '')!r} "
                        f"dest_port={d.get('dest_port', '')!r}"
                    )
                continue
            js.append(j)
            matched_identity.append(ik)
            matched_flow_key.append(keys_fk[j])
        if not js:
            return
        X = feats_np[np.asarray(js, dtype=np.int64)].copy()
        _sanitize_feats_inplace(X)
        _push_matched_rows(X, matched_identity, matched_flow_key)

    try:
        entries: List[Tuple[str, int]] = []
        with open(eve_path, "rb") as f:
            f.seek(read_start)
            if read_start > 0:
                skipped = f.readline()
                if skipped:
                    bytes_read += len(skipped)
            while True:
                line_start = f.tell()
                if line_start >= end:
                    break
                raw = f.readline()
                if not raw:
                    break
                bytes_read += len(raw)
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                entries.append((line, line_start))
                if len(entries) >= rust_line_batch:
                    flush_rust_lines(entries)
                    if dim_error[0]:
                        break
                    entries.clear()
            if not dim_error[0]:
                flush_rust_lines(entries)
        if dim_error[0]:
            return {
                "shard_id": shard_id,
                "matched": matched_total,
                "path": None,
                "error": dim_error[0],
                "bytes_read": bytes_read,
                "join_key_flow_id": 0,
                "join_key_flow_key": 0,
                "unmatched_samples": unmatched_samples,
                "unmatched_details": unmatched_details,
            }
        if buf_i > 0:
            _flush_parquet_buffer()
    except Exception as e:
        return {
            "shard_id": shard_id,
            "matched": matched_total,
            "path": None,
            "error": str(e),
            "bytes_read": bytes_read,
            "join_key_flow_id": 0,
            "join_key_flow_key": 0,
            "unmatched_samples": unmatched_samples,
            "unmatched_details": unmatched_details,
        }
    finally:
        if writer is not None:
            writer.close()

    jk_fn = getattr(engine, "join_key_usage_stats", None)
    jk_fid, jk_fk = (0, 0)
    if callable(jk_fn):
        a, b = jk_fn()
        jk_fid, jk_fk = int(a), int(b)
    base_out = {
        "shard_id": shard_id,
        "join_key_flow_id": jk_fid,
        "join_key_flow_key": jk_fk,
        "unmatched_samples": unmatched_samples,
        "unmatched_details": unmatched_details,
        "bytes_read": bytes_read,
    }
    if matched_total == 0:
        return {**base_out, "matched": 0, "path": None, "error": None}
    return {**base_out, "matched": matched_total, "path": out_shard, "error": None}
