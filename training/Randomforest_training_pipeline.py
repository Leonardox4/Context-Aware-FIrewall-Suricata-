#!/usr/bin/env python3
"""
Random Forest training pipeline for the hybrid ML firewall.

Core design:
- Features come from Suricata eve.json flow logs (unified flow-only behavioral schema).
- Labels come ONLY from an external ground-truth CSV (no alert-derived labels).
- Matching is on `identity_key`: Suricata `flow_id` when present, else time-bucketed `flow_key`
  (see `ingestion.identity_key` and `ingestion.flow_identity`). TCP-derived features use the
  optional `tcp` object on each **flow** event; `has_tcp` encodes whether that object was present.
- Scaler and (optionally) Isolation Forest artifacts can be reused from a
  previous Isolationforest_training_pipeline run to keep schema compatibility.
- Memory-safe for very large eve.json (millions of flows): features are written
  incrementally to a Parquet dataset; no in-memory accumulation of full X/y.

Usage (recommended for hybrid, single shared scaler at runtime):

  # 1) Train RF first (writes scaler.joblib + config.joblib reference):
  python -m training.Randomforest_training_pipeline \\
    --eve path/to/eve.json \\
    --labels-csv path/to/labels.csv \\
    --output-dir artifacts/Saved_models/RF

  # 2) Train IF on benign EVE using RF's scaler (no scaler re-fit):
  python -m training.Isolationforest_training_pipeline \\
    --dataset path/to/benign_eve.json \\
    --output-dir artifacts/Saved_models/IF \\
    --external-scaler artifacts/Saved_models/RF/scaler.joblib

  # Deploy bundle: copy isolation_forest.joblib from IF dir, random_forest.joblib + scaler.joblib + config.joblib from RF
  # (or merge configs so weights/feature_names match; validate with training.validate_hybrid_artifacts).

  # 3) Evaluate an already-trained model on another labeled eve.json (no training):
  python training/Randomforest_training_pipeline.py --eval-only \\
    --artifacts-in artifacts \\
    --eve /path/to/other_eve.json \\
    --labels-csv /path/to/other_labels.csv \\
    --output-dir artifacts

  # 3b) Quick sanity on the *same* rows as training (reuse Parquet, no EVE re-scan):
  python -m training.Randomforest_training_pipeline --eval-only \\
    --artifacts-in artifacts/Saved_models/RF \\
    --features-parquet artifacts/Saved_models/RF/training_dataset.parquet \\
    --output-dir artifacts/Saved_models/RF

  # 4) Full IF + RF + risk evaluation (anomaly, classification, and combined risk by class):
  python training/Randomforest_training_pipeline.py --eval-only --full-eval \\
    --artifacts-in artifacts \\
    --features-parquet artifacts/eval_dataset.parquet

Feature dataset cache:
- The first run writes matched (features + binary_label) to output_dir/training_dataset.parquet (default).
- If that file exists and --rebuild-features is not set, later runs load from it and skip EVE extraction.
- Use --features-parquet only to override the cache path.

Extractor policy:
- By default the pipeline **requires** the Rust `eve_extractor` module and refuses Python fallback.
- Pass **--force-python-extract** only if you explicitly need the slower Python path.
- **--validate-rust-vs-python** (optional): run Rust vs Python on the first N flows and compare Parquet outputs (debug).

The RF is binary (0 = benign, 1 = attack). If the CSV includes an
`attack_subclass` column, it is preserved in the Parquet and for analysis but not used
as a multi-class target in this pipeline.
"""

from __future__ import annotations

import argparse
import gc
import json
import multiprocessing as mp
import os
import pickle
import shutil
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import pyarrow as pa
from pyarrow import parquet as pq
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import (
    StratifiedGroupKFold,
    cross_val_score,
    StratifiedKFold,
    train_test_split,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Ensure Model2_development project root is on path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ingestion.enhanced_eve_builder import EveWork, enhanced_eve_file_context
from ingestion.unified_behavioral_schema import (
    UNIFIED_BEHAVIORAL_FEATURE_NAMES,
    N_UNIFIED_BEHAVIORAL_FEATURES,
    FEATURE_BOUNDS,
    DEFAULT_FILL,
    LABEL_KEY,
)
from ingestion.identity_key import (
    IDENTITY_KEY_COL,
    assign_identity_key_with_flow_id_first,
    build_label_maps_from_identity_key,
    coerce_parquet_utf8,
    eve_flow_id_string,
    identity_key_from_strings,
    log_identity_key_label_conflicts,
    parse_flow_line_for_join_debug,
)
from ingestion.src_ip_temporal_features import SrcIpTemporalTracker
from ingestion.unified_behavioral_pipeline import (
    BehavioralExtractorUnified,
    DstPortVariance300Tracker,
    DstUniqueSrcIps60Tracker,
    FlowInterarrivalVariance300Tracker,
    SanityCheck,
    SrcFlowCount300Tracker,
    TCPFlagEntropyTracker,
    TLSBehaviorTracker,
    WINDOW_60_SEC,
    extract_unified_behavioral_row,
)
from models.isolation_forest_model import anomaly_score_to_01
from models.random_forest_model import build_random_forest
from models.risk_engine import RiskEngine
from utils.serialization import load_artifacts, save_artifacts
from utils.rust_eve import (
    assert_rust_extractor_matches_python_schema,
    get_rust_unified_extractor_class,
    join_eve_labels_parquet_native,
    unpack_rust_process_batch,
)
from utils.streaming import create_eve_progress_bar, iter_eve_lines_with_progress
from utils.logging import log

from training.rf_eve_join_worker import _rust_join_shard_worker

# Python join path: gc every N *chunks* from iter_eve_chunks (each chunk = up to chunk_size flows).
GC_EVERY_CHUNKS = 50
# Larger Parquet batches = fewer write_table calls (faster on huge EVE streams).
PARQUET_ROW_BATCH = 65_536
# Rust: JSONL lines per ``eve_extractor.process_batch`` call. Smaller ⇒ more frequent
# progress callbacks and shorter FFI blocking windows (default 1000; override with --batch-size).
DEFAULT_RUST_PROCESS_BATCH_LINES = 1000
# Parallel EVE join: hard cap so we do not spawn dozens of heavy Rust+NumPy processes.
JOIN_WORKERS_MAX = 8

RUST_EXTRACTOR_UNAVAILABLE_MSG = (
    "Rust extractor not available. Refusing to fall back to Python path due to performance constraints. "
    "Build: cd Model2_development/rust/eve_extractor && maturin develop --release (use the same venv as training). "
    "Or pass --force-python-extract to use the Python extraction path."
)


def _restrict_blas_threads_for_parallel() -> None:
    """Avoid N workers × multi-threaded BLAS (CPU thrash). Override via env if you want."""
    for key in (
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
    ):
        os.environ.setdefault(key, "1")


def _effective_join_workers(requested: int) -> int:
    if requested <= 1:
        return 1
    cpu = os.cpu_count() or 4
    # Leave one logical CPU free for OS / IO.
    cap = max(1, min(JOIN_WORKERS_MAX, requested, max(1, cpu - 1)))
    if cap < requested:
        log(
            f"Capping --join-workers {requested} → {cap} (max {JOIN_WORKERS_MAX}, cpu_count-1={max(1, cpu - 1)}).",
            level="WARN",
        )
    return cap


def _line_aligned_shard_boundaries(path: Path, n_parts: int) -> List[int]:
    """
    Split file into n_parts contiguous byte ranges aligned to newline boundaries.
    boundaries[i]..boundaries[i+1] is processed by shard i (end exclusive).
    """
    size = path.stat().st_size
    if n_parts <= 1:
        return [0, size]
    bounds: List[int] = [0]
    with open(path, "rb") as f:
        for i in range(1, n_parts):
            target = (size * i) // n_parts
            f.seek(min(target, size))
            if 0 < target < size:
                f.readline()
            pos = f.tell()
            if pos <= bounds[-1]:
                pos = min(bounds[-1] + 1, size)
            bounds.append(pos)
    bounds.append(size)
    return bounds


def _feature_bounds_arrays(
    feature_names: List[str],
    bounds: Dict[str, Tuple[Optional[float], Optional[float]]],
) -> Tuple[np.ndarray, np.ndarray]:
    """Per-column clip bounds aligned with feature_names (-inf / inf = no bound)."""
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


def _label_key_to_index(label_map: Dict[str, Any]) -> Dict[str, int]:
    """Stable 0..n-1 index per CSV identity_key (for O(1) csv_cov without a growing set of strings)."""
    return {k: i for i, k in enumerate(label_map.keys())}


def _audit_identity_key_distribution(feats_df: pd.DataFrame) -> None:
    """Log duplicate-flow risk: same identity_key on multiple rows can leak across a random split."""
    if "identity_key" not in feats_df.columns:
        log("[AUDIT] No `identity_key` column in feature table; skip key-uniqueness audit.", level="INFO")
        return
    ik = feats_df["identity_key"].astype(str).str.strip()
    n = len(ik)
    n_unique = int(ik.nunique())
    dup_mask = ik.duplicated(keep=False)
    n_in_dup_groups = int(dup_mask.sum())
    max_per_key = int(ik.value_counts().max()) if n else 0
    log(
        f"[AUDIT] identity_key: {n_unique} unique keys / {n} rows | "
        f"rows belonging to duplicate-key groups: {n_in_dup_groups} | max rows per key: {max_per_key}",
        level="INFO",
    )
    if n_in_dup_groups > 0:
        log(
            "[AUDIT] Duplicate identity_keys present: random train/test split can put the same key in both "
            "sets (near-duplicate feature rows), which inflates held-out accuracy/ROC-AUC. "
            "Prefer GroupKFold/GroupShuffleSplit by identity_key or dedupe before split.",
            level="WARN",
        )


def _audit_feature_matrix_health(feats_df: pd.DataFrame, feat_cols: List[str]) -> None:
    """Mandatory checks: finite, non-constant, and non-zero feature behavior."""
    if not feat_cols:
        log("[AUDIT] No feature columns found for matrix health checks.", level="WARN")
        return
    X = feats_df[feat_cols].astype(np.float64)
    vals = X.values
    if not np.isfinite(vals).all():
        bad = int((~np.isfinite(vals)).sum())
        raise ValueError(f"[AUDIT] Found {bad} NaN/Inf feature values.")
    std = X.std(axis=0, ddof=0)
    nz_ratio = (X != 0.0).mean(axis=0)
    const_cols = std[std <= 0.0].index.tolist()
    all_zero_cols = nz_ratio[nz_ratio <= 0.0].index.tolist()
    low_var_cols = std[std <= 1e-12].index.tolist()
    log(
        f"[AUDIT] feature_health: total={len(feat_cols)} constant={len(const_cols)} "
        f"all_zero={len(all_zero_cols)} near_const={len(low_var_cols)}",
        level="INFO",
    )
    if const_cols:
        log(f"[AUDIT] Constant features: {const_cols}", level="WARN")
    if all_zero_cols:
        log(f"[AUDIT] All-zero features: {all_zero_cols}", level="WARN")


def _audit_train_test_identity_overlap(train_df: pd.DataFrame, test_df: pd.DataFrame) -> None:
    """Detect identity_keys appearing in both train and test (leakage when those rows are correlated)."""
    if "identity_key" not in train_df.columns or "identity_key" not in test_df.columns:
        return
    tr = set(train_df["identity_key"].astype(str).str.strip())
    te = set(test_df["identity_key"].astype(str).str.strip())
    both = tr & te
    log(
        f"[AUDIT] After split: train-only keys={len(tr - te)}, test-only keys={len(te - tr)}, "
        f"keys in BOTH train and test={len(both)}",
        level="INFO",
    )
    if both:
        sample = list(both)[:5]
        log(
            f"[AUDIT] Train/test share {len(both)} identity_keys (leakage risk). Examples: {sample}",
            level="WARN",
        )


def _log_rf_feature_importance(
    rf: Any,
    feature_names: List[str],
    *,
    csv_path: Optional[Path] = None,
    top_n: int = 25,
) -> None:
    """Log sklearn MDI (`feature_importances_`); optional CSV of all columns."""
    if not hasattr(rf, "feature_importances_"):
        log("[INFO] Model has no feature_importances_; skip importance report.", level="INFO")
        return
    imp = np.asarray(rf.feature_importances_, dtype=np.float64)
    if len(feature_names) != len(imp):
        log(
            f"[WARN] feature_importances_ length {len(imp)} != len(feature_names) {len(feature_names)}; "
            "skip importance report.",
            level="WARN",
        )
        return
    order = np.argsort(-imp)
    n = min(top_n, len(imp))
    log(
        f"=== Random Forest feature importance (mean decrease in impurity / Gini), top {n} of {len(imp)} ===",
        level="INFO",
    )
    for rank, idx in enumerate(order[:n], start=1):
        log(f"  {rank:2d}. {feature_names[idx]:45s}  {imp[idx]:.6f}", level="INFO")
    if csv_path is not None:
        out = pd.DataFrame({"feature": feature_names, "importance": imp})
        out = out.sort_values("importance", ascending=False)
        csv_path = Path(csv_path)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        out.to_csv(csv_path, index=False)
        log(f"[INFO] Wrote feature importance CSV: {csv_path}", level="INFO")


def _training_join_parquet_schema(use_subclass: bool) -> pa.Schema:
    fields = [(c, pa.float64()) for c in UNIFIED_BEHAVIORAL_FEATURE_NAMES]
    fields.append(("binary_label", pa.int64()))
    if use_subclass:
        fields.append(("attack_subclass", pa.string()))
    fields.append(("identity_key", pa.string()))
    fields.append(("flow_key", pa.string()))
    return pa.schema(fields)


def _csv_cov_mark_seen(bits: bytearray, unique_seen: List[int], idx: int) -> None:
    """First time seeing label index idx → bump unique_seen. ~n/8 bytes for n labels."""
    bi = idx >> 3
    m = 1 << (idx & 7)
    if bits[bi] & m:
        return
    bits[bi] |= m
    unique_seen[0] += 1


def _canonical_proto_str(val: Any) -> str:
    """Canonicalize protocol to an upper-case string (e.g. TCP/UDP/ICMP/6/17)."""
    if val is None:
        return ""
    s = str(val).strip().upper()
    return s


def _coerce_binary_label_column(col: pd.Series) -> pd.Series:
    """
    Normalize binary_label to int64 {0,1}.

    Accepts numeric 0/1, or common string labels (e.g. attack/benign from dataset generators).
    """
    if pd.api.types.is_numeric_dtype(col):
        v = pd.to_numeric(col, errors="coerce")
        if v.isna().any():
            raise ValueError("binary_label column contains NaN after numeric parse")
        return v.astype("int64")

    benign_tokens = frozenset(
        {"0", "0.0", "false", "no", "benign", "normal", "negative", "clean", "safe"}
    )
    attack_tokens = frozenset(
        {
            "1",
            "1.0",
            "true",
            "yes",
            "attack",
            "malicious",
            "malware",
            "positive",
            "bad",
        }
    )

    def map_one(raw: Any) -> int:
        s = str(raw).strip().lower()
        if s in benign_tokens:
            return 0
        if s in attack_tokens:
            return 1
        try:
            return 1 if int(float(s)) != 0 else 0
        except ValueError as e:
            raise ValueError(
                f"Unrecognized binary_label value {raw!r}. "
                "Use 0/1 or strings like benign/attack."
            ) from e

    return col.map(map_one).astype("int64")


def _parse_labels_timestamp_column(raw: pd.Series) -> pd.Series:
    """
    Parse label CSV timestamps to UTC datetime64 (NaT on failure).

    Rust / EVE paths never parse this column — failures come from pandas only.
    Uses ``format='mixed'`` when available (pandas 2.x) for heterogeneous ISO strings.
    """
    s = raw
    # Empty strings → NaT early (pandas sometimes leaves them as NaT anyway)
    if s.dtype == object:
        s = s.apply(lambda x: x if (x is not None and str(x).strip() != "") else pd.NA)

    kwargs: Dict[str, Any] = {"errors": "coerce", "utc": True}
    try:
        ts = pd.to_datetime(s, format="mixed", **kwargs)
    except (TypeError, ValueError):
        ts = pd.to_datetime(s, **kwargs)

    # Second chance: numeric epoch (seconds or ms) often mis-inferred as strings in CSV
    still = ts.isna() & s.notna()
    if still.any():
        num = pd.to_numeric(s[still], errors="coerce")
        sec = pd.to_datetime(num, unit="s", errors="coerce", utc=True)
        msec = pd.to_datetime(num, unit="ms", errors="coerce", utc=True)
        # Prefer whichever looks like real dates (after year 2000)
        cutoff = pd.Timestamp("2000-01-01", tz="UTC")
        pick = sec.where(sec >= cutoff, pd.NaT)
        pick = pick.where(pick.notna(), msec.where(msec >= cutoff, pd.NaT))
        ts = ts.copy()
        ts.loc[still] = pick.values

    return ts


def _prepare_labels_csv(path: Path, time_tolerance: float) -> Tuple[pd.DataFrame, float]:
    """
    Load and normalize the ground-truth CSV.

    Required columns:
      - binary_label (0/1)
      - src_ip, dst_ip
      - src_port, dst_port
      - protocol
      - timestamp  (any pandas-parsable format)

    Optional:
      - attack_subclass
    """
    df = pd.read_csv(path, low_memory=False)
    df = df.copy()
    # Normalize column names from ground truth generator (label→binary_label, proto→protocol)
    if "label" in df.columns and "binary_label" not in df.columns:
        df["binary_label"] = df["label"]
    if "proto" in df.columns and "protocol" not in df.columns:
        df["protocol"] = df["proto"]
    if "attack_type" in df.columns and "attack_subclass" not in df.columns:
        df["attack_subclass"] = df["attack_type"]
    required = [
        "binary_label",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "timestamp",
    ]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"labels CSV missing required columns: {missing}")

    df["binary_label"] = _coerce_binary_label_column(df["binary_label"])
    # Canonicalize keys
    df["src_ip"] = df["src_ip"].astype(str).str.strip()
    df["dst_ip"] = df["dst_ip"].astype(str).str.strip()
    df["src_port"] = df["src_port"].astype(int)
    df["dst_port"] = df["dst_port"].astype(int)
    df["protocol_str"] = df["protocol"].map(_canonical_proto_str)

    ts = _parse_labels_timestamp_column(df["timestamp"])
    n_bad = int(ts.isna().sum())
    if n_bad:
        bad_idx = ts.isna()
        raw_samples = (
            df.loc[bad_idx, "timestamp"]
            .dropna()
            .astype(str)
            .unique()[:12]
            .tolist()
        )
        dtypes = f"pandas={pd.__version__} timestamp_dtype={df['timestamp'].dtype}"
        log(
            f"Labels CSV: {n_bad} row(s) have timestamps that could not be parsed (dropped). "
            f"{dtypes}. Sample raw values: {raw_samples!r}",
            level="WARN",
        )
    df = df.loc[~ts.isna()].copy()
    ts = ts.loc[~ts.isna()]
    # pandas >= 2: use astype('int64') instead of .view('int64') for datetime64[ns, tz] → int conversion
    df["ts_epoch"] = ts.astype("int64") / 1e9  # seconds

    if time_tolerance <= 0:
        time_tolerance = 1.0
    df["ts_bucket"] = np.floor(df["ts_epoch"] / time_tolerance).astype(np.int64)

    # Canonical time-bucketed join key (must match eve_extractor + build_ground_truth).
    if "flow_key" not in df.columns:
        from ingestion.flow_identity import flow_key_with_time_bucket

        df["flow_key"] = [
            flow_key_with_time_bucket(
                str(r["src_ip"]).strip(),
                int(r["src_port"]),
                str(r["dst_ip"]).strip(),
                int(r["dst_port"]),
                str(r["protocol_str"]) if pd.notna(r["protocol_str"]) else str(r["protocol"]),
                float(r["ts_epoch"]),
            )
            for _, r in df.iterrows()
        ]

    df, n_ik_fid, n_ik_fk = assign_identity_key_with_flow_id_first(df)
    n_lab = len(df)
    if n_lab:
        pct_fid = 100.0 * n_ik_fid / n_lab
        pct_fk = 100.0 * n_ik_fk / n_lab
        log(
            "[INFO] Labels: using flow_id for identity_key when available (fallback=flow_key)",
            level="INFO",
        )
        log(
            f"[INFO] Labels join key mix: flow_id={pct_fid:.2f}% flow_key_fallback={pct_fk:.2f}% "
            f"({n_ik_fid} / {n_ik_fk} rows)",
            level="INFO",
        )
    return df, time_tolerance


def _export_labels_csv_for_native_join(labels_df: pd.DataFrame, path: Path, use_subclass: bool) -> None:
    """
    Minimal CSV for ``eve_extractor.join_eve_labels_to_parquet`` (Rust loads this once; no pandas on hot path).
    """
    cols = ["identity_key", "binary_label"]
    if use_subclass:
        cols.append("attack_subclass")
    missing = [c for c in cols if c not in labels_df.columns]
    if missing:
        raise RuntimeError(f"--native-rust-join: prepared labels missing columns {missing}")
    export = labels_df[cols].copy()
    export["identity_key"] = export["identity_key"].astype(str).str.strip()
    export.to_csv(path, index=False)


def _run_native_rust_join_to_parquet(
    work: EveWork,
    labels_df: pd.DataFrame,
    output_parquet_path: Path,
) -> None:
    use_subclass = "attack_subclass" in labels_df.columns
    tmp_csv = output_parquet_path.parent / ".labels_native_join_export.csv"
    _export_labels_csv_for_native_join(labels_df, tmp_csv, use_subclass)
    try:
        log(
            "[INFO] Native Rust join: Rust reads EVE (BufReader), extracts, joins, writes Parquet (GIL released).",
            level="INFO",
        )
        n_matched = join_eve_labels_parquet_native(
            work.path,
            tmp_csv,
            output_parquet_path,
            use_subclass=use_subclass,
        )
        log(f"[INFO] Native join wrote {n_matched} matched rows to {output_parquet_path}", level="INFO")
    finally:
        try:
            tmp_csv.unlink()
        except OSError:
            pass


def _count_unique_identity_keys_parquet(path: Path) -> int:
    """Distinct ``identity_key`` values in a training join Parquet (for label coverage)."""
    pf = pq.ParquetFile(path)
    seen: set[str] = set()
    n_rg = pf.num_row_groups
    for rgi in range(n_rg):
        tbl = pf.read_row_group(rgi, columns=["identity_key"])
        col = tbl.column(0)
        for ci in range(col.num_chunks):
            for x in col.chunk(ci).to_pylist():
                if x is None:
                    continue
                seen.add(str(x))
    return len(seen)


def _join_flows_with_labels_rust_parallel(
    eve_path: Path,
    label_map: Dict[str, int],
    subclass_map: Dict[str, str],
    use_subclass: bool,
    output_parquet_path: Path,
    join_workers: int,
    overlap_bytes: int = 0,
    rust_process_batch_lines: int = DEFAULT_RUST_PROCESS_BATCH_LINES,
) -> None:
    """
    Shard eve.json by line-aligned byte ranges; each process runs Rust extract + Parquet shard; merge at end.

    overlap_bytes: each worker (except the file start) may read this many bytes *before* its logical shard
    and feed those lines through Rust without writing rows—warms sliding-window state at boundaries.
    """
    join_workers = _effective_join_workers(join_workers)
    schema = _training_join_parquet_schema(use_subclass)
    output_parquet_path.parent.mkdir(parents=True, exist_ok=True)

    boundaries = _line_aligned_shard_boundaries(eve_path, join_workers)
    tmpdir = Path(tempfile.mkdtemp(prefix="rf_eve_join_"))
    labels_pkl = tmpdir / "labels.pkl"

    eve_bytes = eve_path.stat().st_size
    log(
        f"EVE size {eve_bytes / (1024 ** 3):.2f} GiB — progress: one bar advances per finished shard (order varies); "
        "read_GiB sums worker I/O (overlap warmup double-counts some bytes).",
        level="INFO",
    )

    _restrict_blas_threads_for_parallel()
    try:
        with open(labels_pkl, "wb") as lf:
            pickle.dump(
                {"label_map": label_map, "subclass_map": subclass_map},
                lf,
                protocol=pickle.HIGHEST_PROTOCOL,
            )

        nkeys = len(label_map)
        if overlap_bytes > 0:
            log(
                f"Parallel join warmup: each shard (except the first) reads ~{overlap_bytes // (1024 * 1024)} MiB "
                "before its logical start and runs those JSONL lines through Rust only (no Parquet rows) "
                "to refresh sliding-window state. Assumes EVE is roughly time-ordered; increase "
                "--join-overlap-mb if 120s-context features still look wrong at boundaries.",
                level="INFO",
            )
        else:
            log(
                "Parallel join with --join-overlap-mb 0: no boundary warmup — contextual features reset "
                "at each shard start. Prefer default overlap or --join-workers 1 for parity.",
                level="WARN",
            )
        log(
            f"Parallel Rust EVE join: {join_workers} worker processes (spawn), line-aligned shards. "
            f"Each worker unpickles the label map ({nkeys} keys). "
            f"Expect roughly {join_workers}× map RAM + per-worker Rust/NumPy overhead. "
            f"BLAS/OpenMP limited to 1 thread per worker to reduce CPU thrashing.",
            level="INFO",
        )

        jobs: List[Dict[str, Any]] = []
        for i in range(join_workers):
            jobs.append(
                {
                    "model2_root": str(ROOT.resolve()),
                    "eve_path": str(eve_path.resolve()),
                    "start": boundaries[i],
                    "end": boundaries[i + 1],
                    "out_shard": str(tmpdir / f"shard_{i:04d}.parquet"),
                    "labels_pkl": str(labels_pkl),
                    "use_subclass": use_subclass,
                    "shard_id": i,
                    "overlap_bytes": overlap_bytes,
                    "rust_line_batch": rust_process_batch_lines,
                }
            )

        ctx = mp.get_context("spawn")
        results: List[Dict[str, Any]] = []
        matched_cum = 0
        bytes_cum = 0
        _join_last_log = time.monotonic()
        _join_log_interval = 5.0
        with ProcessPoolExecutor(max_workers=join_workers, mp_context=ctx) as ex:
            futures = [ex.submit(_rust_join_shard_worker, j) for j in jobs]
            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                err = r.get("error")
                if err:
                    raise RuntimeError(f"Parallel join shard {r.get('shard_id')}: {err}")
                matched_cum += int(r.get("matched", 0))
                bytes_cum += int(r.get("bytes_read", 0))
                _now = time.monotonic()
                if _now - _join_last_log >= _join_log_interval:
                    log(
                        f"[Parallel EVE join] shards_done={len(results)}/{len(jobs)} | "
                        f"matched={matched_cum} | read_GiB={bytes_cum / (1024 ** 3):.2f}",
                        level="INFO",
                    )
                    _join_last_log = _now

        total_matched = sum(int(r.get("matched", 0)) for r in results)
        if total_matched == 0:
            raise RuntimeError("No matching flows between eve.json and labels CSV (parallel join).")

        UNMATCHED_DEBUG_LIMIT = int(os.getenv("UNMATCHED_DEBUG_LIMIT", "100"))
        UNMATCHED_DETAIL_LIMIT = int(os.getenv("UNMATCHED_DETAIL_LIMIT", "20"))
        jk_fid_sum = sum(int(r.get("join_key_flow_id", 0)) for r in results)
        jk_fk_sum = sum(int(r.get("join_key_flow_key", 0)) for r in results)
        jk_denom = max(1, jk_fid_sum + jk_fk_sum)
        log(
            f"[INFO] Join key usage (EVE feature rows, parallel sum): flow_id={100.0 * jk_fid_sum / jk_denom:.2f}% "
            f"flow_key={100.0 * jk_fk_sum / jk_denom:.2f}% (n_flow_id={jk_fid_sum} n_flow_key={jk_fk_sum})",
            level="INFO",
        )
        merged_unmatched: List[str] = []
        merged_details: List[str] = []
        for r in sorted(results, key=lambda x: int(x["shard_id"])):
            if len(merged_unmatched) < UNMATCHED_DEBUG_LIMIT:
                for k in r.get("unmatched_samples") or []:
                    if len(merged_unmatched) >= UNMATCHED_DEBUG_LIMIT:
                        break
                    merged_unmatched.append(str(k))
            if len(merged_details) < UNMATCHED_DETAIL_LIMIT:
                for ln in r.get("unmatched_details") or []:
                    if len(merged_details) >= UNMATCHED_DETAIL_LIMIT:
                        break
                    merged_details.append(str(ln))
        if merged_unmatched:
            log(
                f"[DEBUG] First unmatched identity_keys (N={len(merged_unmatched)}): {merged_unmatched!r}",
                level="INFO",
            )
        for ln in merged_details:
            log(f"[DEBUG] unmatched_detail: {ln}", level="INFO")
        if merged_unmatched:
            log(
                "[INFO] Hint: unmatched keys often involve flow_key time buckets — ensure FLOW_KEY_BUCKET_SEC "
                "matches between Python (labels) and Rust (eve_extractor); widen (e.g. 10.0 or 30.0) only "
                "if timestamps are coarse; rebuild the extension after changing the env var.",
                level="INFO",
            )

        shards_sorted = sorted([r for r in results if r.get("path")], key=lambda x: int(x["shard_id"]))
        log(f"Merging {len(shards_sorted)} Parquet shards ({total_matched} matched rows)...", level="INFO")
        writer = pq.ParquetWriter(output_parquet_path, schema)
        _merge_last_log = time.monotonic()
        _merge_interval = 5.0
        try:
            for _mi, r in enumerate(shards_sorted):
                pf = pq.ParquetFile(r["path"])
                try:
                    for rgi in range(pf.num_row_groups):
                        writer.write_table(pf.read_row_group(rgi))
                finally:
                    pf.close()
                _mn = time.monotonic()
                if _mn - _merge_last_log >= _merge_interval:
                    log(
                        f"[Merging Parquet] {_mi + 1}/{len(shards_sorted)} shards written",
                        level="INFO",
                    )
                    _merge_last_log = _mn
        finally:
            writer.close()

        n_unique = _count_unique_identity_keys_parquet(output_parquet_path)
        csv_cov = 100.0 * n_unique / max(1, nkeys)
        log(
            f"[INFO] Join complete (parallel): matched_rows={total_matched} "
            f"label_key_coverage={csv_cov:.2f}% (unique identity_keys in Parquet / {nkeys} label keys)",
            level="INFO",
        )
        if csv_cov < 99.0 and jk_fk_sum > jk_fid_sum and jk_fk_sum > 0:
            log(
                "[INFO] Recommendation: coverage is below 100% and EVE rows mostly use flow_key for join — "
                "if unmatched_detail shows real flows, try FLOW_KEY_BUCKET_SEC=10.0 or 30.0 (rebuild Rust, "
                "regenerate labels flow_key with the same bucket).",
                level="INFO",
            )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _join_flows_with_labels_rust(
    eve_path: Path,
    labels_df: pd.DataFrame,
    time_tolerance: float,
    max_events: Optional[int],
    output_parquet_path: Path,
    join_workers: int = 1,
    join_overlap_bytes: int = 0,
    rust_process_batch_lines: int = DEFAULT_RUST_PROCESS_BATCH_LINES,
    debug_progress: bool = False,
) -> None:
    """
    Same as _join_flows_with_labels but JSON parse + feature extraction run in Rust (eve_extractor).
    """
    _ = time_tolerance  # legacy API; join matches on identity_key (flow_id preferred, else flow_key).
    use_subclass = "attack_subclass" in labels_df.columns
    if "flow_key" not in labels_df.columns:
        raise RuntimeError("Labels CSV must contain 'flow_key' and 'binary_label' for behavioral join.")
    if IDENTITY_KEY_COL not in labels_df.columns:
        raise RuntimeError("Labels DataFrame must contain 'identity_key' (use _prepare_labels_csv).")
    log_identity_key_label_conflicts(labels_df, lambda m: log(m, level="INFO"))
    label_map, subclass_map = build_label_maps_from_identity_key(labels_df, use_subclass)

    jw = _effective_join_workers(join_workers)
    if jw > 1:
        if max_events is not None:
            log("--join-workers > 1 is ignored when --max-events is set (single-process path).", level="WARN")
        else:
            _join_flows_with_labels_rust_parallel(
                eve_path,
                label_map,
                subclass_map,
                use_subclass,
                output_parquet_path,
                jw,
                overlap_bytes=join_overlap_bytes,
                rust_process_batch_lines=rust_process_batch_lines,
            )
            return

    schema = _training_join_parquet_schema(use_subclass)
    output_parquet_path.parent.mkdir(parents=True, exist_ok=True)

    RustCls = get_rust_unified_extractor_class()
    if RustCls is None:
        raise RuntimeError(RUST_EXTRACTOR_UNAVAILABLE_MSG)
    engine = RustCls(if_benign_only=False)
    _reset_jk = getattr(engine, "reset_join_key_usage_stats", None)
    if callable(_reset_jk):
        _reset_jk()
    _slg = getattr(engine, "set_label_identity_keys", None)
    if callable(_slg):
        _slg(list(label_map.keys()))
    n_feat = assert_rust_extractor_matches_python_schema(engine)
    _lo, _hi = _feature_bounds_arrays(UNIFIED_BEHAVIORAL_FEATURE_NAMES, FEATURE_BOUNDS)

    events_consumed: List[int] = [0]
    matched_total: List[int] = [0]
    total_label_keys = max(1, len(label_map))
    key_to_idx = _label_key_to_index(label_map)
    cov_bits = bytearray((total_label_keys + 7) // 8)
    csv_unique_seen: List[int] = [0]

    # Debug instrumentation (mandatory audit): print extracted + joined row samples.
    dbg_enabled = os.environ.get("DEBUG_PARITY_AUDIT", "").strip().lower() in {"1", "true", "yes", "on"}
    dbg_limit_raw = os.environ.get("DEBUG_PARITY_AUDIT_LIMIT", "3")
    try:
        dbg_limit = int(dbg_limit_raw)
    except ValueError:
        dbg_limit = 3
    dbg_extracted = 0
    dbg_joined = 0
    buf_identity: List[str] = [""] * PARQUET_ROW_BATCH
    buf_flow_key: List[str] = [""] * PARQUET_ROW_BATCH

    UNMATCHED_DEBUG_LIMIT = int(os.getenv("UNMATCHED_DEBUG_LIMIT", "100"))
    UNMATCHED_DETAIL_LIMIT = int(os.getenv("UNMATCHED_DETAIL_LIMIT", "20"))
    unmatched_samples: List[str] = []
    unmatched_details: List[str] = []

    def get_postfix() -> Dict[str, Any]:
        csv_cov = 100.0 * csv_unique_seen[0] / total_label_keys
        stream_rate = 100.0 * matched_total[0] / events_consumed[0] if events_consumed[0] > 0 else 0.0
        return {
            "flows": events_consumed[0],
            "matched_rows": matched_total[0],
            "csv_cov": f"{csv_cov:.1f}%",
            "stream_rate": f"{stream_rate:.1f}%",
            "backend": "rust",
        }

    pbar, progress_cb = create_eve_progress_bar(eve_path, desc="Processing flows", chunk_size=50_000, use_tqdm=True, get_postfix=get_postfix)

    def combined_callback(b: int, _lines: int) -> None:
        if progress_cb:
            progress_cb(b, events_consumed[0])

    writer: Optional[pq.ParquetWriter] = None
    buf_feats = np.zeros((PARQUET_ROW_BATCH, n_feat), dtype=np.float64)
    buf_labels = np.zeros(PARQUET_ROW_BATCH, dtype=np.int64)
    buf_sub: List[str] = [""] * PARQUET_ROW_BATCH if use_subclass else []
    buf_i = 0

    def _sanitize_feats_inplace(x: np.ndarray) -> None:
        """Fix NaN/Inf and apply FEATURE_BOUNDS; x is (n, n_feat) or (n_feat,)."""
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
        # identity_key / flow_key are always str from join; avoid per-cell coercion hot path.
        cols["identity_key"] = buf_identity[:buf_i]
        cols["flow_key"] = buf_flow_key[:buf_i]
        if writer is None:
            writer = pq.ParquetWriter(output_parquet_path, schema)
        writer.write_table(pa.table(cols, schema=schema))
        buf_i = 0

    def _push_matched_rows(X: np.ndarray, identity_keys: List[str], flow_keys_out: List[str]) -> None:
        """X: (n, n_feat) already sanitized; append to Parquet buffer."""
        nonlocal buf_i
        for row in range(X.shape[0]):
            ik = identity_keys[row]
            _csv_cov_mark_seen(cov_bits, csv_unique_seen, key_to_idx[ik])
            buf_feats[buf_i] = X[row]
            buf_labels[buf_i] = int(label_map[ik])
            if use_subclass:
                buf_sub[buf_i] = subclass_map.get(ik, "")
            buf_identity[buf_i] = ik
            buf_flow_key[buf_i] = flow_keys_out[row]
            buf_i += 1
            matched_total[0] += 1
            if buf_i >= PARQUET_ROW_BATCH:
                _flush_parquet_buffer()

    def flush_rust_lines(line_buf: List[str]) -> None:
        """One Rust call for many lines; avoids per-flow PyDict+PyList FFI (major win)."""
        if not line_buf:
            return
        is_flow_b, idx_b, flow_id_tup, fk_tup, feat_b = unpack_rust_process_batch(engine, line_buf)
        n_lines = len(line_buf)
        is_flow_np = np.frombuffer(memoryview(is_flow_b), dtype=np.uint8, count=n_lines)
        feat_idx_np = np.frombuffer(memoryview(idx_b), dtype=np.int32, count=n_lines)
        keys_fid = flow_id_tup
        keys_fk = fk_tup
        n_dense = len(keys_fid)
        if n_dense:
            n_floats = len(feat_b) // 8
            if n_floats != n_dense * n_feat:
                raise RuntimeError(
                    f"Rust feature blob size mismatch: {n_floats} floats for {n_dense} rows "
                    f"(expected {n_dense * n_feat} = {n_dense}×{n_feat}). "
                    f"Rebuild eve_extractor: cd Model2_development/rust/eve_extractor && maturin develop --release"
                )
            feats_np = np.frombuffer(memoryview(feat_b), dtype=np.float64).reshape(n_dense, n_feat)
        else:
            feats_np = np.empty((0, n_feat), dtype=np.float64)
        js: List[int] = []
        matched_identity: List[str] = []
        matched_flow_key: List[str] = []
        for i in range(n_lines):
            if is_flow_np[i]:
                events_consumed[0] += 1
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
        line_buf: List[str] = []
        total_raw_lines: List[int] = [0]
        if max_events is None:
            for line in iter_eve_lines_with_progress(eve_path, progress_callback=combined_callback):
                total_raw_lines[0] += 1
                if debug_progress and total_raw_lines[0] % 10_000 == 0:
                    print(
                        f"[DEBUG] processed_raw_lines={total_raw_lines[0]}",
                        file=sys.stderr,
                        flush=True,
                    )
                line_buf.append(line)
                if len(line_buf) >= rust_process_batch_lines:
                    flush_rust_lines(line_buf)
                    line_buf.clear()
            flush_rust_lines(line_buf)
        else:
            for line in iter_eve_lines_with_progress(eve_path, progress_callback=combined_callback):
                is_flow, out = engine.process_line_detailed(line)
                if is_flow:
                    if events_consumed[0] >= max_events:
                        break
                    events_consumed[0] += 1
                if out is None:
                    continue
                ik = identity_key_from_strings(str(out.get("flow_id", "")), str(out["flow_key"]))
                fk = str(out["flow_key"])
                if ik not in label_map:
                    if len(unmatched_samples) < UNMATCHED_DEBUG_LIMIT:
                        unmatched_samples.append(ik)
                    if len(unmatched_details) < UNMATCHED_DETAIL_LIMIT:
                        d = parse_flow_line_for_join_debug(line)
                        unmatched_details.append(
                            f"identity_key={ik!r} flow_id={str(out.get('flow_id', ''))!r} flow_key={fk!r} "
                            f"ts={d.get('ts', '')!r} src_ip={d.get('src_ip', '')!r} "
                            f"dest_ip={d.get('dest_ip', '')!r} src_port={d.get('src_port', '')!r} "
                            f"dest_port={d.get('dest_port', '')!r}"
                        )
                    continue
                feats = out["features"]
                v = np.asarray(feats, dtype=np.float64).reshape(n_feat)
                _sanitize_feats_inplace(v)
                _push_matched_rows(v.reshape(1, n_feat), [ik], [fk])
        if buf_i > 0:
            _flush_parquet_buffer()
    finally:
        if pbar is not None:
            pbar.close()
        if writer is not None:
            writer.close()

    fn_fid_i, fn_fk_i = 0, 0
    _jks = getattr(engine, "join_key_usage_stats", None)
    if callable(_jks):
        fn_fid, fn_fk = _jks()
        fn_fid_i, fn_fk_i = int(fn_fid), int(fn_fk)
        denom = max(1, fn_fid_i + fn_fk_i)
        log(
            f"[INFO] Join key usage (EVE feature rows): flow_id={100.0 * fn_fid_i / denom:.2f}% "
            f"flow_key={100.0 * fn_fk_i / denom:.2f}% (n_flow_id={fn_fid_i} n_flow_key={fn_fk_i})",
            level="INFO",
        )
    csv_cov_final = 100.0 * csv_unique_seen[0] / total_label_keys
    log(
        f"[INFO] Join complete: matched_rows={matched_total[0]} "
        f"label_key_coverage={csv_cov_final:.2f}% (unique CSV identity_keys with ≥1 match / {total_label_keys})",
        level="INFO",
    )
    if unmatched_samples:
        log(
            f"[DEBUG] First unmatched identity_keys (N={len(unmatched_samples)}): {unmatched_samples!r}",
            level="INFO",
        )
    for ln in unmatched_details:
        log(f"[DEBUG] unmatched_detail: {ln}", level="INFO")
    if unmatched_samples:
        log(
            "[INFO] Hint: unmatched keys often involve flow_key time buckets — ensure FLOW_KEY_BUCKET_SEC "
            "matches between Python (labels) and Rust (eve_extractor); widen (e.g. 10.0 or 30.0) only "
            "if timestamps are coarse; rebuild the extension after changing the env var.",
            level="INFO",
        )
    if csv_cov_final < 99.0 and fn_fk_i > fn_fid_i and fn_fk_i > 0:
        log(
            "[INFO] Recommendation: coverage is below 100% and EVE rows mostly use flow_key for join — "
            "if unmatched_detail shows real flows, try FLOW_KEY_BUCKET_SEC=10.0 or 30.0 (rebuild Rust, "
            "regenerate labels flow_key with the same bucket).",
            level="INFO",
        )

    if matched_total[0] == 0:
        raise RuntimeError(
            "No matching flows between eve.json and labels CSV; ensure labels CSV has flow_key, "
            "binary_label, and matching identity_key (flow_id or flow_key) in EVE flow events."
        )


def _rf_validate_rust_vs_python(
    eve_path: Path,
    labels_df: pd.DataFrame,
    time_tolerance: float,
    max_flow_events: Optional[int],
    chunk_size: int,
    work_dir: Path,
    rust_process_batch_lines: int = DEFAULT_RUST_PROCESS_BATCH_LINES,
    debug_progress: bool = False,
) -> None:
    """
    Run Python then Rust join on the same EVE stream prefix (max_events); compare Parquet outputs.
    Intended for debugging semantic parity (same file order, same state update order).
    """
    if get_rust_unified_extractor_class() is None:
        raise RuntimeError(RUST_EXTRACTOR_UNAVAILABLE_MSG)
    py_path = work_dir / "validate_py.parquet"
    rust_path = work_dir / "validate_rust.parquet"
    with enhanced_eve_file_context(
        eve_path,
        legacy_raw_stream=True,
        tmp_dir=eve_path.parent,
        force_temp_enhanced=False,
    ) as eve_work:
        log("[INFO] validate-rust-vs-python: Python join...", level="INFO")
        _join_flows_with_labels(
            eve_work.path,
            labels_df,
            time_tolerance,
            max_flow_events,
            chunk_size,
            py_path,
            force_python_extract=True,
            join_workers=1,
            join_overlap_bytes=0,
        )
        log("[INFO] validate-rust-vs-python: Rust join...", level="INFO")
        _join_flows_with_labels_rust(
            eve_work.path,
            labels_df,
            time_tolerance,
            max_flow_events,
            rust_path,
            join_workers=1,
            join_overlap_bytes=0,
            rust_process_batch_lines=rust_process_batch_lines,
            debug_progress=debug_progress,
        )
    df_py = pd.read_parquet(py_path)
    df_ru = pd.read_parquet(rust_path)
    if len(df_py) != len(df_ru):
        log(
            f"Validation FAILED: row count mismatch Python={len(df_py)} Rust={len(df_ru)}",
            level="ERROR",
        )
        return
    feat_cols = [c for c in UNIFIED_BEHAVIORAL_FEATURE_NAMES if c in df_py.columns and c in df_ru.columns]
    rtol, atol = 1e-5, 1e-7
    mismatches = 0
    first_bad: Optional[Tuple[int, str, Any, Any]] = None
    for i in range(len(df_py)):
        if int(df_py["binary_label"].iloc[i]) != int(df_ru["binary_label"].iloc[i]):
            mismatches += 1
            if first_bad is None:
                first_bad = (i, "binary_label", df_py["binary_label"].iloc[i], df_ru["binary_label"].iloc[i])
            continue
        for c in feat_cols:
            a = float(df_py[c].iloc[i])
            b = float(df_ru[c].iloc[i])
            if not np.isfinite(a) or not np.isfinite(b) or not np.isclose(a, b, rtol=rtol, atol=atol):
                mismatches += 1
                if first_bad is None:
                    first_bad = (i, c, a, b)
                break
    if mismatches:
        fb = first_bad
        log(
            f"Validation FAILED: {mismatches} row/column mismatches. First: row={fb[0]} col={fb[1]} py={fb[2]} rust={fb[3]}",
            level="ERROR",
        )
    else:
        log(
            f"[INFO] validate-rust-vs-python OK: {len(df_py)} rows; features match within rtol={rtol} atol={atol}",
            level="INFO",
        )


def _join_flows_with_labels(
    eve_path: Path,
    labels_df: pd.DataFrame,
    time_tolerance: float,
    max_events: Optional[int],
    chunk_size: int,
    output_parquet_path: Path,
    force_python_extract: bool = False,
    join_workers: int = 1,
    join_overlap_bytes: int = 0,
    rust_process_batch_lines: int = DEFAULT_RUST_PROCESS_BATCH_LINES,
    debug_progress: bool = False,
) -> None:
    """
    Stream eve.json, extract flow-behavioral feature rows, join with labels by identity_key.
    Write matched rows to Parquet. Labels CSV must include flow_key and binary_label
    (identity_key is added in _prepare_labels_csv).

    **Default:** Rust ``eve_extractor`` (``process_batch``) on raw flow JSONL; TCP from embedded ``tcp`` only.
    **Opt-out:** ``--force-python-extract`` (debug only).
    """
    if not force_python_extract:
        if get_rust_unified_extractor_class() is None:
            raise RuntimeError(RUST_EXTRACTOR_UNAVAILABLE_MSG)
        log(
            "[INFO] RF join: Rust feature extraction on raw EVE (eve_extractor.process_batch; embedded tcp).",
            level="INFO",
        )
        _join_flows_with_labels_rust(
            eve_path,
            labels_df,
            time_tolerance,
            max_events,
            output_parquet_path,
            join_workers=join_workers,
            join_overlap_bytes=join_overlap_bytes,
            rust_process_batch_lines=rust_process_batch_lines,
            debug_progress=debug_progress,
        )
        return

    log(
        "[WARN] Using Python extractor (--force-python-extract). Slower than Rust; debugging only.",
        level="WARN",
    )
    if join_workers > 1:
        log("[WARN] Parallel --join-workers ignored on Python extraction path (single process).", level="WARN")

    use_subclass = "attack_subclass" in labels_df.columns
    if "flow_key" not in labels_df.columns:
        raise RuntimeError("Labels CSV must contain 'flow_key' and 'binary_label' for behavioral join.")
    if IDENTITY_KEY_COL not in labels_df.columns:
        raise RuntimeError("Labels DataFrame must contain 'identity_key' (use _prepare_labels_csv).")
    log_identity_key_label_conflicts(labels_df, lambda m: log(m, level="INFO"))
    label_map, subclass_map = build_label_maps_from_identity_key(labels_df, use_subclass)

    schema = _training_join_parquet_schema(use_subclass)
    output_parquet_path.parent.mkdir(parents=True, exist_ok=True)

    behavioral = BehavioralExtractorUnified()
    tls_tracker = TLSBehaviorTracker(window_sec=WINDOW_60_SEC)
    tcp_tracker = TCPFlagEntropyTracker(window_sec=WINDOW_60_SEC)
    dst_var_tracker = DstPortVariance300Tracker()
    iat_var_300 = FlowInterarrivalVariance300Tracker()
    dst_unique_src_60 = DstUniqueSrcIps60Tracker()
    src_flow_300 = SrcFlowCount300Tracker()
    temporal = SrcIpTemporalTracker()
    sanity = SanityCheck(UNIFIED_BEHAVIORAL_FEATURE_NAMES, FEATURE_BOUNDS, DEFAULT_FILL)
    emit_flow_id_dedupe = os.getenv("EVE_DISABLE_FLOW_ID_EMIT_DEDUPE", "").strip().lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }
    seen_emit_flow_id: set[str] = set()
    flows_seen: List[int] = [0]
    matched_total: List[int] = [0]
    total_label_keys = max(1, len(label_map))
    key_to_idx = _label_key_to_index(label_map)
    cov_bits = bytearray((total_label_keys + 7) // 8)
    csv_unique_seen: List[int] = [0]

    # Debug instrumentation (mandatory audit): print extracted + joined row samples.
    dbg_enabled = os.environ.get("DEBUG_PARITY_AUDIT", "").strip().lower() in {"1", "true", "yes", "on"}
    dbg_limit_raw = os.environ.get("DEBUG_PARITY_AUDIT_LIMIT", "3")
    try:
        dbg_limit = int(dbg_limit_raw)
    except ValueError:
        dbg_limit = 3
    dbg_extracted = 0
    dbg_joined = 0

    def get_postfix() -> Dict[str, Any]:
        # Primary rate: coverage of CSV-labeled keys (not full-stream flow ratio).
        csv_cov = 100.0 * csv_unique_seen[0] / total_label_keys
        stream_rate = 100.0 * matched_total[0] / flows_seen[0] if flows_seen[0] > 0 else 0.0
        return {
            "flows": flows_seen[0],
            "matched_rows": matched_total[0],
            "csv_cov": f"{csv_cov:.1f}%",
            "stream_rate": f"{stream_rate:.1f}%",
            "backend": "python",
        }

    pbar, progress_cb = create_eve_progress_bar(eve_path, desc="Processing flows", chunk_size=chunk_size, use_tqdm=True, get_postfix=get_postfix)

    def combined_callback(b: int, _e: int) -> None:
        if progress_cb:
            progress_cb(b, flows_seen[0])

    writer: Optional[pq.ParquetWriter] = None
    batch: List[Dict[str, Any]] = []

    line_i = 0
    try:
        for line in iter_eve_lines_with_progress(eve_path, progress_callback=combined_callback):
            line_i += 1
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(ev, dict):
                continue
            et = str(ev.get("event_type", "")).strip().lower()
            if et == "tcp":
                continue
            if et != "flow":
                continue
            if max_events is not None and flows_seen[0] >= max_events:
                break
            flows_seen[0] += 1
            if emit_flow_id_dedupe:
                fid_emit = eve_flow_id_string(ev)
                if fid_emit is not None:
                    if fid_emit in seen_emit_flow_id:
                        continue
                    seen_emit_flow_id.add(fid_emit)
            row = extract_unified_behavioral_row(
                ev,
                behavioral,
                tls_tracker,
                tcp_tracker,
                dst_var_tracker,
                iat_var_300,
                dst_unique_src_60,
                src_flow_300,
                temporal,
            )
            ik = row.get(IDENTITY_KEY_COL, "")
            if dbg_enabled and dbg_extracted < dbg_limit:
                f0 = [float(row.get(k, 0.0)) for k in UNIFIED_BEHAVIORAL_FEATURE_NAMES[:5]]
                print(
                    f"[AUDIT][train] extracted_sample identity_key={ik!r} flow_key={row.get('flow_key', '')!r} "
                    f"matched_in_labels={ik in label_map} feat0={f0}",
                    file=sys.stderr,
                )
                dbg_extracted += 1
            if ik not in label_map:
                continue
            fixed = sanity.check_and_fix(row)
            row["binary_label"] = label_map[ik]
            _csv_cov_mark_seen(cov_bits, csv_unique_seen, key_to_idx[ik])
            if use_subclass:
                row["attack_subclass"] = coerce_parquet_utf8(subclass_map.get(ik, ""))
            out = {c: fixed.get(c) for c in UNIFIED_BEHAVIORAL_FEATURE_NAMES}
            out["binary_label"] = row["binary_label"]
            if use_subclass:
                out["attack_subclass"] = row["attack_subclass"]
            out["identity_key"] = coerce_parquet_utf8(ik)
            out["flow_key"] = coerce_parquet_utf8(row.get("flow_key", ""))
            batch.append(out)
            matched_total[0] += 1
            if dbg_enabled and dbg_joined < dbg_limit:
                f0j = [float(out.get(k, 0.0)) for k in UNIFIED_BEHAVIORAL_FEATURE_NAMES[:5]]
                print(
                    f"[AUDIT][train] joined_sample identity_key={ik!r} binary_label={out.get('binary_label')} "
                    f"flow_key={out.get('flow_key', '')!r} feat0={f0j}",
                    file=sys.stderr,
                )
                dbg_joined += 1
            if len(batch) >= PARQUET_ROW_BATCH:
                if writer is None:
                    writer = pq.ParquetWriter(output_parquet_path, schema)
                tbl = pa.table({c: [b[c] for b in batch] for c in schema.names})
                writer.write_table(tbl)
                batch.clear()
            if line_i % (GC_EVERY_CHUNKS * chunk_size) == 0:
                gc.collect()
        if batch:
            if writer is None:
                writer = pq.ParquetWriter(output_parquet_path, schema)
            tbl = pa.table({c: [b[c] for b in batch] for c in schema.names})
            writer.write_table(tbl)
    finally:
        if pbar is not None:
            pbar.close()
        if writer is not None:
            writer.close()

    if matched_total[0] == 0:
        raise RuntimeError(
            "No matching flows between eve.json and labels CSV; ensure labels CSV has flow_key, "
            "binary_label, and matching identity_key (flow_id or flow_key) in EVE flow events."
        )


def main() -> None:
    p = argparse.ArgumentParser(
        description="Random Forest training using Suricata eve.json features and external CSV ground truth.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--eve", type=Path, default=None, help="Path to Suricata eve.json (JSONL, flow events). Required unless --eval-only with existing --features-parquet.")
    p.add_argument("--labels-csv", type=Path, default=None, help="Path to CSV with binary_label and flow identifiers. Required unless --eval-only with existing --features-parquet.")
    p.add_argument(
        "--artifacts-in",
        type=Path,
        default=None,
        help="Optional directory with existing IF + scaler artifacts (from Isolationforest_training_pipeline).",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts"),
        help="Directory to save updated artifacts (RF + config, reuse scaler/IF if provided).",
    )
    p.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Optional cap on number of eve.json flow events to read.",
    )
    p.add_argument(
        "--chunk-size",
        type=int,
        default=50_000,
        help="Flow events per chunk when streaming eve.json.",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_RUST_PROCESS_BATCH_LINES,
        metavar="N",
        help=(
            "JSONL lines per Rust eve_extractor.process_batch call (Rust RF join path only). "
            "Smaller ⇒ more frequent progress callbacks and shorter FFI blocking; "
            f"default {DEFAULT_RUST_PROCESS_BATCH_LINES}."
        ),
    )
    p.add_argument(
        "--debug-progress",
        action="store_true",
        help="Rust EVE join: print stderr every 10000 non-empty raw JSONL lines (sparse).",
    )
    p.add_argument(
        "--time-tolerance-sec",
        type=float,
        default=1.0,
        help="Time bucket size (seconds) for matching eve.json flows to labels CSV.",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random state for RF (for reproducibility).",
    )
    p.add_argument(
        "--features-parquet",
        type=Path,
        default=None,
        help="Override path for cached training features (default: output-dir/training_dataset.parquet).",
    )
    p.add_argument(
        "--rebuild-features",
        action="store_true",
        help="Rebuild feature dataset from eve.json even if cached Parquet exists.",
    )
    p.add_argument(
        "--cache-only",
        action="store_true",
        help="Build/load feature dataset cache only, then exit without RF training.",
    )
    p.add_argument(
        "--force-python-extract",
        action="store_true",
        help="Use Python feature extraction instead of required Rust eve_extractor (slow; debugging only).",
    )
    p.add_argument(
        "--validate-rust-vs-python",
        action="store_true",
        help="Exit after comparing Rust vs Python join outputs on a prefix of the EVE file (semantic parity check).",
    )
    p.add_argument(
        "--validate-max-flows",
        type=int,
        default=50_000,
        help="Max flow events to scan per backend when using --validate-rust-vs-python.",
    )
    p.add_argument(
        "--join-workers",
        type=int,
        default=1,
        help=(
            "Parallel Rust EVE→Parquet join: number of processes (line-aligned file shards). "
            "Default 1 (single process). Capped at min(8, cpu_count-1). Each worker loads a full label-map copy — "
            "use 2–4 first. Requires: cd Model2_development && python -m training.Randomforest_training_pipeline ... "
            "(not python training/Randomforest_training_pipeline.py). Ignored with --max-events or Python join path."
        ),
    )
    p.add_argument(
        "--native-rust-join",
        action="store_true",
        help=(
            "Disk→Rust→Parquet hot path: Rust reads JSONL with BufReader, extracts, joins labels, writes Parquet "
            "(arrow+parquet). Python only prepares labels CSV export and calls one native entrypoint. "
            "Incompatible with --force-python-extract, --join-workers>1, and --max-events. "
            "Rebuild: cd Model2_development/rust/eve_extractor && maturin develop --release"
        ),
    )
    p.add_argument(
        "--join-overlap-mb",
        type=int,
        default=128,
        help=(
            "Parallel join only: MiB of eve.jsonl to scan *before* each logical shard boundary (after the first shard) "
            "to warm Rust sliding-window state; those lines are not written to Parquet (no duplicate flow rows). "
            "0 disables warmup. Default 128. Best when EVE is roughly time-ordered; increase if 120s-context features "
            "still look off at shard edges."
        ),
    )
    p.add_argument(
        "--eval-only",
        action="store_true",
        help="Only evaluate an already-trained model on a labeled dataset (no training). Load model from --artifacts-in. Dataset: use --features-parquet to point to an existing Parquet, or pass --eve + --labels-csv for another eve.json (e.g. test set); features are then built and written to --eval-output-parquet (default: output-dir/eval_dataset.parquet) so the training parquet is not overwritten.",
    )
    p.add_argument(
        "--eval-output-parquet",
        type=Path,
        default=None,
        help="When using --eval-only with --eve + --labels-csv, write the built feature dataset here. Default: output-dir/eval_dataset.parquet.",
    )
    p.add_argument(
        "--full-eval",
        action="store_true",
        help="With --eval-only: run full IF + RF + risk evaluation. Reports RF metrics, IF anomaly distribution by class, and risk/decision distribution. Requires artifacts with both IF and RF.",
    )
    p.add_argument(
        "--cv-folds",
        type=int,
        default=0,
        help=(
            "If >1: run stratified K-fold ROC-AUC CV on the full labeled feature matrix (Pipeline: scaler+RF) "
            "before the single holdout split. Slower but shows whether one random 80/20 split is optimistic. "
            "Example: --cv-folds 5"
        ),
    )
    p.add_argument(
        "--dedupe-identity-key",
        action="store_true",
        help=(
            "Keep a single row per identity_key (first row after shuffle). Use when EVE produced duplicate "
            "matches for the same key (~165 rows in your audit). Reduces trivial train/test leakage."
        ),
    )
    p.add_argument(
        "--split-by-identity-group",
        action="store_true",
        help=(
            "Train/test split (and --cv-folds when set) using StratifiedGroupKFold so each identity_key "
            "appears only in train OR test (~80/20 via first fold of 5). Removes the 56-key overlap issue. "
            "Requires identity_key column."
        ),
    )
    p.add_argument(
        "--feature-importance-csv",
        type=Path,
        default=None,
        help="Write all RF MDI importances to this CSV (feature, importance), sorted descending.",
    )
    p.add_argument(
        "--legacy-raw-eve-stream",
        action="store_true",
        help=(
            "Deprecated no-op: TCP is always taken from the optional ``tcp`` object on flow events only. "
            "Kept for backward-compatible CLI scripts."
        ),
    )
    args = p.parse_args()

    if int(args.batch_size) < 1:
        log("--batch-size must be >= 1.", level="ERROR")
        sys.exit(1)

    join_overlap_bytes = max(0, int(args.join_overlap_mb)) * 1024 * 1024
    if args.join_workers <= 1:
        join_overlap_bytes = 0

    if getattr(args, "native_rust_join", False):
        if args.force_python_extract:
            log("--native-rust-join cannot be used with --force-python-extract.", level="ERROR")
            sys.exit(1)
        if args.join_workers > 1:
            log("--native-rust-join is single-process only; set --join-workers 1.", level="ERROR")
            sys.exit(1)
        if args.max_events is not None:
            log("--native-rust-join does not support --max-events.", level="ERROR")
            sys.exit(1)
        try:
            import eve_extractor as _ee_native  # noqa: F401

            _ = _ee_native.join_eve_labels_to_parquet
        except (ImportError, AttributeError):
            log(
                "--native-rust-join requires eve_extractor with join_eve_labels_to_parquet "
                "(arrow+parquet). Rebuild: cd Model2_development/rust/eve_extractor && maturin develop --release",
                level="ERROR",
            )
            sys.exit(1)

    if args.join_workers > 1:
        if __spec__ is None:
            log(
                "--join-workers > 1 uses multiprocessing spawn and must be run as a package module.",
                level="ERROR",
            )
            log(
                "  cd Model2_development && python -m training.Randomforest_training_pipeline --join-workers N ...",
                level="ERROR",
            )
            log("(Running `python training/Randomforest_training_pipeline.py` sets __spec__=None and breaks workers.)", level="ERROR")
            sys.exit(1)
        if args.force_python_extract:
            log("--join-workers > 1 requires Rust extraction; omit --force-python-extract.", level="ERROR")
            sys.exit(1)

    if args.validate_rust_vs_python:
        if args.eval_only:
            log("--validate-rust-vs-python cannot be combined with --eval-only.", level="ERROR")
            sys.exit(1)
        if args.force_python_extract:
            log("--validate-rust-vs-python requires Rust; omit --force-python-extract.", level="ERROR")
            sys.exit(1)
        if args.eve is None or not args.eve.exists() or args.labels_csv is None or not args.labels_csv.exists():
            log("--validate-rust-vs-python requires --eve and --labels-csv.", level="ERROR")
            sys.exit(1)
        labels_df_v, tol_v = _prepare_labels_csv(args.labels_csv, args.time_tolerance_sec)
        vdir = Path(tempfile.mkdtemp(prefix="rf_validate_"))
        try:
            _rf_validate_rust_vs_python(
                args.eve,
                labels_df_v,
                tol_v,
                args.validate_max_flows,
                args.chunk_size,
                vdir,
                rust_process_batch_lines=int(args.batch_size),
                debug_progress=bool(args.debug_progress),
            )
        finally:
            shutil.rmtree(vdir, ignore_errors=True)
        return

    if args.eval_only:
        if args.artifacts_in is None or not args.artifacts_in.exists():
            log("--eval-only requires --artifacts-in pointing to an existing directory.", level="ERROR")
            sys.exit(1)
        # Default eval dataset path: avoid overwriting training_dataset.parquet
        if args.features_parquet is not None:
            feats_path = args.features_parquet
        else:
            feats_path = args.eval_output_parquet if args.eval_output_parquet is not None else args.output_dir / "eval_dataset.parquet"
        if not feats_path.exists():
            if args.eve is None or args.labels_csv is None or not args.eve.exists() or not args.labels_csv.exists():
                log("For --eval-only with no existing feature Parquet, provide --eve and --labels-csv to build the eval dataset.", level="ERROR")
                sys.exit(1)
            log(f"Building eval feature dataset from eve.json + labels (streaming) -> {feats_path}...")
            labels_df, tol = _prepare_labels_csv(args.labels_csv, args.time_tolerance_sec)
            feats_path.parent.mkdir(parents=True, exist_ok=True)
            log("[INFO] Eval build: single-pass Rust/Python extraction on raw EVE (embedded tcp).", level="INFO")
            with enhanced_eve_file_context(
                args.eve,
                legacy_raw_stream=True,
                tmp_dir=args.eve.parent,
                force_temp_enhanced=False,
            ) as eve_work:
                if args.native_rust_join:
                    _run_native_rust_join_to_parquet(eve_work, labels_df, feats_path)
                else:
                    _join_flows_with_labels(
                        eve_work.path,
                        labels_df,
                        tol,
                        max_events=args.max_events,
                        chunk_size=args.chunk_size,
                        output_parquet_path=feats_path,
                        force_python_extract=args.force_python_extract,
                        join_workers=args.join_workers,
                        join_overlap_bytes=join_overlap_bytes,
                        rust_process_batch_lines=int(args.batch_size),
                        debug_progress=bool(args.debug_progress),
                    )
        log(f"Loading feature dataset from {feats_path}")
        feats_df = pd.read_parquet(feats_path)
        if "binary_label" not in feats_df.columns:
            log("Feature dataset is missing 'binary_label' column.", level="ERROR")
            sys.exit(1)
        log(f"Loading artifacts from {args.artifacts_in}")
        if_model, rf, scaler, config = load_artifacts(args.artifacts_in)
        eval_schema = list(config.get("feature_names", UNIFIED_BEHAVIORAL_FEATURE_NAMES))
        X = feats_df.reindex(columns=eval_schema, fill_value=0.0).astype(np.float64).values
        y = feats_df["binary_label"].astype(int).values
        X_scaled = scaler.transform(X)
        y_pred = rf.predict(X_scaled)
        y_prob = rf.predict_proba(X_scaled)[:, 1] if hasattr(rf, "predict_proba") else None
        tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
        acc = accuracy_score(y, y_pred)
        roc = roc_auc_score(y, y_prob) if y_prob is not None else float("nan")
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        log("=== RandomForest evaluation (--eval-only) ===")
        log(f"Dataset rows: {len(y)}")
        log(f"Confusion matrix: [[{tn} {fp}] [{fn} {tp}]]")
        log(f"Accuracy: {acc:.4f}")
        report = classification_report(y, y_pred, target_names=["benign", "attack"])
        log("Classification report:\n" + report)
        log(f"ROC-AUC: {roc:.4f}" if not np.isnan(roc) else "ROC-AUC: N/A")
        log(f"False Positive Rate (benign misclassified as attack): {fpr:.4%}")

        n_ev = len(y)
        if n_ev > 0:
            tb, ta = int((y == 0).sum()), int((y == 1).sum())
            pb, pa = int((y_pred == 0).sum()), int((y_pred == 1).sum())
            log("=== Sanity: class mix (ground truth vs RF predictions) ===", level="INFO")
            log(
                f"Ground truth: benign {tb} ({100.0 * tb / n_ev:.2f}%), attack {ta} ({100.0 * ta / n_ev:.2f}%)",
                level="INFO",
            )
            log(
                f"Predicted:    benign {pb} ({100.0 * pb / n_ev:.2f}%), attack {pa} ({100.0 * pa / n_ev:.2f}%)",
                level="INFO",
            )
            if y_prob is not None:
                log(
                    f"P(attack): min={y_prob.min():.4f} max={y_prob.max():.4f} mean={y_prob.mean():.4f} "
                    f"median={float(np.median(y_prob)):.4f}",
                    level="INFO",
                )

        if getattr(args, "full_eval", False):
            # Full IF + RF + risk evaluation
            weights = config.get("weights")
            if weights is None or len(weights) != 3:
                weights = (0.4, 0.4, 0.2)
            low_thresh = 0.30
            high_thresh = 0.60

            if if_model is not None:
                raw_if = if_model.decision_function(X_scaled)
                anom_01 = anomaly_score_to_01(raw_if)
                try:
                    if_roc = roc_auc_score(y, anom_01)
                except ValueError:
                    if_roc = float("nan")
                benign_mask = y == 0
                attack_mask = y == 1
                log("=== Isolation Forest (anomaly) evaluation ===")
                log(f"Anomaly score [0,1] (1=most anomalous); ROC-AUC (anomaly vs attack): {if_roc:.4f}" if not np.isnan(if_roc) else "ROC-AUC: N/A")
                if benign_mask.any():
                    log(f"  Benign (n={benign_mask.sum()}): mean={np.mean(anom_01[benign_mask]):.4f} std={np.std(anom_01[benign_mask]):.4f} p50={np.percentile(anom_01[benign_mask], 50):.4f} p95={np.percentile(anom_01[benign_mask], 95):.4f}")
                if attack_mask.any():
                    log(f"  Attack (n={attack_mask.sum()}): mean={np.mean(anom_01[attack_mask]):.4f} std={np.std(anom_01[attack_mask]):.4f} p50={np.percentile(anom_01[attack_mask], 50):.4f} p95={np.percentile(anom_01[attack_mask], 95):.4f}")

                engine = RiskEngine(w1=weights[0], w2=weights[1], w3=weights[2])
                severity = np.zeros(len(y))
                risk = engine.compute(anom_01, y_prob if y_prob is not None else np.zeros(len(y)), severity)
                decisions = np.array([engine.decision(float(r), low_thresh=low_thresh, high_thresh=high_thresh) for r in risk])

                log("=== Combined risk score (IF + RF + severity) ===")
                log(f"Weights: w1(anomaly)={weights[0]} w2(attack_prob)={weights[1]} w3(severity)={weights[2]} | thresholds: low={low_thresh} high={high_thresh}")
                if benign_mask.any():
                    log(f"  Benign: risk mean={np.mean(risk[benign_mask]):.4f} std={np.std(risk[benign_mask]):.4f} | LOW={np.sum(decisions[benign_mask] == 'LOW')} MEDIUM={np.sum(decisions[benign_mask] == 'MEDIUM')} HIGH={np.sum(decisions[benign_mask] == 'HIGH')}")
                if attack_mask.any():
                    log(f"  Attack: risk mean={np.mean(risk[attack_mask]):.4f} std={np.std(risk[attack_mask]):.4f} | LOW={np.sum(decisions[attack_mask] == 'LOW')} MEDIUM={np.sum(decisions[attack_mask] == 'MEDIUM')} HIGH={np.sum(decisions[attack_mask] == 'HIGH')}")
                log(f"  Overall: LOW={np.sum(decisions == 'LOW')} MEDIUM={np.sum(decisions == 'MEDIUM')} HIGH={np.sum(decisions == 'HIGH')}")
            else:
                log("=== Full eval: IF not present (RF-only artifacts); skipping IF and risk sections. ===")
        return

    if args.eve is None or not args.eve.exists():
        log("--eve is required and must point to an existing eve.json file.", level="ERROR")
        sys.exit(1)
    if args.labels_csv is None or not args.labels_csv.exists():
        log("--labels-csv is required and must point to an existing CSV file.", level="ERROR")
        sys.exit(1)

    # Prepare labels
    labels_df, tol = _prepare_labels_csv(args.labels_csv, args.time_tolerance_sec)
    log(f"Loaded labels CSV with {len(labels_df)} rows (time_tolerance={tol}s).")

    # Debug instrumentation (mandatory audit): print label rows.
    if os.environ.get("DEBUG_PARITY_AUDIT", "").strip().lower() in {"1", "true", "yes", "on"}:
        dbg_limit_raw = os.environ.get("DEBUG_PARITY_AUDIT_LIMIT", "3")
        try:
            dbg_limit = int(dbg_limit_raw)
        except ValueError:
            dbg_limit = 3
        print(
            f"[AUDIT][train] labels_head (limit={dbg_limit}):\n{labels_df.head(dbg_limit).to_string(index=False)}",
            file=sys.stderr,
        )

    # Build or load cached feature dataset (flow-level samples with labels)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    feats_path: Path
    if args.features_parquet is not None:
        feats_path = args.features_parquet
    else:
        feats_path = args.output_dir / "training_dataset.parquet"

    if feats_path.exists() and not args.rebuild_features:
        log(f"[INFO] Using cached feature Parquet (skip extraction): {feats_path}", level="INFO")
        feats_df = pd.read_parquet(feats_path)
    else:
        if args.rebuild_features and feats_path.exists():
            log("[WARN] Rebuilding features from JSONL (this is expensive)", level="WARN")
        elif not feats_path.exists():
            log(f"[INFO] No cache at {feats_path}; extracting features from EVE via Rust (enforced)...", level="INFO")
        feats_path.parent.mkdir(parents=True, exist_ok=True)
        log(
            "[INFO] Training join: single-pass extraction on raw EVE (Rust process_batch; embedded tcp).",
            level="INFO",
        )
        with enhanced_eve_file_context(
            args.eve,
            legacy_raw_stream=True,
            tmp_dir=args.eve.parent,
            force_temp_enhanced=False,
        ) as eve_work:
            if args.native_rust_join:
                _run_native_rust_join_to_parquet(eve_work, labels_df, feats_path)
            else:
                _join_flows_with_labels(
                    eve_work.path,
                    labels_df,
                    tol,
                    max_events=args.max_events,
                    chunk_size=args.chunk_size,
                    output_parquet_path=feats_path,
                    force_python_extract=args.force_python_extract,
                    join_workers=args.join_workers,
                    join_overlap_bytes=join_overlap_bytes,
                    rust_process_batch_lines=int(args.batch_size),
                    debug_progress=bool(args.debug_progress),
                )
        feats_df = pd.read_parquet(feats_path)
        n_feat = len([c for c in UNIFIED_BEHAVIORAL_FEATURE_NAMES if c in feats_df.columns])
        log(f"Matched {len(feats_df)} labeled flows for RF training (features dim={n_feat}).")
        log(f"Saved feature dataset to {feats_path}")

    if args.cache_only:
        log(f"Cache-only mode: feature dataset ready at {feats_path}. Exiting without RF training.")
        return

    # Global shuffle to break up clumped attack blocks before train/test split
    feats_df = feats_df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    # Sanity checks on dataset
    if "binary_label" not in feats_df.columns:
        raise RuntimeError("Feature dataset is missing 'binary_label' column.")

    if args.split_by_identity_group and "identity_key" not in feats_df.columns:
        log("--split-by-identity-group requires column identity_key in the feature Parquet.", level="ERROR")
        sys.exit(1)

    if args.dedupe_identity_key:
        if "identity_key" not in feats_df.columns:
            log("--dedupe-identity-key requires column identity_key in the feature Parquet.", level="ERROR")
            sys.exit(1)
        ik_s = feats_df["identity_key"].astype(str).str.strip()
        before = len(feats_df)
        tmp = feats_df.assign(_ik=ik_s)
        n_conflicts = int(tmp.groupby("_ik", sort=False)["binary_label"].nunique().gt(1).sum())
        if n_conflicts:
            log(
                f"[WARN] {n_conflicts} identity_keys have conflicting binary_label across rows; "
                "dedupe keeps the first row after shuffle.",
                level="WARN",
            )
        feats_df = feats_df.drop_duplicates(subset=["identity_key"], keep="first").reset_index(drop=True)
        log(f"[INFO] Deduplicated by identity_key: {before} → {len(feats_df)} rows.", level="INFO")

    n_rows = len(feats_df)
    label_counts = feats_df["binary_label"].value_counts().to_dict()
    log(f"Dataset rows: {n_rows}")
    log(f"Label distribution: {label_counts}")

    _audit_identity_key_distribution(feats_df)

    feat_cols = [c for c in UNIFIED_BEHAVIORAL_FEATURE_NAMES if c in feats_df.columns]
    missing_unified = [c for c in UNIFIED_BEHAVIORAL_FEATURE_NAMES if c not in feats_df.columns]
    if missing_unified:
        log(f"[AUDIT] Feature dataframe missing unified schema columns: {missing_unified}", level="WARN")
    assert len(feat_cols) == N_UNIFIED_BEHAVIORAL_FEATURES, (
        f"feat_cols length {len(feat_cols)} != N_UNIFIED_BEHAVIORAL_FEATURES ({N_UNIFIED_BEHAVIORAL_FEATURES}); "
        f"missing={missing_unified}"
    )
    _audit_feature_matrix_health(feats_df, feat_cols)
    y_all = feats_df["binary_label"].astype(int).values
    X_all = feats_df[feat_cols].astype(np.float64).values
    groups_arr = (
        feats_df["identity_key"].astype(str).str.strip().values
        if "identity_key" in feats_df.columns
        else None
    )

    if args.cv_folds and int(args.cv_folds) > 1:
        k = int(args.cv_folds)
        cv_pipe = Pipeline(
            [
                ("scaler", StandardScaler()),
                ("rf", build_random_forest(random_state=args.seed)),
            ]
        )
        if args.split_by_identity_group:
            assert groups_arr is not None
            log(
                f"[AUDIT] Running stratified **group** {k}-fold CV (ROC-AUC; no key appears in two folds)…",
                level="INFO",
            )
            cv = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=args.seed)
            cv_scores = cross_val_score(
                cv_pipe,
                X_all,
                y_all,
                cv=cv,
                scoring="roc_auc",
                n_jobs=-1,
                groups=groups_arr,
            )
        else:
            log(f"[AUDIT] Running stratified {k}-fold CV (ROC-AUC) on full data — can take several minutes...", level="INFO")
            cv = StratifiedKFold(n_splits=k, shuffle=True, random_state=args.seed)
            cv_scores = cross_val_score(
                cv_pipe,
                X_all,
                y_all,
                cv=cv,
                scoring="roc_auc",
                n_jobs=-1,
            )
        log(
            f"[AUDIT] {k}-fold CV ROC-AUC: mean={cv_scores.mean():.4f} std={cv_scores.std():.4f} "
            f"per-fold={np.round(cv_scores, 4).tolist()}",
            level="INFO",
        )

    # Train/test split: optional group-aware split so identity_key never straddles train/test
    if args.split_by_identity_group:
        assert groups_arr is not None
        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=args.seed)
        train_idx, test_idx = next(sgkf.split(X_all, y_all, groups_arr))
        train_df = feats_df.iloc[train_idx].reset_index(drop=True)
        test_df = feats_df.iloc[test_idx].reset_index(drop=True)
        log(
            "[INFO] Train/test split: StratifiedGroupKFold (5 folds; first fold = test, ~20%) — "
            "each identity_key in train OR test only.",
            level="INFO",
        )
    else:
        train_df, test_df = train_test_split(
            feats_df,
            test_size=0.2,
            stratify=feats_df["binary_label"],
            random_state=args.seed,
        )
    _audit_train_test_identity_overlap(train_df, test_df)

    y_train = train_df["binary_label"].astype(int).values
    y_test = test_df["binary_label"].astype(int).values
    X_train = train_df[feat_cols].astype(np.float64).values
    X_test = test_df[feat_cols].astype(np.float64).values
    log(f"Train/test split: {len(y_train)} train, {len(y_test)} test samples.")

    # Load existing artifacts (preferred) or create a new scaler
    if args.artifacts_in is not None:
        if_model, rf_old, scaler, config = load_artifacts(args.artifacts_in)
        log(f"Loaded existing artifacts from {args.artifacts_in}")
    else:
        log("No artifacts-in provided; fitting a new scaler on training data and training RF only.")
        scaler = StandardScaler()
        scaler.fit(X_train)
        if_model = None
        config = {"weights": None, "feature_names": UNIFIED_BEHAVIORAL_FEATURE_NAMES}

    # Scale features with existing/new scaler
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train RF (binary)
    rf = build_random_forest(random_state=args.seed)
    rf.fit(X_train_scaled, y_train)
    log("Random Forest trained on training set.")

    # Train-set metrics (large gap vs test suggests classic overfit; both near 1.0 can still be leakage or easy task)
    y_pred_train = rf.predict(X_train_scaled)
    train_acc = accuracy_score(y_train, y_pred_train)
    if hasattr(rf, "predict_proba"):
        y_prob_train = rf.predict_proba(X_train_scaled)[:, 1]
        try:
            train_roc = roc_auc_score(y_train, y_prob_train)
        except ValueError:
            train_roc = float("nan")
    else:
        train_roc = float("nan")
    _train_audit_msg = (
        f"[AUDIT] Train-set metrics (same model, not held-out): accuracy={train_acc:.4f}"
    )
    if not np.isnan(train_roc):
        _train_audit_msg += f" ROC-AUC={train_roc:.4f}"
    log(_train_audit_msg, level="INFO")

    # Evaluation on held-out test set
    y_pred = rf.predict(X_test_scaled)
    if hasattr(rf, "predict_proba"):
        y_prob = rf.predict_proba(X_test_scaled)[:, 1]
    else:
        y_prob = None

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    acc = accuracy_score(y_test, y_pred)
    try:
        roc = roc_auc_score(y_test, y_prob) if y_prob is not None else float("nan")
    except ValueError:
        roc = float("nan")
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    log("=== RandomForest Evaluation (held-out test set) ===")
    log(f"Confusion matrix: [[{tn} {fp}] [{fn} {tp}]]")
    log(f"Accuracy: {acc:.4f}")
    if not np.isnan(train_roc) and not np.isnan(roc):
        log(
            f"[AUDIT] Train vs hold-out test: acc {train_acc:.4f}→{acc:.4f} (Δ={train_acc - acc:+.4f}), "
            f"ROC-AUC {train_roc:.4f}→{roc:.4f} (Δ={train_roc - roc:+.4f})",
            level="INFO",
        )
    # Attack is positive class (1)
    report = classification_report(y_test, y_pred, target_names=["benign", "attack"])
    log("Classification report:\n" + report)
    log(f"ROC-AUC: {roc:.4f}" if not np.isnan(roc) else "ROC-AUC: N/A")
    log(f"False Positive Rate (benign misclassified as attack): {fpr:.4%}")

    # Summarize subclass info if present (only when we just built features)
    # Note: subclasses are not cached; if needed, they should be added to feats_df.

    # Feature names must match training matrix column order (for inference + importance)
    config["feature_names"] = list(feat_cols)
    _log_rf_feature_importance(
        rf,
        feat_cols,
        csv_path=args.feature_importance_csv,
        top_n=25,
    )

    # Save artifacts: reuse IF + scaler if we had them; otherwise IF may be None
    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    if config.get("weights") is None:
        config["weights"] = (0.4, 0.4, 0.2)
    if if_model is None:
        # Save RF + scaler + config; IF will be None (not ideal for full runtime, but OK if RF-only is used)
        save_artifacts(if_model=None, rf_model=rf, scaler=scaler, config=config, path_dir=out_dir)
    else:
        save_artifacts(if_model, rf, scaler, config, out_dir)
    log(f"Artifacts (RF + scaler + config) saved to {out_dir}")
    sc_path = (out_dir / "scaler.joblib").resolve()
    log(
        f"[INFO] Reference StandardScaler for hybrid IF: {sc_path} | "
        f"train IF with: python -m training.Isolationforest_training_pipeline "
        f"--dataset <benign_eve.jsonl> --output-dir <IF_dir> --external-scaler {sc_path}",
        level="INFO",
    )


if __name__ == "__main__":
    main()

