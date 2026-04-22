#!/usr/bin/env python3
"""
Streaming Suricata eve.json training for large IDS datasets (e.g. 4.7 GB+).

Design:
- eve.json is JSONL (one JSON object per line). We stream line-by-line and never
  load the entire file into memory. ijson is for single huge JSON documents; for
  JSONL, line-by-line json.loads() is the standard and memory-safe approach.
- Line-based streaming: JSONL lines are processed in file order; **flow** lines produce feature rows
  (sliding-window state is flow-only). With ``--features-parquet``, rows stream to Parquet during the
  EVE scan (RF-style bounded RAM); without it, rows collect in memory. Default ``--max-samples 0`` caps
  at 20M benign rows; ``--max-samples N`` stops after N rows.
- Only **benign** flows (flow.alerted != True) append rows to the IF buffer; attack flows still
  advance flow counters and window state (matches Rust extractor).
- Hybrid correctness: use ``--external-scaler path/to/RF/scaler.joblib`` so IF trains in the same
  scaled space as RF (single ``scaler.transform`` at runtime). Default is still fit-on-benign for
  backward compatibility.
- Progress is logged to stderr ~every 5s (byte %, MiB/s, line/event counts) — no per-line UI.

Usage:
  python training/stream_suricata_training.py --dataset path/to/eve.json [options]
  python -m training.Isolationforest_training_pipeline --dataset benign.jsonl --output-dir artifacts/IF \\
    --external-scaler artifacts/Saved_models/RF/scaler.joblib
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure Model2 root is on path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.metrics import f1_score, recall_score, roc_auc_score
from sklearn.preprocessing import StandardScaler

from ingestion.unified_behavioral_schema import UNIFIED_BEHAVIORAL_FEATURE_NAMES, FEATURE_BOUNDS, DEFAULT_FILL
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
from models.isolation_forest_model import build_isolation_forest
from models.random_forest_model import build_random_forest
from utils.config import (
    DEFAULT_CHUNK_EVE,
    DEFAULT_IF_CONTAMINATION,
    DEFAULT_IF_ESTIMATORS,
    DEFAULT_RANDOM_STATE,
    DEFAULT_W1,
    DEFAULT_W2,
    DEFAULT_W3,
)
from utils.rust_eve import (
    assert_rust_extractor_matches_python_schema,
    get_rust_unified_extractor_class,
    unpack_rust_process_batch,
)
from utils.serialization import save_artifacts
from utils.streaming import create_eve_progress_bar, iter_eve_chunks, iter_eve_lines_with_progress

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

# RF Python join uses gc every (GC_EVERY_CHUNKS * chunk_size) lines (~2.5M); Rust RF join skips gc in the hot loop.
# IF must not gc per line: chunk_idx advances once per JSONL line, so ``% GC_EVERY_CHUNKS`` would run gc every 50 lines.
GC_EVERY_CHUNKS = 50
# Match Randomforest_training_pipeline: fewer PyO3 round-trips on large JSONL.
IF_RUST_LINE_BATCH = 65_536
GC_COLLECT_EVERY_LINES = GC_EVERY_CHUNKS * IF_RUST_LINE_BATCH

IF_RUST_EXTRACTOR_REQUIRED_MSG = (
    "Rust extractor not available. Refusing to fall back to Python path due to performance constraints. "
    "Build: cd Model2/rust/eve_extractor && maturin develop --release (same venv). "
    "Or pass --force-python-extract to use the Python extraction path."
)


# -----------------------------------------------------------------------------
# Chunk → feature matrix (unified behavioral schema)
# -----------------------------------------------------------------------------

def chunk_to_feature_matrix_unified(
    chunk_events: List[Dict[str, Any]],
    behavioral: BehavioralExtractorUnified,
    sanity: SanityCheck,
    tls_tracker: TLSBehaviorTracker,
    tcp_tracker: TCPFlagEntropyTracker,
    dst_var_tracker: DstPortVariance300Tracker,
    iat_var_300: FlowInterarrivalVariance300Tracker,
    dst_unique_src_60: DstUniqueSrcIps60Tracker,
    src_flow_300: SrcFlowCount300Tracker,
    temporal: SrcIpTemporalTracker,
) -> np.ndarray:
    """
    Build (n_benign, n_features) from a chunk of EVE dicts (flow events only in chunk).
    """
    n_feat = len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    rows: List[List[float]] = []
    for ev in chunk_events:
        if ev.get("event_type") != "flow" or not _is_benign(ev):
            continue
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
        fixed = sanity.check_and_fix(row)
        rows.append([fixed[k] for k in UNIFIED_BEHAVIORAL_FEATURE_NAMES])
    if not rows:
        return np.empty((0, n_feat), dtype=np.float64)
    return np.asarray(rows, dtype=np.float64)


def _is_benign(ev: Dict[str, Any]) -> bool:
    """True if flow is not alerted (benign)."""
    flow = ev.get("flow") or {}
    return flow.get("alerted") is not True


def filter_benign_flows(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep only benign flows: flow.alerted is False or missing."""
    out = []
    for ev in events:
        flow = ev.get("flow") or {}
        if flow.get("alerted") is True:
            continue
        out.append(ev)
    return out


# -----------------------------------------------------------------------------
# Training buffer (pre-allocated to cap memory)
# -----------------------------------------------------------------------------

class TrainingBuffer:
    """
    Pre-allocated buffer for feature matrix. Avoids repeated reallocations and
    caps memory at max_samples * n_features * 8 bytes.
    """

    def __init__(self, max_samples: int, n_features: int):
        self.max_samples = max_samples
        self.n_features = n_features
        self._buffer = np.zeros((max_samples, n_features), dtype=np.float64)
        self._n = 0

    @property
    def n_filled(self) -> int:
        return self._n

    def append(self, X: np.ndarray) -> int:
        """Copy up to (max_samples - n_filled) rows from X into buffer. Returns number copied."""
        take = min(X.shape[0], self.max_samples - self._n)
        if take <= 0:
            return 0
        self._buffer[self._n : self._n + take] = X[:take]
        self._n += take
        return take

    def get_filled(self) -> np.ndarray:
        """Return view of filled portion (read-only use)."""
        return self._buffer[: self._n]

    def clear(self) -> None:
        self._n = 0


class BenignFeatureCollector:
    """
    Collect benign feature rows up to row_cap. Two modes:
    - chunked=False: one pre-allocated TrainingBuffer (user set --max-samples N).
    - chunked=True: growable contiguous ndarray (single-pass --max-samples 0 up to USE_ALL_CAP).
      Uses doubling realloc instead of many block appends + np.vstack (same order, one stream).
    """

    __slots__ = ("row_cap", "n_features", "chunked", "_buf", "_storage", "_capacity", "_n")

    def __init__(self, row_cap: int, n_features: int, *, chunked: bool) -> None:
        self.row_cap = int(row_cap)
        self.n_features = int(n_features)
        self.chunked = chunked
        if chunked:
            self._buf = None
            self._storage: Optional[np.ndarray] = None
            self._capacity = 0
            self._n = 0
        else:
            self._buf = TrainingBuffer(self.row_cap, self.n_features)
            self._storage = None
            self._capacity = 0
            self._n = 0

    def _ensure_chunked_capacity(self, need_rows: int) -> None:
        """Grow _storage so at least need_rows rows fit (capped at row_cap)."""
        if need_rows <= self._capacity:
            return
        cap = min(self.row_cap, need_rows)
        if self._capacity == 0:
            init = min(IF_RUST_LINE_BATCH, self.row_cap)
            new_cap = min(self.row_cap, max(cap, init))
        else:
            doubled = min(self.row_cap, self._capacity * 2)
            new_cap = max(cap, doubled)
        new_cap = max(new_cap, need_rows)
        new_cap = min(new_cap, self.row_cap)
        new_storage = np.zeros((new_cap, self.n_features), dtype=np.float64)
        if self._storage is not None and self._n > 0:
            new_storage[: self._n] = self._storage[: self._n]
        self._storage = new_storage
        self._capacity = new_cap

    @property
    def n_filled(self) -> int:
        if self._buf is not None:
            return self._buf.n_filled
        return self._n

    def append(self, X: np.ndarray) -> bool:
        """
        Append feature rows (already sanitized). Return True if the EVE stream should stop
        (cap reached).
        """
        if X.size == 0:
            return False
        if self._buf is not None:
            copied = self._buf.append(X)
            if copied < X.shape[0]:
                logger.info(
                    "Training buffer full (%d samples); stopping stream.",
                    self._buf.n_filled,
                )
                return True
            if self._buf.n_filled >= self.row_cap:
                logger.info(
                    "Training buffer full (%d samples); stopping stream.",
                    self._buf.n_filled,
                )
                return True
            return False
        room = self.row_cap - self._n
        if room <= 0:
            return True
        take = min(int(X.shape[0]), room)
        if take <= 0:
            return self._n >= self.row_cap
        need = self._n + take
        self._ensure_chunked_capacity(need)
        dest = self._storage
        assert dest is not None
        dest[self._n : need] = np.ascontiguousarray(X[:take])
        self._n = need
        if self._n >= self.row_cap:
            logger.info(
                "Reached benign feature cap (%d rows); stopping stream.",
                self.row_cap,
            )
            return True
        return False

    def to_numpy(self) -> np.ndarray:
        if self._buf is not None:
            out = self._buf.get_filled().copy()
            self._buf.clear()
            return out
        if self._n == 0:
            self._storage = None
            self._capacity = 0
            return np.empty((0, self.n_features), dtype=np.float64)
        assert self._storage is not None
        out = self._storage[: self._n].copy()
        self._storage = None
        self._capacity = 0
        self._n = 0
        return out


def _if_feature_bounds_arrays() -> Tuple[np.ndarray, np.ndarray]:
    n = len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    lo = np.full(n, -np.inf, dtype=np.float64)
    hi = np.full(n, np.inf, dtype=np.float64)
    for k, name in enumerate(UNIFIED_BEHAVIORAL_FEATURE_NAMES):
        b = FEATURE_BOUNDS.get(name)
        if not b:
            continue
        lo_b, hi_b = b
        if lo_b is not None:
            lo[k] = float(lo_b)
        if hi_b is not None:
            hi[k] = float(hi_b)
    return lo, hi


def _if_sanitize_feats_inplace(x: np.ndarray, lo: np.ndarray, hi: np.ndarray) -> None:
    m = ~np.isfinite(x)
    x[m] = DEFAULT_FILL
    np.clip(x, lo, hi, out=x)


# -----------------------------------------------------------------------------
# Feature normalization hook (placeholder for custom logic)
# -----------------------------------------------------------------------------

def apply_feature_normalization(X: np.ndarray, scaler: Optional[StandardScaler] = None) -> np.ndarray:
    """
    Apply feature normalization. Currently uses StandardScaler.transform when
    scaler is fitted; otherwise returns X. Placeholder for future custom logic.
    """
    if scaler is not None and hasattr(scaler, "n_features_in_"):
        return scaler.transform(X)
    return X


# -----------------------------------------------------------------------------
# Risk scoring integration hook (placeholder)
# -----------------------------------------------------------------------------

def risk_scoring_hook(anomaly_scores: np.ndarray, attack_proba: Optional[np.ndarray] = None, severity: Optional[np.ndarray] = None) -> np.ndarray:
    """
    Placeholder for risk score integration: combine anomaly, classification, severity.
    Returns anomaly_scores unchanged for now; full pipeline uses RiskEngine at inference.
    """
    return anomaly_scores


# -----------------------------------------------------------------------------
# Model serialization (uses existing joblib save)
# -----------------------------------------------------------------------------

def _scaler_fingerprint_hex(scaler: StandardScaler) -> str:
    m = np.asarray(scaler.mean_, dtype=np.float64).tobytes()
    s = np.asarray(scaler.scale_, dtype=np.float64).tobytes()
    return hashlib.sha256(m + s).hexdigest()[:16]


def save_training_artifacts(
    if_model: Any,
    scaler: StandardScaler,
    output_dir: Path,
    *,
    reference_config: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Save IF, scaler, and config. Saves a minimal RF (dummy two-class fit) so
    load_artifacts() in inference still works; merge RF reference_config when
    training IF with --external-scaler for hybrid consistency.
    """
    if reference_config is not None:
        fn = list(reference_config.get("feature_names", UNIFIED_BEHAVIORAL_FEATURE_NAMES))
        if fn != list(UNIFIED_BEHAVIORAL_FEATURE_NAMES):
            raise ValueError(
                "reference_config feature_names must equal UNIFIED_BEHAVIORAL_FEATURE_NAMES order; "
                f"got len={len(fn)} vs unified={len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)}"
            )
        w = reference_config.get("weights")
        if w is None:
            weights = (DEFAULT_W1, DEFAULT_W2, DEFAULT_W3)
        else:
            weights = (float(w[0]), float(w[1]), float(w[2]))
        config: Dict[str, Any] = {"weights": weights, "feature_names": fn}
    else:
        config = {
            "weights": (DEFAULT_W1, DEFAULT_W2, DEFAULT_W3),
            "feature_names": list(UNIFIED_BEHAVIORAL_FEATURE_NAMES),
        }
    rf = build_random_forest(random_state=DEFAULT_RANDOM_STATE)
    X_dummy = np.zeros((2, len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)), dtype=np.float64)
    rf.fit(X_dummy, [0, 1])
    save_artifacts(if_model, rf, scaler, config, output_dir)
    logger.info("Artifacts saved to %s", output_dir)


# -----------------------------------------------------------------------------
# Cap when using "all" data (single pass, chunked collect; avoids huge upfront alloc when N << cap)
# -----------------------------------------------------------------------------

USE_ALL_CAP = 20_000_000


def _save_if_feature_cache(path: Path, X_train: np.ndarray) -> None:
    """Save IF training feature matrix to Parquet with schema column names."""
    path.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(X_train, columns=UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    df.to_parquet(path, index=False)
    logger.info("Saved IF feature cache: %s (%d rows)", path, len(df))


def _load_if_feature_cache(path: Path) -> np.ndarray:
    """Load IF training feature matrix from Parquet cache."""
    df = pd.read_parquet(path)
    missing = [c for c in UNIFIED_BEHAVIORAL_FEATURE_NAMES if c not in df.columns]
    if missing:
        raise ValueError(f"IF feature cache missing columns: {missing}")
    X = df.reindex(columns=UNIFIED_BEHAVIORAL_FEATURE_NAMES, fill_value=0.0).astype(np.float64).values
    logger.info("Loaded IF feature cache: %s (%d rows)", path, X.shape[0])
    return X


class _IfParquetFeatureSink:
    """
    Stream benign feature rows straight to Parquet (RF-style): bounded RAM, no giant
    in-memory matrix during EVE scan. Same column schema as _save_if_feature_cache.
    """

    __slots__ = ("path", "row_cap", "_n", "_writer", "_schema")

    def __init__(self, path: Path, row_cap: int) -> None:
        self.path = path
        self.row_cap = int(row_cap)
        self._n = 0
        self._writer: Optional[pq.ParquetWriter] = None
        self._schema = pa.schema([(n, pa.float64()) for n in UNIFIED_BEHAVIORAL_FEATURE_NAMES])

    @property
    def n_filled(self) -> int:
        return self._n

    def append(self, X: np.ndarray) -> bool:
        """Append rows; return True to stop streaming (cap or truncated batch)."""
        if X.size == 0:
            return False
        room = self.row_cap - self._n
        take = min(int(X.shape[0]), room)
        if take <= 0:
            return True
        sl = np.ascontiguousarray(X[:take])
        arrays = [pa.array(sl[:, i], type=pa.float64()) for i in range(sl.shape[1])]
        tbl = pa.Table.from_arrays(arrays, schema=self._schema)
        if self._writer is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                self.path.unlink()
            self._writer = pq.ParquetWriter(self.path, self._schema, compression="snappy")
        self._writer.write_table(tbl)
        self._n += take
        if self._n >= self.row_cap or take < int(X.shape[0]):
            logger.info(
                "Reached benign feature cap (%d rows); stopping stream.",
                self.row_cap,
            )
            return True
        return False

    def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None


def _eval_if_metrics(
    if_model: Any,
    scaler: StandardScaler,
    eval_eve_path: Path,
    eval_labels_path: Path,
    output_dir: Path,
) -> None:
    """
    Build labeled eval set from eval eve + labels CSV, score with IF, report ROC-AUC and Recall.
    Recall is computed at the threshold that maximizes F1 on the eval set.
    """
    from training.Randomforest_training_pipeline import _join_flows_with_labels, _prepare_labels_csv

    time_tolerance = 1.0
    labels_df, _ = _prepare_labels_csv(eval_labels_path, time_tolerance)
    eval_parquet = output_dir / ".eval_if_dataset.parquet"
    try:
        _join_flows_with_labels(
            eval_eve_path,
            labels_df,
            time_tolerance,
            max_events=None,
            chunk_size=50_000,
            output_parquet_path=eval_parquet,
        )
    except RuntimeError as e:
        if "No matching flows" in str(e):
            logger.warning("Eval set: no matching flows between eval eve and labels; skipping IF metrics.")
            return
        raise
    feats_df = pd.read_parquet(eval_parquet)
    eval_parquet.unlink(missing_ok=True)
    if "binary_label" not in feats_df.columns:
        logger.warning("Eval parquet missing binary_label; skipping IF metrics.")
        return
    X = feats_df.reindex(columns=UNIFIED_BEHAVIORAL_FEATURE_NAMES, fill_value=0.0).astype(np.float64).values
    y = feats_df["binary_label"].astype(int).values
    if X.size == 0 or len(y) == 0:
        logger.warning("Eval set empty; skipping IF metrics.")
        return
    X_scaled = scaler.transform(X)
    # decision_function: more negative = more anomalous; negate so high = attack
    scores = np.asarray(-if_model.decision_function(X_scaled), dtype=np.float64)
    roc_auc = roc_auc_score(y, scores)
    # Recall at the threshold that maximizes F1
    best_f1, best_recall = 0.0, 0.0
    for thresh in np.percentile(scores, np.linspace(5, 95, 19)):
        pred = (scores >= thresh).astype(int)
        f1 = f1_score(y, pred, zero_division=0)
        rec = recall_score(y, pred, zero_division=0)
        if f1 >= best_f1:
            best_f1 = f1
            best_recall = rec
    logger.info("IsolationForest ROC-AUC: %.2f", roc_auc)
    logger.info("IsolationForest Recall:  %.2f", best_recall)


def count_benign_flows(
    dataset_path: Path,
    chunk_size: int = 50_000,
    max_events: Optional[int] = None,
    use_tqdm: bool = True,
) -> int:
    """Stream eve.json and count flow events that are benign (flow.alerted != True)."""
    total = 0
    pbar, progress_cb = create_eve_progress_bar(
        dataset_path,
        desc="Counting benign flows",
        chunk_size=chunk_size,
        use_tqdm=use_tqdm,
        get_postfix=lambda: {"benign": total},
    )
    try:
        for chunk_events in iter_eve_chunks(
            dataset_path,
            chunk_size=chunk_size,
            event_type_filter="flow",
            max_events=max_events,
            progress_callback=progress_cb,
        ):
            total += sum(1 for ev in chunk_events if _is_benign(ev))
    finally:
        if pbar is not None:
            pbar.close()
    return total


def run_if_rust_python_validation(
    dataset_path: Path,
    chunk_size: int,
    max_flow_events: Optional[int],
    max_benign_rows: int,
) -> None:
    """
    Collect up to max_benign_rows benign flow feature rows via Python and Rust (same EVE order);
    compare numeric matrices (semantic parity check).
    """
    if get_rust_unified_extractor_class() is None:
        logger.error(IF_RUST_EXTRACTOR_REQUIRED_MSG)
        sys.exit(1)
    n_features = len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    logger.info("[INFO] validate-rust-vs-python: Python path (benign flows)...")
    behavioral = BehavioralExtractorUnified()
    tls_tracker = TLSBehaviorTracker(window_sec=WINDOW_60_SEC)
    tcp_tracker = TCPFlagEntropyTracker(window_sec=WINDOW_60_SEC)
    dst_var_tracker = DstPortVariance300Tracker()
    iat_var_300 = FlowInterarrivalVariance300Tracker()
    dst_unique_src_60 = DstUniqueSrcIps60Tracker()
    src_flow_300 = SrcFlowCount300Tracker()
    temporal = SrcIpTemporalTracker()
    sanity = SanityCheck(UNIFIED_BEHAVIORAL_FEATURE_NAMES, FEATURE_BOUNDS, DEFAULT_FILL)
    rows_py: List[List[float]] = []
    flows_seen_py = 0
    for line in iter_eve_lines_with_progress(dataset_path, progress_callback=None):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(ev, dict):
            continue
        if ev.get("event_type") != "flow":
            continue
        if max_flow_events is not None and flows_seen_py >= max_flow_events:
            break
        flows_seen_py += 1
        if not _is_benign(ev):
            continue
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
        fixed = sanity.check_and_fix(row)
        rows_py.append([fixed[k] for k in UNIFIED_BEHAVIORAL_FEATURE_NAMES])
        if len(rows_py) >= max_benign_rows:
            break
    X_py = np.asarray(rows_py, dtype=np.float64)

    logger.info("[INFO] validate-rust-vs-python: Rust path (benign flows)...")
    RustCls = get_rust_unified_extractor_class()
    assert RustCls is not None
    engine = RustCls(if_benign_only=True)
    rows_ru: List[List[float]] = []
    flows_seen = 0
    for line in iter_eve_lines_with_progress(dataset_path, progress_callback=None):
        is_flow, out = engine.process_line_detailed(line)
        if is_flow:
            if max_flow_events is not None and flows_seen >= max_flow_events:
                break
            flows_seen += 1
        if out is None:
            continue
        feats = out["features"]
        rows_ru.append(np.asarray(feats, dtype=np.float64).reshape(n_features).tolist())
        if len(rows_ru) >= max_benign_rows:
            break
    X_ru = np.asarray(rows_ru, dtype=np.float64)

    n = min(X_py.shape[0], X_ru.shape[0])
    if X_py.shape[0] != X_ru.shape[0]:
        logger.warning(
            "Benign row count mismatch: Python=%d Rust=%d (comparing first %d rows)",
            X_py.shape[0],
            X_ru.shape[0],
            n,
        )
    rtol, atol = 1e-5, 1e-7
    bad = 0
    first_i: Optional[int] = None
    for i in range(n):
        if not np.allclose(X_py[i], X_ru[i], rtol=rtol, atol=atol):
            bad += 1
            if first_i is None:
                first_i = i
    if bad:
        logger.error(
            "validate-rust-vs-python FAILED: %d/%d rows differ (first mismatch row index=%s)",
            bad,
            n,
            first_i,
        )
    else:
        logger.info(
            "[INFO] validate-rust-vs-python OK: %d benign rows match (rtol=%s atol=%s)",
            n,
            rtol,
            atol,
        )


# -----------------------------------------------------------------------------
# Main streaming training workflow
# -----------------------------------------------------------------------------

def _prepare_if_scaler_and_scaled_X(
    X_train: np.ndarray,
    *,
    external_scaler_path: Optional[Path],
    reference_config_path: Optional[Path],
) -> Tuple[StandardScaler, np.ndarray, Optional[Dict[str, Any]]]:
    """
    Fit a new StandardScaler on X_train, or load a reference scaler (RF) and transform only.
    Returns (scaler, X_scaled, reference_config_dict_or_none).
    """
    n_feat = len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    if X_train.ndim != 2 or X_train.shape[1] != n_feat:
        logger.error(
            "IF feature matrix has shape %s; expected (N, %d) unified columns.",
            getattr(X_train, "shape", None),
            n_feat,
        )
        sys.exit(1)

    ref_cfg: Optional[Dict[str, Any]] = None
    if external_scaler_path is not None:
        p = Path(external_scaler_path)
        if not p.is_file():
            logger.error("--external-scaler path does not exist or is not a file: %s", p)
            sys.exit(1)
        scaler = joblib.load(p)
        if not isinstance(scaler, StandardScaler):
            logger.error("--external-scaler must be a sklearn StandardScaler; got %s", type(scaler))
            sys.exit(1)
        nf = int(getattr(scaler, "n_features_in_", n_feat))
        if nf != n_feat:
            logger.error(
                "External scaler n_features_in_=%s != unified %s (schema mismatch).",
                nf,
                n_feat,
            )
            sys.exit(1)
        cfg_p = Path(reference_config_path) if reference_config_path is not None else p.parent / "config.joblib"
        if cfg_p.is_file():
            ref_cfg = joblib.load(cfg_p)
            if not isinstance(ref_cfg, dict):
                logger.error("Reference config at %s must be a dict; got %s", cfg_p, type(ref_cfg))
                sys.exit(1)
            fn_rf = list(ref_cfg.get("feature_names", []))
            fn_uni = list(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
            if fn_rf != fn_uni:
                diff_at = next((i for i, (a, b) in enumerate(zip(fn_rf, fn_uni)) if a != b), None)
                logger.error(
                    "Reference config feature_names != UNIFIED_BEHAVIORAL_FEATURE_NAMES (hybrid alignment failed). "
                    "len_rf=%s len_uni=%s first_mismatch_index=%s",
                    len(fn_rf),
                    len(fn_uni),
                    diff_at,
                )
                sys.exit(1)
            logger.info("Reference config loaded from %s; feature_names match unified schema.", cfg_p)
        else:
            logger.warning(
                "[WARN] No reference config at %s — skipping strict RF vs IF feature_names assertion. "
                "Prefer placing config.joblib beside scaler.joblib from RF training.",
                cfg_p,
            )
        fp = _scaler_fingerprint_hex(scaler)
        logger.info(
            "Using external StandardScaler from %s (no re-fit). Fingerprint sha256[:16]=%s",
            p,
            fp,
        )
        X_scaled = scaler.transform(X_train)
        return scaler, X_scaled, ref_cfg

    logger.info("Fitting IF StandardScaler on %d benign rows (standalone mode).", X_train.shape[0])
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)
    logger.warning(
        "[WARN] IF trained with a NEW scaler. For hybrid IF+RF with one runtime transform(), train RF first, "
        "then re-run IF with --external-scaler path/to/RF/scaler.joblib.",
    )
    return scaler, X_scaled, None


def run_streaming_training(
    dataset_path: Path,
    output_dir: Path,
    chunk_size: int = 50_000,
    max_training_samples: int = 500_000,
    max_events: Optional[int] = None,
    seed: int = 42,
    use_tqdm: bool = True,
    eval_eve_path: Optional[Path] = None,
    eval_labels_path: Optional[Path] = None,
    features_parquet: Optional[Path] = None,
    rebuild_features: bool = False,
    cache_only: bool = False,
    force_python_extract: bool = False,
    external_scaler_path: Optional[Path] = None,
    reference_config_path: Optional[Path] = None,
) -> None:
    """
    Stream eve.json, process flow events in chunks, fill training buffer with
    benign flows only, then fit scaler and Isolation Forest. Uses
    UNIFIED_BEHAVIORAL_FEATURE_NAMES from ingestion.unified_behavioral_schema.
    Saves artifacts and clears memory.

    When max_training_samples is 0, a single Rust streaming pass collects benign
    feature rows until EOF or USE_ALL_CAP (no Python JSON pre-count).

    When eval_eve_path and eval_labels_path are provided, after training the
    model is evaluated on that labeled set and ROC-AUC and Recall are logged.
    """
    n_features = len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    cache_path = features_parquet
    X_train: Optional[np.ndarray] = None
    events_processed = [0]  # mutable for progress logs

    try:
        if cache_path is not None and cache_path.exists() and not rebuild_features:
            logger.info("[INFO] Using cached IF feature Parquet (skip extraction): %s", cache_path)
            X_train = _load_if_feature_cache(cache_path)
        else:
            if rebuild_features and cache_path is not None and cache_path.exists():
                logger.warning("[WARN] Rebuilding IF features from JSONL (this is expensive)")
            if max_training_samples == 0:
                row_cap = USE_ALL_CAP
                use_chunked_collect = True
                logger.info(
                    "IF extraction: single Rust pass, up to %d benign flow rows (no pre-scan).",
                    row_cap,
                )
            else:
                row_cap = max_training_samples
                use_chunked_collect = False
            stream_parquet = cache_path is not None
            if stream_parquet:
                logger.info(
                    "[INFO] Streaming IF features to Parquet during EVE scan (RF-style RAM): %s",
                    cache_path,
                )
                row_sink: Any = _IfParquetFeatureSink(cache_path, row_cap)
            else:
                row_sink = BenignFeatureCollector(row_cap, n_features, chunked=use_chunked_collect)
            if force_python_extract:
                logger.warning("[WARN] Using Python extractor (--force-python-extract)")
                RustCls = None
                use_rust = False
            else:
                RustCls = get_rust_unified_extractor_class()
                if RustCls is None:
                    logger.error(IF_RUST_EXTRACTOR_REQUIRED_MSG)
                    sys.exit(1)
                logger.info("[INFO] Using Rust extractor (enforced)")
                use_rust = True
            behavioral = None if use_rust else BehavioralExtractorUnified()
            tls_tracker = None if use_rust else TLSBehaviorTracker(window_sec=WINDOW_60_SEC)
            tcp_tracker = None if use_rust else TCPFlagEntropyTracker(window_sec=WINDOW_60_SEC)
            sanity = None if use_rust else SanityCheck(UNIFIED_BEHAVIORAL_FEATURE_NAMES, FEATURE_BOUNDS, DEFAULT_FILL)
            rust_engine = RustCls(if_benign_only=True) if use_rust else None

            pbar, progress_callback_wrapper = create_eve_progress_bar(
                dataset_path,
                desc="Streaming eve.json",
                chunk_size=chunk_size,
                use_tqdm=use_tqdm,
                get_postfix=lambda: {
                    "events": events_processed[0],
                    "buff": row_sink.n_filled,
                    "backend": "rust" if use_rust else "python",
                },
            )

            chunk_idx = 0
            try:
                if use_rust and rust_engine is not None:
                    # Pass physical JSONL line count into the progress bar's "lines=" field.
                    # Flow/event counters only advance when a Rust batch flushes (IF_RUST_LINE_BATCH);
                    # using events_processed here made early logs show lines=0 while the file was moving.
                    def rust_progress(b: int, ln: int) -> None:
                        if progress_callback_wrapper is not None:
                            progress_callback_wrapper(b, ln)

                    # Batched Rust FFI is much faster on huge merged EVE files. When --max-events is set,
                    # keep per-line semantics (stop exactly after N flow events without over-driving state).
                    if max_events is None:
                        n_feat_rust = assert_rust_extractor_matches_python_schema(rust_engine)
                        if n_feat_rust != n_features:
                            logger.error(
                                "Rust n_features=%s != Python %s; rebuild eve_extractor.",
                                n_feat_rust,
                                n_features,
                            )
                            sys.exit(1)
                        _lo_if, _hi_if = _if_feature_bounds_arrays()
                        line_buf_r: List[str] = []

                        def flush_if_rust_batch(buf: List[str]) -> bool:
                            """Return True if caller should stop the outer stream (buffer full)."""
                            if not buf:
                                return False
                            _is_flow_b, _idx_b, _fid_t, _fk_t, _feat_b = unpack_rust_process_batch(
                                rust_engine, buf
                            )
                            n_ln = len(buf)
                            is_fn = np.frombuffer(memoryview(_is_flow_b), dtype=np.uint8, count=n_ln)
                            idx_np = np.frombuffer(memoryview(_idx_b), dtype=np.int32, count=n_ln)
                            n_den = len(_fid_t)
                            if n_den:
                                n_flt = len(_feat_b) // 8
                                if n_flt != n_den * n_features:
                                    logger.error(
                                        "Rust IF batch feature size mismatch: %s floats vs %s×%s",
                                        n_flt,
                                        n_den,
                                        n_features,
                                    )
                                    sys.exit(1)
                                feats_arr = np.frombuffer(
                                    memoryview(_feat_b), dtype=np.float64
                                ).reshape(n_den, n_features)
                            else:
                                feats_arr = np.empty((0, n_features), dtype=np.float64)
                            take_js: List[int] = []
                            for ii in range(n_ln):
                                if is_fn[ii]:
                                    events_processed[0] += 1
                                jj = int(idx_np[ii])
                                if jj < 0:
                                    continue
                                take_js.append(jj)
                            if take_js:
                                xblk = feats_arr[np.asarray(take_js, dtype=np.int64)].copy()
                                _if_sanitize_feats_inplace(xblk, _lo_if, _hi_if)
                                if row_sink.append(xblk):
                                    return True
                            return False

                        stop_stream = False
                        for line in iter_eve_lines_with_progress(
                            dataset_path, progress_callback=rust_progress
                        ):
                            chunk_idx += 1
                            line_buf_r.append(line)
                            if len(line_buf_r) >= IF_RUST_LINE_BATCH:
                                if flush_if_rust_batch(line_buf_r):
                                    stop_stream = True
                                line_buf_r.clear()
                            if chunk_idx % GC_COLLECT_EVERY_LINES == 0:
                                gc.collect()
                            if stop_stream:
                                break
                        if not stop_stream and line_buf_r:
                            flush_if_rust_batch(line_buf_r)
                            line_buf_r.clear()
                    else:
                        for line in iter_eve_lines_with_progress(
                            dataset_path, progress_callback=rust_progress
                        ):
                            chunk_idx += 1
                            is_flow, out = rust_engine.process_line_detailed(line)
                            if is_flow:
                                if max_events is not None and events_processed[0] >= max_events:
                                    break
                                events_processed[0] += 1
                            if out is None:
                                continue
                            feats = out["features"]
                            X_row = np.asarray(feats, dtype=np.float64).reshape(1, n_features)
                            if row_sink.append(X_row):
                                break
                            if chunk_idx % GC_COLLECT_EVERY_LINES == 0:
                                gc.collect()
                else:
                    dst_var_tracker = DstPortVariance300Tracker()
                    iat_var_300 = FlowInterarrivalVariance300Tracker()
                    dst_unique_src_60 = DstUniqueSrcIps60Tracker()
                    src_flow_300 = SrcFlowCount300Tracker()
                    temporal = SrcIpTemporalTracker()

                    def py_progress(b: int, ln: int) -> None:
                        if progress_callback_wrapper is not None:
                            progress_callback_wrapper(b, ln)

                    for line in iter_eve_lines_with_progress(dataset_path, progress_callback=py_progress):
                        chunk_idx += 1
                        try:
                            ev = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(ev, dict):
                            continue
                        if ev.get("event_type") != "flow":
                            continue
                        if max_events is not None and events_processed[0] >= max_events:
                            break
                        events_processed[0] += 1
                        if not _is_benign(ev):
                            if chunk_idx % GC_COLLECT_EVERY_LINES == 0:
                                gc.collect()
                            continue
                        row = extract_unified_behavioral_row(
                            ev,
                            behavioral,  # type: ignore[arg-type]
                            tls_tracker,  # type: ignore[arg-type]
                            tcp_tracker,  # type: ignore[arg-type]
                            dst_var_tracker,
                            iat_var_300,
                            dst_unique_src_60,
                            src_flow_300,
                            temporal,
                        )
                        fixed = sanity.check_and_fix(row)  # type: ignore[arg-type]
                        X_row = np.asarray(
                            [[fixed[k] for k in UNIFIED_BEHAVIORAL_FEATURE_NAMES]],
                            dtype=np.float64,
                        )
                        if row_sink.append(X_row):
                            break
                        if chunk_idx % GC_COLLECT_EVERY_LINES == 0:
                            gc.collect()
            finally:
                if pbar is not None:
                    pbar.close()
                if stream_parquet:
                    row_sink.close()

            if stream_parquet:
                if row_sink.n_filled == 0:
                    logger.error("No benign flow events found. Cannot train Isolation Forest.")
                    sys.exit(1)
                if cache_only:
                    logger.info(
                        "Cache-only mode complete. IF feature cache ready at %s (%d rows)",
                        cache_path,
                        row_sink.n_filled,
                    )
                    return
                X_train = _load_if_feature_cache(cache_path)
            else:
                X_train = row_sink.to_numpy()

            gc.collect()

            if X_train.shape[0] == 0:
                logger.error("No benign flow events found. Cannot train Isolation Forest.")
                sys.exit(1)

        if cache_only:
            if cache_path is None:
                logger.info("Cache-only requested without --features-parquet. Nothing persisted; exiting.")
            else:
                logger.info("Cache-only mode complete. IF feature cache ready at %s", cache_path)
            return

        if X_train is None or X_train.shape[0] == 0:
            logger.error("No IF training features available.")
            sys.exit(1)

        scaler, X_scaled, ref_cfg = _prepare_if_scaler_and_scaled_X(
            X_train,
            external_scaler_path=external_scaler_path,
            reference_config_path=reference_config_path,
        )

        # Placeholder: optional extra normalization hook
        X_final = apply_feature_normalization(X_scaled, scaler=None)  # already scaled
        if X_final is not X_scaled:
            X_scaled = X_final

        logger.info("Training Isolation Forest (benign flows only)...")
        if_model = build_isolation_forest(
            contamination=DEFAULT_IF_CONTAMINATION,
            n_estimators=DEFAULT_IF_ESTIMATORS,
            random_state=seed,
        )
        if_model.fit(X_scaled)

        # Clear large arrays before saving
        del X_train, X_scaled, X_final
        gc.collect()

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        save_training_artifacts(
            if_model,
            scaler,
            output_dir,
            reference_config=ref_cfg,
        )
        logger.info("Streaming training complete. Total flow events processed: %d", events_processed[0])

        # Optional: evaluate IF on labeled set and report ROC-AUC and Recall
        if eval_eve_path is not None and eval_labels_path is not None:
            _eval_if_metrics(if_model, scaler, eval_eve_path, eval_labels_path, output_dir)

    except Exception as e:
        logger.exception("Streaming training failed: %s", e)
        raise


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stream Suricata eve.json and train Isolation Forest on benign flows (memory-safe for large files).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
        help="Path to Suricata eve.json (JSONL).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts"),
        help="Directory to save models and scaler.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_EVE,
        help="Number of flow events per chunk (unified with inference; memory vs throughput).",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=0,
        help="Max training samples (stops when buffer full). Default 0 = single pass, all benign flows up to 20M cap.",
    )
    parser.add_argument(
        "--features-parquet",
        type=Path,
        default=None,
        help=(
            "IF feature Parquet path. If set during EVE extraction, rows are written incrementally (fast, "
            "low RAM like RF). If the file exists and not --rebuild-features, loads it and skips EVE."
        ),
    )
    parser.add_argument(
        "--rebuild-features",
        action="store_true",
        help="With --features-parquet: rebuild cache from EVE even when cache file exists.",
    )
    parser.add_argument(
        "--cache-only",
        action="store_true",
        help="Build/load IF feature cache and exit without fitting scaler/IF.",
    )
    parser.add_argument(
        "--eval-eve",
        type=Path,
        default=None,
        help="Optional: path to labeled eve.json for IF evaluation (ROC-AUC and Recall). Requires --eval-labels-csv.",
    )
    parser.add_argument(
        "--eval-labels-csv",
        type=Path,
        default=None,
        help="Optional: path to labels CSV for IF evaluation. Use with --eval-eve.",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Max flow events to read from file (default: no limit).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_RANDOM_STATE,
        help="Random state for Isolation Forest.",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable time-based progress logging (~every 5s) to stderr.",
    )
    parser.add_argument(
        "--no-tqdm",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--external-scaler",
        type=Path,
        default=None,
        help=(
            "Path to StandardScaler joblib from RF training (e.g. artifacts/Saved_models/RF/scaler.joblib). "
            "When set, IF is trained on scaler.transform(X) only (no scaler re-fit). "
            "Place config.joblib beside it (default) or pass --reference-config. "
            "Required for correct hybrid deployment with a single runtime scaler.transform."
        ),
    )
    parser.add_argument(
        "--reference-config",
        type=Path,
        default=None,
        help=(
            "Optional path to RF config.joblib for feature_names assertion. "
            "Default: same directory as --external-scaler / config.joblib."
        ),
    )
    parser.add_argument(
        "--force-python-extract",
        action="store_true",
        help="Use Python feature extraction instead of required Rust eve_extractor (slow; debugging only).",
    )
    parser.add_argument(
        "--validate-rust-vs-python",
        action="store_true",
        help="Exit after comparing Rust vs Python benign-feature rows on a prefix of the dataset.",
    )
    parser.add_argument(
        "--validate-max-flow-events",
        type=int,
        default=200_000,
        help="Max flow events to scan per backend during --validate-rust-vs-python.",
    )
    parser.add_argument(
        "--validate-max-benign-rows",
        type=int,
        default=10_000,
        help="Max benign rows to compare during --validate-rust-vs-python.",
    )
    args = parser.parse_args()

    if args.validate_rust_vs_python:
        if not args.dataset.exists():
            logger.error("Dataset not found: %s", args.dataset)
            return 1
        if args.force_python_extract:
            logger.error("--validate-rust-vs-python requires Rust; omit --force-python-extract.")
            return 1
        run_if_rust_python_validation(
            args.dataset,
            chunk_size=args.chunk_size,
            max_flow_events=args.validate_max_flow_events,
            max_benign_rows=args.validate_max_benign_rows,
        )
        return 0

    if args.reference_config is not None and args.external_scaler is None:
        logger.error("--reference-config requires --external-scaler.")
        return 1

    if not args.dataset.exists():
        logger.error("Dataset not found: %s", args.dataset)
        return 1
    if args.chunk_size < 1:
        logger.error("chunk-size must be >= 1.")
        return 1
    if args.max_samples < 0:
        logger.error("max-samples must be >= 0 (0 = use whole file).")
        return 1
    eval_eve = args.eval_eve
    eval_labels = args.eval_labels_csv
    if (eval_eve is not None) != (eval_labels is not None):
        logger.error("For IF evaluation provide both --eval-eve and --eval-labels-csv.")
        return 1
    try:
        run_streaming_training(
            dataset_path=args.dataset,
            output_dir=args.output_dir,
            chunk_size=args.chunk_size,
            max_training_samples=args.max_samples,
            max_events=args.max_events,
            seed=args.seed,
            use_tqdm=not args.no_progress and not args.no_tqdm,
            eval_eve_path=eval_eve if (eval_eve and eval_labels and eval_eve.exists() and eval_labels.exists()) else None,
            eval_labels_path=eval_labels if (eval_eve and eval_labels and eval_eve.exists() and eval_labels.exists()) else None,
            features_parquet=args.features_parquet if args.features_parquet is not None else (args.output_dir / "if_training_features.parquet"),
            rebuild_features=args.rebuild_features,
            cache_only=args.cache_only,
            force_python_extract=args.force_python_extract,
            external_scaler_path=args.external_scaler,
            reference_config_path=args.reference_config,
        )
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    sys.exit(main())
