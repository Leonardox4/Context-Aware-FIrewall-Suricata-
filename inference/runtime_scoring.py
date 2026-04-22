#!/usr/bin/env python3
"""
Production-grade runtime scoring pipeline for the hybrid ML firewall.

Memory-safe, chunked streaming: never loads full dataset into RAM.
- CSV (CICIDS/CICIoT): pandas read_csv(chunksize); normalize → enforce_schema → score → write → gc.
- Suricata eve.json: utils.streaming iter_eve_chunks or tail; normalize → enforce_schema → score → write → gc.

**Default (no extra flags):** IF + LGBM Stage 1 from project ``artifacts/Saved_models/IF`` and
``LGBM_STAGE01``, input ``/var/log/suricata/master_eve.json``, output ``logs/``, **tail** JSON,
**no context engine**. LGBM drives ALLOW / ALERT / BLOCK (0.05 / 0.4 / 0.7); IF is log-only
(``anomaly_score_if``). Stage-2 multiclass runs only when Stage-1 prob ≥ 0.7. Context requires
``--use-context``. Legacy behavior: ``--legacy-decisions`` (RiskEngine + hybrid + full context rules).

Loads IF + RF + scaler from the main artifact dir; **LightGBM** uses **raw** unified columns
(``build_lgbm_matrix``), never scaled. Optional packaged LGBM under ``models/bundled/`` when enabled.
Writes ``decisions.jsonl`` (or configured log name); ``runtime_summary.json``.
"""

from __future__ import annotations

import argparse
import datetime
import gc
import io
import json
import logging
import os
import sys
import time
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names",
    category=UserWarning,
)

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Shipped binary LGBM + config (same filenames as Stage 1) for resilience when deploy dirs omit LGBM.
PACKAGED_LGBM_FALLBACK_DIR = ROOT / "models" / "bundled"

from ingestion.unified_behavioral_schema import (
    UNIFIED_BEHAVIORAL_FEATURE_NAMES,
    FEATURE_BOUNDS,
    DEFAULT_FILL,
    N_UNIFIED_BEHAVIORAL_FEATURES,
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
    flow_event_sort_key,
)
from models.isolation_forest_model import anomaly_score_to_01
from models.random_forest_model import attack_probability
from models.risk_engine import RiskEngine
from utils.serialization import load_artifacts, load_multiclass_rf
from utils.hybrid_bundle import (
    HYBRID_STAGE02_CONFIG,
    HYBRID_STAGE02_MODEL,
    is_hybrid_bundle,
    load_hybrid_models,
    validate_lgbm_feature_schema,
)
from utils.streaming import TimeBasedByteProgress, create_eve_progress_bar, iter_eve_chunks, iter_eve_tail
from pipeline.stage2_classifier import load_stage2_model

try:
    from inference.context_engine import (
        ContextEngine,
        create_context_engine,
        DEFAULT_DDOS_WINDOW_SECONDS,
        DEFAULT_DDOS_FLOW_THRESHOLD,
        DEFAULT_DDOS_UNIQUE_SRC_THRESHOLD,
        DEFAULT_FANOUT_WINDOW_SECONDS,
        DEFAULT_FANOUT_UNIQUE_PORTS_THRESHOLD,
        DEFAULT_FANOUT_VELOCITY_THRESHOLD,
        DEFAULT_SRC_BURST_WINDOW_SECONDS,
        DEFAULT_SRC_BURST_THRESHOLD,
        DEFAULT_SRC_PORTSCAN_WINDOW_SECONDS,
        DEFAULT_SRC_PORTSCAN_PORTS_THRESHOLD,
        DEFAULT_SRC_DSTFANOUT_WINDOW_SECONDS,
        DEFAULT_SRC_DSTFANOUT_HOSTS_THRESHOLD,
        DEFAULT_SRC_SLOWSCAN_WINDOW_SECONDS,
        DEFAULT_SRC_SLOWSCAN_PORTS_THRESHOLD,
    )
except ImportError:
    try:
        from context_engine import (
            ContextEngine,
            create_context_engine,
            DEFAULT_DDOS_WINDOW_SECONDS,
            DEFAULT_DDOS_FLOW_THRESHOLD,
            DEFAULT_DDOS_UNIQUE_SRC_THRESHOLD,
            DEFAULT_FANOUT_WINDOW_SECONDS,
            DEFAULT_FANOUT_UNIQUE_PORTS_THRESHOLD,
            DEFAULT_FANOUT_VELOCITY_THRESHOLD,
            DEFAULT_SRC_BURST_WINDOW_SECONDS,
            DEFAULT_SRC_BURST_THRESHOLD,
            DEFAULT_SRC_PORTSCAN_WINDOW_SECONDS,
            DEFAULT_SRC_PORTSCAN_PORTS_THRESHOLD,
            DEFAULT_SRC_DSTFANOUT_WINDOW_SECONDS,
            DEFAULT_SRC_DSTFANOUT_HOSTS_THRESHOLD,
            DEFAULT_SRC_SLOWSCAN_WINDOW_SECONDS,
            DEFAULT_SRC_SLOWSCAN_PORTS_THRESHOLD,
        )
    except ImportError:
        ContextEngine = None  # type: ignore
        create_context_engine = None  # type: ignore
        DEFAULT_DDOS_WINDOW_SECONDS = 10.0
        DEFAULT_DDOS_FLOW_THRESHOLD = 100
        DEFAULT_DDOS_UNIQUE_SRC_THRESHOLD = 50
        DEFAULT_FANOUT_WINDOW_SECONDS = 120.0
        DEFAULT_FANOUT_UNIQUE_PORTS_THRESHOLD = 20
        DEFAULT_FANOUT_VELOCITY_THRESHOLD = 0.0
        DEFAULT_SRC_BURST_WINDOW_SECONDS = 20.0
        DEFAULT_SRC_BURST_THRESHOLD = 100
        DEFAULT_SRC_PORTSCAN_WINDOW_SECONDS = 30.0
        DEFAULT_SRC_PORTSCAN_PORTS_THRESHOLD = 20
        DEFAULT_SRC_DSTFANOUT_WINDOW_SECONDS = 60.0
        DEFAULT_SRC_DSTFANOUT_HOSTS_THRESHOLD = 10
        DEFAULT_SRC_SLOWSCAN_WINDOW_SECONDS = 600.0
        DEFAULT_SRC_SLOWSCAN_PORTS_THRESHOLD = 30

try:
    from inference.enforcement_engine import (
        EnforcementEngine,
        create_enforcement_engine,
        DEFAULT_MAX_BLOCKS,
        DEFAULT_BLOCK_TTL_SECONDS,
        DEFAULT_MAX_BLOCKS_PER_MINUTE,
    )
except ImportError:
    try:
        from enforcement_engine import (
            EnforcementEngine,
            create_enforcement_engine,
            DEFAULT_MAX_BLOCKS,
            DEFAULT_BLOCK_TTL_SECONDS,
            DEFAULT_MAX_BLOCKS_PER_MINUTE,
        )
    except ImportError:
        EnforcementEngine = None  # type: ignore
        create_enforcement_engine = None  # type: ignore
        DEFAULT_MAX_BLOCKS = 2000
        DEFAULT_BLOCK_TTL_SECONDS = 600
        DEFAULT_MAX_BLOCKS_PER_MINUTE = 60

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)
logger = logging.getLogger(__name__)

# Default output directory (logs/) and chunk sizes
DEFAULT_OUTPUT_DIR = "logs"
DEFAULT_CSV_CHUNK_SIZE = 100_000
DEFAULT_JSON_CHUNK_SIZE = 50_000
# Thresholds: risk < low -> LOW/ALLOW; low <= risk < high -> MEDIUM/ALERT; risk >= high -> HIGH/BLOCK
DEFAULT_LOW_THRESH = 0.30
DEFAULT_HIGH_THRESH = 0.60
# RF malicious_probability at or above this → HIGH (primary ML path). Anomaly blends below this.
DEFAULT_ML_BLOCK_THRESHOLD = 0.68
# RF probability >= this → MEDIUM/ALERT in ML-first mode (below ml_block_threshold).
DEFAULT_ML_ALERT_THRESHOLD = 0.40
# IF anomaly (stable sigmoid score) above this bumps LOW → MEDIUM when RF is below alert threshold.
DEFAULT_IF_MEDIUM_BOOST_THRESHOLD = 0.8

# IF + LGBM hybrid (raw sklearn IF decision_function; more anomalous → more negative)
DEFAULT_HYBRID_LGBM_ATTACK_THRESHOLD = 0.9
DEFAULT_HYBRID_IF_ANOMALY_THRESHOLD = -0.12

# LGBM-primary production path (non-legacy): IF does not affect action / tiering
LGBM_PRIMARY_FORCE_ALLOW_BELOW = 0.05
LGBM_PRIMARY_ALERT_AT = 0.40
LGBM_PRIMARY_BLOCK_AT = 0.70
LGBM_STAGE2_MIN_PROB = 0.70
DEFAULT_IF_BLOCK_THRESHOLD = 0.80

# Default CLI paths (project root = parent of ``inference/``)
_DEFAULT_RUNTIME_ARTIFACTS_IF = ROOT / "artifacts" / "Saved_models" / "IF"
_DEFAULT_RUNTIME_LGBM_STAGE01 = ROOT / "artifacts" / "Saved_models" / "LGBM_STAGE01"
_DEFAULT_RUNTIME_EVE_INPUT = Path("/var/log/suricata/master_eve.json")


def _wall_clock_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


class _ByteCountingBuffer(io.BufferedIOBase):
    """
    Wraps a binary file and counts bytes read. Used for CSV progress by file size
    without loading the full file. Pass to io.TextIOWrapper then to pd.read_csv.
    """

    def __init__(self, path: Path) -> None:
        self._f = open(path, "rb")
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        data = self._f.read(size)
        self.bytes_read += len(data)
        return data

    def readinto(self, b: Any) -> Optional[int]:
        n = self._f.readinto(b)
        if n is not None:
            self.bytes_read += n
        return n

    def close(self) -> None:
        self._f.close()
        super().close()

    def readable(self) -> bool:
        return True


def decision_to_action(decision: str) -> str:
    if decision == "HIGH":
        return "BLOCK"
    if decision == "MEDIUM":
        return "ALERT"
    return "ALLOW"


def _lgbm_bundle_model_and_config(lgbm_dir: Path) -> Optional[Tuple[Path, Path]]:
    """Return (model_path, config_path) if a known Stage-1 / legacy bundle is present."""
    cfg_p = lgbm_dir / "config.joblib"
    if not cfg_p.is_file():
        return None
    for name in ("lgbm_model.joblib", "lgbm_stage01_model.joblib"):
        mp = lgbm_dir / name
        if mp.is_file():
            return mp, cfg_p
    return None


def resolve_lgbm_artifacts_dir(main_artifacts: Path, explicit: Optional[Path]) -> Optional[Path]:
    """Return directory with a loadable LGBM bundle (legacy ``LGBM/`` or ``LGBM_STAGE01/``), or None."""
    if explicit is not None:
        p = Path(explicit).resolve()
        return p if p.is_dir() else None
    parent = main_artifacts.resolve().parent
    for dirname in ("LGBM", "LGBM_STAGE01"):
        sibling = parent / dirname
        if sibling.is_dir() and _lgbm_bundle_model_and_config(sibling) is not None:
            return sibling
    return None


def load_lgbm_bundle(lgbm_dir: Optional[Path]) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """
    Load optional LightGBM classifier and config. No scaler. Returns (None, None) if dir missing or incomplete.
    Accepts ``lgbm_model.joblib`` (legacy) or ``lgbm_stage01_model.joblib`` (Stage 1 pipeline).
    """
    if lgbm_dir is None or not lgbm_dir.is_dir():
        return None, None
    pair = _lgbm_bundle_model_and_config(lgbm_dir)
    if pair is None:
        logger.warning(
            "LGBM directory %s missing config.joblib and one of lgbm_model.joblib / lgbm_stage01_model.joblib; LGBM disabled.",
            lgbm_dir,
        )
        return None, None
    model_p, cfg_p = pair
    try:
        m = joblib.load(model_p)
        c = joblib.load(cfg_p)
    except Exception as e:
        logger.error("Failed loading LGBM artifacts from %s: %s", lgbm_dir, e)
        return None, None
    if not isinstance(c, dict) or "feature_names" not in c:
        logger.error("LGBM config.joblib must be a dict with 'feature_names'.")
        return None, None
    return m, c


def try_load_lgbm_stage02_sibling(stage01_dir: Optional[Path]) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """
    Load LGBM Stage 2 from ``<parent>/LGBM_STAGE02/`` next to the Stage-1 bundle directory.
    Fails gracefully (returns None, None) on missing files or load errors.
    """
    if stage01_dir is None:
        return None, None
    p = Path(stage01_dir).resolve()
    if not p.is_dir():
        return None, None
    s2_dir = p.parent / "LGBM_STAGE02"
    mp = s2_dir / HYBRID_STAGE02_MODEL
    cp = s2_dir / HYBRID_STAGE02_CONFIG
    if not mp.is_file() or not cp.is_file():
        return None, None
    try:
        m = joblib.load(mp)
        c = joblib.load(cp)
        if not isinstance(c, dict) or "feature_names" not in c:
            logger.warning("LGBM_STAGE02 config invalid at %s; Stage 2 disabled.", s2_dir)
            return None, None
        return m, c
    except Exception as e:
        logger.warning("LGBM Stage 2 load failed (%s): %s", s2_dir, e)
        return None, None


def load_models(
    artifacts_dir: Path,
    lgbm_artifacts_dir: Optional[Path] = None,
    *,
    use_packaged_lgbm_fallback: bool = True,
) -> Tuple[
    Any,
    Any,
    Any,
    Dict,
    List[str],
    Any,
    Any,
    Optional[Any],
    Optional[Dict[str, Any]],
    bool,
    Optional[Any],
    Optional[Dict[str, Any]],
]:
    """
    Load IF, RF, scaler, config, optional multiclass RF, optional Stage-2 RF, LGBM Stage 1, optional LGBM Stage 2.

    Returns (if_model, rf_model, scaler, config, feature_schema, rf_multiclass, stage2_model,
             lgbm_model, lgbm_config, hybrid_if_lgbm_enabled, lgbm_stage2_model, lgbm_stage2_config).

    When ``artifacts_dir`` is a HYBRID bundle (``lgbm_stage01_model.joblib`` + ``lgbm_stage01_config.joblib``
    in the same directory), loads IF + scaler + IF config + Stage 1 + optional Stage 2 from that path.
    """
    artifacts_dir = Path(artifacts_dir).resolve()
    lgbm_stage2_model: Optional[Any] = None
    lgbm_stage2_config: Optional[Dict[str, Any]] = None

    if is_hybrid_bundle(artifacts_dir):
        h = load_hybrid_models(artifacts_dir)
        if_model = h["if_model"]
        rf_model = h["rf_model"]
        scaler = h["scaler"]
        config = h["if_config"]
        if if_model is not None and scaler is None:
            raise RuntimeError("HYBRID bundle: Isolation Forest present but scaler.joblib missing.")
        schema = list(config.get("feature_names", UNIFIED_BEHAVIORAL_FEATURE_NAMES))
        rf_multiclass = load_multiclass_rf(artifacts_dir)
        stage2_model = load_stage2_model(artifacts_dir)
        lgbm_model = h["lgbm_stage01"]
        lgbm_config = h["config_stage01"]
        lgbm_stage2_model = h["lgbm_stage02"]
        lgbm_stage2_config = h["config_stage02"]
        fn1 = list(lgbm_config["feature_names"])
        fn2 = list(lgbm_stage2_config["feature_names"]) if lgbm_stage2_config else None
        validate_lgbm_feature_schema(fn1, fn2, n_unified=N_UNIFIED_BEHAVIORAL_FEATURES)
        hybrid_possible = lgbm_model is not None and if_model is not None
        logger.info(
            "[INFO] HYBRID bundle: IF=yes LGBM_S1=yes LGBM_S2=%s RF=%s",
            "yes" if lgbm_stage2_model is not None else "no",
            "yes" if rf_model is not None else "no",
        )
        return (
            if_model,
            rf_model,
            scaler,
            config,
            schema,
            rf_multiclass,
            stage2_model,
            lgbm_model,
            lgbm_config,
            hybrid_possible,
            lgbm_stage2_model,
            lgbm_stage2_config,
        )

    if_model, rf_model, scaler, config = load_artifacts(artifacts_dir)
    if if_model is not None and scaler is None:
        raise RuntimeError(
            "Isolation Forest is present but scaler.joblib is missing from the artifact bundle. "
            "IF inference requires scaler.transform()."
        )
    schema = list(config.get("feature_names", UNIFIED_BEHAVIORAL_FEATURE_NAMES))
    if scaler is not None and hasattr(scaler, "n_features_in_"):
        nf_s = int(getattr(scaler, "n_features_in_", 0) or 0)
        if nf_s > 0 and len(schema) != nf_s:
            logger.warning(
                "[AUDIT] Scaler n_features_in_=%d != len(bundle feature_names)=%d; verify artifact compatibility.",
                nf_s,
                len(schema),
            )
    rf_multiclass = load_multiclass_rf(artifacts_dir)
    stage2_model = load_stage2_model(artifacts_dir)
    if stage2_model is None:
        logger.info(
            "Stage-2 attack classifier not found in %s or models/; Stage-2 disabled.",
            artifacts_dir,
        )
    else:
        logger.info("Stage-2 attack classifier loaded for artifacts_dir=%s", artifacts_dir)

    lgbm_dir = resolve_lgbm_artifacts_dir(artifacts_dir, lgbm_artifacts_dir)
    lgbm_model, lgbm_config = load_lgbm_bundle(lgbm_dir)
    if lgbm_model is None and use_packaged_lgbm_fallback:
        if (
            PACKAGED_LGBM_FALLBACK_DIR.is_dir()
            and _lgbm_bundle_model_and_config(PACKAGED_LGBM_FALLBACK_DIR) is not None
        ):
            lgbm_model, lgbm_config = load_lgbm_bundle(PACKAGED_LGBM_FALLBACK_DIR)
            if lgbm_model is not None:
                logger.warning(
                    "[AUDIT] Using packaged LGBM fallback from %s (trained LGBM bundle missing or incomplete). "
                    "Deploy LGBM_STAGE01 artifacts for production accuracy.",
                    PACKAGED_LGBM_FALLBACK_DIR,
                )
    hybrid_possible = lgbm_model is not None and if_model is not None
    logger.info("LGBM loaded: %s", "yes" if lgbm_model is not None else "no")
    logger.info("IF loaded: %s", "yes" if if_model is not None else "no")
    logger.info("Hybrid mode (IF+LGBM) available: %s", "yes" if hybrid_possible else "no")

    if lgbm_stage2_model is None and lgbm_model is not None and isinstance(lgbm_config, dict):
        s2_m, s2_c = try_load_lgbm_stage02_sibling(lgbm_dir)
        if s2_m is not None and s2_c is not None:
            try:
                fn1 = list(lgbm_config["feature_names"])
                fn2 = list(s2_c["feature_names"])
                validate_lgbm_feature_schema(fn1, fn2, n_unified=N_UNIFIED_BEHAVIORAL_FEATURES)
                lgbm_stage2_model, lgbm_stage2_config = s2_m, s2_c
                logger.info("LGBM Stage 2 loaded from sibling LGBM_STAGE02")
            except ValueError as ve:
                logger.warning("LGBM Stage 2 sibling present but schema check failed; disabled: %s", ve)

    return (
        if_model,
        rf_model,
        scaler,
        config,
        schema,
        rf_multiclass,
        stage2_model,
        lgbm_model,
        lgbm_config,
        hybrid_possible,
        lgbm_stage2_model,
        lgbm_stage2_config,
    )


def build_lgbm_matrix(
    X_unified: np.ndarray,
    feature_names: List[str],
    unified_names: Optional[List[str]] = None,
) -> np.ndarray:
    """
    Select columns from the full unified feature matrix (row order = unified_names) for LightGBM.
    **No scaling.** Missing names are filled with 0.
    """
    names = unified_names if unified_names is not None else list(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    idx_map = {n: i for i, n in enumerate(names)}
    n = X_unified.shape[0]
    out = np.zeros((n, len(feature_names)), dtype=np.float32)
    for j, name in enumerate(feature_names):
        ii = idx_map.get(name)
        if ii is not None and ii < X_unified.shape[1]:
            out[:, j] = X_unified[:, ii]
    return out


def hybrid_if_lgbm_decision(
    lgbm_prob: float,
    raw_if_score: float,
    thresholds: Dict[str, float],
) -> str:
    """
    Rule layer for IF + LGBM. Uses raw sklearn IsolationForest.decision_function (lower = more anomalous).
    Returns ATTACK | ANOMALY | BENIGN.
    """
    if lgbm_prob > thresholds.get("lgbm_attack", DEFAULT_HYBRID_LGBM_ATTACK_THRESHOLD):
        return "ATTACK"
    if raw_if_score < thresholds.get("if_anomaly", DEFAULT_HYBRID_IF_ANOMALY_THRESHOLD):
        return "ANOMALY"
    return "BENIGN"


def _hybrid_label_to_tier(label: str) -> str:
    if label == "ATTACK":
        return "HIGH"
    if label == "ANOMALY":
        return "MEDIUM"
    return "LOW"


def _tier_rank(tier: str) -> int:
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(tier, 1)


def merge_rf_and_hybrid_tiers(rf_tier: str, hybrid_tier: str) -> str:
    """Prefer the more severe tier (RF and hybrid are independent signals)."""
    return rf_tier if _tier_rank(rf_tier) >= _tier_rank(hybrid_tier) else hybrid_tier


def _log_runtime_parallelism(if_model: Any, rf_model: Any) -> None:
    """Log CPU count and model n_jobs so operators can confirm multi-core usage."""
    cores = os.cpu_count()
    if_nj = getattr(if_model, "n_jobs", None)
    rf_nj = getattr(rf_model, "n_jobs", None) if rf_model is not None else None
    logger.info(
        "Runtime parallelism: CPU cores=%s | IsolationForest.n_jobs=%s | RandomForest.n_jobs=%s",
        cores,
        if_nj,
        rf_nj,
    )
    if rf_model is None:
        logger.info("RandomForest not loaded (HYBRID/LGBM-primary path may use LGBM Stage 1 for P(attack)).")
    elif rf_nj == -1 or (rf_nj is not None and rf_nj > 1):
        logger.info("RandomForest inference will use multiple cores (n_jobs=%s).", rf_nj)
    elif rf_nj is None or rf_nj == 1:
        logger.info(
            "RandomForest inference is single-threaded (n_jobs=%s). Retrain with current code to enable multi-core RF inference.",
            rf_nj,
        )


def _silence_lgbm_runtime() -> None:
    try:
        import warnings

        warnings.filterwarnings("ignore", message=".*No further splits.*")
        import lightgbm as lgb

        lgb.register_logger(lambda _: None)
    except Exception:
        pass


def project_features_to_model_schema(X_full: np.ndarray, model_schema: List[str]) -> np.ndarray:
    """
    Select and order columns from the full unified feature matrix to match saved training `feature_names`.
    Names absent from the current unified row (older models) get column 0; extra unified columns are dropped.
    """
    idx_map = {n: i for i, n in enumerate(UNIFIED_BEHAVIORAL_FEATURE_NAMES)}
    n = X_full.shape[0]
    if n == 0:
        return np.zeros((0, len(model_schema)), dtype=np.float32)
    if (
        X_full.shape[1] == len(model_schema)
        and len(model_schema) == len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
        and all(a == b for a, b in zip(model_schema, UNIFIED_BEHAVIORAL_FEATURE_NAMES))
    ):
        return np.asarray(X_full, dtype=np.float32)
    out = np.zeros((n, len(model_schema)), dtype=np.float32)
    for j, name in enumerate(model_schema):
        ii = idx_map.get(name)
        if ii is not None and ii < X_full.shape[1]:
            out[:, j] = X_full[:, ii]
    return out


def enforce_schema(df: pd.DataFrame, schema: List[str], fill_missing: float = 0.0) -> pd.DataFrame:
    """
    Align DataFrame to saved schema: correct column order, fill missing columns with fill_missing.
    Returns DataFrame with only schema columns, float32 for memory efficiency.
    """
    out = pd.DataFrame(index=df.index)
    for col in schema:
        if col in df.columns:
            out[col] = pd.to_numeric(df[col], errors="coerce").fillna(fill_missing).astype(np.float32)
        else:
            out[col] = np.float32(fill_missing)
    return out


def _build_X_chunk_unified(
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
    sort_deterministic: bool = True,
) -> np.ndarray:
    """Build (n, len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)) matrix from flow events (stateful temporal features)."""
    if not chunk_events:
        return np.empty((0, len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)), dtype=np.float32)
    events = list(chunk_events)
    if sort_deterministic:
        events.sort(key=flow_event_sort_key)
    rows = []
    for ev in events:
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
    return np.array(rows, dtype=np.float32)


def score_chunk(
    X: np.ndarray,
    if_model: Any,
    rf_model: Any,
    scaler: Any,
    engine: RiskEngine,
    low_thresh: float,
    high_thresh: float,
    severity: Optional[np.ndarray] = None,
    ml_block_threshold: Optional[float] = DEFAULT_ML_BLOCK_THRESHOLD,
    ml_alert_threshold: float = DEFAULT_ML_ALERT_THRESHOLD,
    legacy_decisions: bool = False,
    if_medium_boost_threshold: float = DEFAULT_IF_MEDIUM_BOOST_THRESHOLD,
    X_unified: Optional[np.ndarray] = None,
    lgbm_model: Any = None,
    lgbm_feature_names: Optional[List[str]] = None,
    hybrid_if_lgbm: bool = False,
    hybrid_thresholds: Optional[Dict[str, float]] = None,
    lgbm_stage2_model: Any = None,
    lgbm_stage2_config: Optional[Dict[str, Any]] = None,
    if_block_threshold: float = DEFAULT_IF_BLOCK_THRESHOLD,
) -> Tuple[np.ndarray, List[str], List[str], np.ndarray, np.ndarray, List[str], np.ndarray, np.ndarray]:
    """
    Score a chunk: **scaled** features for IF + RF; **raw** unified matrix for LightGBM (no scaler).

    Returns ``(risk_scores, decisions, actions, prob_attack, lgbm_probability,
    lgbm_stage2_attack_type, lgbm_stage2_confidence, anomaly_score_if)``.

    **Non-legacy:** ``risk_scores == lgbm_probability``; tiers and actions follow LGBM only (IF is
    diagnostic via ``anomaly_score_if`` only). Stage 2 runs when ``lgbm_probability >= 0.7``.

    **Legacy:** prior RiskEngine + RF/IF/hybrid behavior.
    """
    X_raw = np.asarray(X, dtype=np.float32)
    n = X_raw.shape[0]
    if if_model is not None and scaler is None:
        raise RuntimeError(
            "Isolation Forest requires scaler.transform(); scaler is missing for this bundle."
        )
    if scaler is not None:
        X_scaled = scaler.transform(X_raw)
    else:
        X_scaled = X_raw

    if_norm_legacy = bool(legacy_decisions)
    raw_if = np.full(n, np.nan, dtype=np.float64)
    if if_model is not None:
        raw_if = np.asarray(if_model.decision_function(X_scaled), dtype=np.float64)
        anom_01 = anomaly_score_to_01(raw_if, legacy_batch_norm=if_norm_legacy)
    else:
        anom_01 = np.zeros(n, dtype=np.float32)

    lgbm_prob = np.zeros(n, dtype=np.float32)
    if lgbm_model is not None and lgbm_feature_names:
        if X_unified is not None and X_unified.shape[0] == n:
            X_lgbm = build_lgbm_matrix(X_unified, lgbm_feature_names)
            X_lgbm_df = pd.DataFrame(X_lgbm, columns=list(lgbm_feature_names))
            proba = lgbm_model.predict_proba(X_lgbm_df)
            if proba.shape[1] >= 2:
                lgbm_prob = np.asarray(proba[:, 1], dtype=np.float32)
        else:
            logger.warning(
                "LGBM is loaded but X_unified is missing or row count mismatch; skipping LGBM for this chunk."
            )

    if rf_model is not None and hasattr(rf_model, "predict_proba"):
        prob_attack = np.asarray(attack_probability(rf_model, X_scaled), dtype=np.float32)
    else:
        prob_attack = np.asarray(lgbm_prob, dtype=np.float32)

    lgbm_s2_types: List[str] = ["unknown"] * n
    lgbm_s2_conf = np.zeros(n, dtype=np.float32)
    stage2_prob_floor = float(ml_alert_threshold) if legacy_decisions else float(LGBM_STAGE2_MIN_PROB)
    if (
        lgbm_stage2_model is not None
        and isinstance(lgbm_stage2_config, dict)
        and lgbm_stage2_config.get("feature_names")
        and X_unified is not None
        and X_unified.shape[0] == n
    ):
        try:
            s2_names = list(lgbm_stage2_config["feature_names"])
            s1_attack_idx = np.nonzero(np.asarray(lgbm_prob, dtype=np.float32) >= stage2_prob_floor)[0]
            if s1_attack_idx.size > 0:
                X_s2_full = build_lgbm_matrix(X_unified, s2_names)
                X_s2 = X_s2_full[s1_attack_idx]
                X_s2_df = pd.DataFrame(X_s2, columns=s2_names)
                p2 = lgbm_stage2_model.predict_proba(X_s2_df)
                classes = lgbm_stage2_config.get("classes")
                if classes is not None and len(classes) == p2.shape[1]:
                    idx = np.argmax(p2, axis=1)
                    confs = np.max(p2, axis=1).astype(np.float32)
                    types_sub = [str(classes[int(i)]) for i in idx]
                else:
                    idx = np.argmax(p2, axis=1)
                    confs = np.max(p2, axis=1).astype(np.float32)
                    types_sub = [str(int(i)) for i in idx]
                for j, pos in enumerate(s1_attack_idx):
                    pi = int(pos)
                    lgbm_s2_types[pi] = types_sub[j]
                    lgbm_s2_conf[pi] = confs[j]
        except Exception as e:
            logger.warning("LGBM Stage 2 scoring failed: %s", e)
    sev = np.asarray(severity, dtype=np.float32).ravel() if severity is not None else np.zeros(n, dtype=np.float32)
    if sev.size != n:
        sev = np.zeros(n, dtype=np.float32)

    if legacy_decisions:
        risk = engine.compute(anom_01, prob_attack, sev)
        if ml_block_threshold is None:
            decisions = [engine.decision(float(r), low_thresh=low_thresh, high_thresh=high_thresh) for r in risk]
        else:
            decisions = []
            risk_adj = np.asarray(risk, dtype=np.float32).copy()
            for i in range(n):
                p = float(prob_attack[i])
                if p >= ml_block_threshold:
                    decisions.append("HIGH")
                    risk_adj[i] = max(float(risk[i]), high_thresh)
                else:
                    r_i = float(risk[i])
                    risk_adj[i] = r_i
                    decisions.append(engine.decision(r_i, low_thresh=low_thresh, high_thresh=high_thresh))
            risk = risk_adj
        thr = hybrid_thresholds or {
            "lgbm_attack": DEFAULT_HYBRID_LGBM_ATTACK_THRESHOLD,
            "if_anomaly": DEFAULT_HYBRID_IF_ANOMALY_THRESHOLD,
        }
        if hybrid_if_lgbm and lgbm_model is not None and if_model is not None:
            for i in range(n):
                lbl = hybrid_if_lgbm_decision(float(lgbm_prob[i]), float(raw_if[i]), thr)
                hybrid_tier = _hybrid_label_to_tier(lbl)
                decisions[i] = merge_rf_and_hybrid_tiers(decisions[i], hybrid_tier)
        actions = [decision_to_action(d) for d in decisions]
    else:
        risk = np.asarray(lgbm_prob, dtype=np.float32).copy()
        prob_attack = risk
        decisions = []
        for i in range(n):
            p = float(lgbm_prob[i])
            if p < LGBM_PRIMARY_FORCE_ALLOW_BELOW:
                decisions.append("LOW")
            elif p >= LGBM_PRIMARY_BLOCK_AT:
                decisions.append("HIGH")
            elif p >= LGBM_PRIMARY_ALERT_AT:
                decisions.append("MEDIUM")
            else:
                decisions.append("LOW")
            # IF anomaly override for LGBM-primary deployments:
            # allow strongly anomalous traffic to be blocked even when LGBM score is lower.
            if float(anom_01[i]) >= float(if_block_threshold):
                decisions[-1] = "HIGH"
        actions = [decision_to_action(d) for d in decisions]

    return (
        risk,
        decisions,
        actions,
        np.asarray(prob_attack, dtype=np.float32),
        lgbm_prob,
        lgbm_s2_types,
        lgbm_s2_conf,
        np.asarray(anom_01, dtype=np.float32),
    )


def write_decisions(
    risk_scores: np.ndarray,
    actions: List[str],
    src_ips: List[str],
    dst_ips: List[str],
    dst_ports: List[int],
    log_path: Path,
    lgbm_probability: np.ndarray,
    lgbm_stage2_attack_type: List[str],
    anomaly_score_if: np.ndarray,
    ml_alert_threshold: float,
    legacy_decisions: bool = False,
    timestamp_iso: Optional[str] = None,
) -> None:
    """
    Append one minimal JSON object per row to ``decisions.jsonl``.

    Non-legacy: ``is_attack`` uses ``LGBM_PRIMARY_ALERT_AT``; ``attack_type`` only when
    ``lgbm_probability >= LGBM_STAGE2_MIN_PROB`` and Stage-2 returned a label.
    ``risk_score`` equals LGBM probability. ``anomaly_score_if`` is IF 0–1 score (logging only).
    """
    ts = timestamp_iso or datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    n = len(risk_scores)
    lgbm_p = np.asarray(lgbm_probability, dtype=np.float32).ravel()
    anom = np.asarray(anomaly_score_if, dtype=np.float32).ravel()
    s2_types = lgbm_stage2_attack_type if lgbm_stage2_attack_type is not None else ["unknown"] * n
    atk_floor = float(ml_alert_threshold) if legacy_decisions else float(LGBM_PRIMARY_ALERT_AT)
    s2_floor = float(ml_alert_threshold) if legacy_decisions else float(LGBM_STAGE2_MIN_PROB)

    with open(log_path, "a", encoding="utf-8") as f:
        for i in range(n):
            src = (src_ips[i] if i < len(src_ips) else "UNKNOWN") or "UNKNOWN"
            dst = (dst_ips[i] if i < len(dst_ips) else "UNKNOWN") or "UNKNOWN"
            dport = int(dst_ports[i]) if i < len(dst_ports) and dst_ports[i] is not None else 0
            lgbm_pi = float(lgbm_p[i]) if i < lgbm_p.size else 0.0
            stage1_is_attack = lgbm_pi >= atk_floor
            s2t = s2_types[i] if i < len(s2_types) else "unknown"
            stage2_label: Optional[str] = None
            if lgbm_pi >= s2_floor and s2t and s2t != "unknown":
                stage2_label = s2t

            act = actions[i] if i < len(actions) else "ALLOW"
            rs = float(lgbm_p[i]) if i < lgbm_p.size else 0.0
            if legacy_decisions and i < len(risk_scores):
                rs = float(risk_scores[i])
            out: Dict[str, Any] = {
                "timestamp": ts,
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": dport,
                "is_attack": bool(stage1_is_attack),
                "confidence": lgbm_pi,
                "risk_score": rs,
                "anomaly_score_if": float(anom[i]) if i < anom.size else 0.0,
                "action": act,
            }
            if stage2_label:
                out["attack_type"] = stage2_label
            f.write(json.dumps(out) + "\n")


def write_context_events(context_events: List[Dict[str, Any]], log_path: Path) -> None:
    """
    Append context engine smart log entries (escalations, distributed_attack) to context_engine_log.jsonl.
    """
    if not context_events:
        return
    with open(log_path, "a", encoding="utf-8") as f:
        for ev in context_events:
            f.write(json.dumps(ev) + "\n")


def cap_context_escalation_without_ml_confidence(
    decisions: List[str],
    actions: List[str],
    mal_prob: np.ndarray,
    ml_block_threshold: float,
    context_can_block: bool,
) -> None:
    """If context escalates to BLOCK but ML probability is below the block threshold, cap at ALERT."""
    if context_can_block:
        return
    for i in range(len(decisions)):
        if decisions[i] == "HIGH" and float(mal_prob[i]) < ml_block_threshold - 1e-9:
            decisions[i] = "MEDIUM"
            actions[i] = "ALERT"


def merge_context_assist_only(
    ml_decisions: List[str],
    ctx_decisions: List[str],
    context_can_block: bool,
    legacy_decisions: bool,
) -> Tuple[List[str], List[str]]:
    """
    Combine ML tier with context_engine output. Context cannot promote LOW→HIGH unless
    ``context_can_block`` or ``legacy_decisions`` (full legacy authority).
    """
    if legacy_decisions or context_can_block:
        d = list(ctx_decisions)
        return d, [decision_to_action(x) for x in d]
    out_d: List[str] = []
    for m, c in zip(ml_decisions, ctx_decisions):
        if m == "HIGH":
            out_d.append("HIGH")
        elif m == "LOW":
            out_d.append("LOW")
        else:
            out_d.append("HIGH" if c == "HIGH" else "MEDIUM")
    return out_d, [decision_to_action(x) for x in out_d]


def apply_enforcement(
    actions: List[str],
    src_ips: List[str],
    enforcement_engine: Optional[Any],
    reason: str = "ml_decision",
    block_timing: Optional[Dict[str, Any]] = None,
) -> None:
    """For each flow with action BLOCK, call enforcement_engine.add_block(src_ip). No-op if engine is None."""
    if enforcement_engine is None:
        return
    for i, action in enumerate(actions):
        if action == "BLOCK" and i < len(src_ips):
            src = (src_ips[i] or "UNKNOWN").strip()
            if src and src != "UNKNOWN":
                if block_timing is not None and not block_timing.get("first_block_logged"):
                    block_timing["first_block_logged"] = True
                    t0 = float(block_timing.get("session_start_perf", time.perf_counter()))
                    elapsed_sec = time.perf_counter() - t0
                    logger.info(
                        "First BLOCK at %s (%.3fs after session start) src=%s",
                        _wall_clock_iso(),
                        elapsed_sec,
                        src,
                    )
                    # Persist timing details for comparison across runs.
                    block_timing["first_block_elapsed_sec"] = round(elapsed_sec, 6)
                    block_timing["first_block_wall_clock_iso"] = _wall_clock_iso()
                    block_timing["first_block_src"] = src
                enforcement_engine.add_block(src, reason=reason)


def update_summary(
    stats: Dict[str, Any],
    risk_scores: np.ndarray,
    decisions: List[str],
    chunk_size: int,
) -> None:
    """
    Update running stats (no accumulation of per-event data).
    """
    n = len(risk_scores)
    stats["total_processed"] = stats.get("total_processed", 0) + n
    stats["sum_risk"] = stats.get("sum_risk", 0.0) + float(np.sum(risk_scores))
    stats["max_risk"] = max(stats.get("max_risk", 0.0), float(np.max(risk_scores)) if n else 0.0)
    for d in decisions:
        stats["count_" + d.lower()] = stats.get("count_" + d.lower(), 0) + 1


def stream_csv_runtime(
    csv_path: Path,
    artifacts_dir: Path,
    output_dir: Path,
    chunk_size: int = DEFAULT_CSV_CHUNK_SIZE,
    low_thresh: float = DEFAULT_LOW_THRESH,
    high_thresh: float = DEFAULT_HIGH_THRESH,
    progress_every_n_chunks: int = 1,
    use_progress: bool = True,
    context_engine: Optional[Any] = None,
    enforcement_engine: Optional[Any] = None,
    ml_block_threshold: Optional[float] = DEFAULT_ML_BLOCK_THRESHOLD,
    ml_alert_threshold: float = DEFAULT_ML_ALERT_THRESHOLD,
    legacy_decisions: bool = False,
    context_can_block: bool = False,
    lgbm_artifacts_dir: Optional[Path] = None,
    hybrid_if_lgbm: bool = True,
    hybrid_thresholds: Optional[Dict[str, float]] = None,
    use_packaged_lgbm_fallback: bool = True,
    if_block_threshold: float = DEFAULT_IF_BLOCK_THRESHOLD,
) -> Dict[str, Any]:
    """
    Stream CSV (CICIDS/CICIoT) in chunks. For each chunk: normalize → enforce_schema → score → write → gc.
    No concatenation of chunks; no global accumulation of predictions.
    Time-based progress (~every 5s) by bytes read when use_progress is True.
    """
    (
        if_model,
        rf_model,
        scaler,
        config,
        schema,
        _rf_multiclass,
        _stage2_rf,
        lgbm_model,
        lgbm_config,
        hybrid_possible,
        lgbm_stage2_model,
        lgbm_stage2_config,
    ) = load_models(
        artifacts_dir,
        lgbm_artifacts_dir=lgbm_artifacts_dir,
        use_packaged_lgbm_fallback=use_packaged_lgbm_fallback,
    )
    logger.info("Base IF artifacts directory: %s", artifacts_dir)
    lgbm_features: Optional[List[str]] = (
        list(lgbm_config["feature_names"])
        if isinstance(lgbm_config, dict) and lgbm_config.get("feature_names")
        else None
    )
    do_hybrid = bool(hybrid_if_lgbm) and hybrid_possible
    logger.info("Hybrid IF+LGBM runtime merge: %s", "enabled" if do_hybrid else "disabled")
    _log_runtime_parallelism(if_model, rf_model)
    if lgbm_stage2_model is not None:
        logger.info("LGBM Stage 2 (multiclass attack_type) loaded")
    weights = config.get("weights") or (0.4, 0.4, 0.2)
    engine = RiskEngine(w1=weights[0], w2=weights[1], w3=weights[2])

    log_path = output_dir / "decisions.jsonl"
    context_log_path = output_dir / "context_engine_log.jsonl"
    for p in (log_path, context_log_path):
        if p.exists():
            p.unlink()
    output_dir.mkdir(parents=True, exist_ok=True)

    stats: Dict[str, Any] = {}
    start_time = time.perf_counter()
    block_timing: Dict[str, Any] = {
        "session_start_perf": start_time,
        "session_start_iso": _wall_clock_iso(),
        "first_block_logged": False,
    }
    logger.info("Runtime scoring session started at %s", block_timing["session_start_iso"])
    chunk_count = 0
    total_bytes = csv_path.stat().st_size

    prog: Optional[TimeBasedByteProgress] = None
    if use_progress:
        prog = TimeBasedByteProgress(
            file_size=total_bytes,
            desc="CSV",
            get_extra=lambda: {
                "events": stats.get("total_processed", 0),
                "events_per_sec": round(
                    stats.get("total_processed", 0) / (time.perf_counter() - start_time), 1
                )
                if (time.perf_counter() - start_time) > 0
                else 0,
            },
        )

    buffer = _ByteCountingBuffer(csv_path)
    text_stream = io.TextIOWrapper(buffer, encoding="utf-8", errors="replace")
    try:
        reader = pd.read_csv(
            text_stream,
            chunksize=chunk_size,
            low_memory=False,
        )
        for chunk_df in reader:
            chunk_count += 1
            n_rows = len(chunk_df)
            src_col = None
            for c in ("Source IP", "Src IP", "src_ip"):
                if c in chunk_df.columns:
                    src_col = c
                    break
            src_ips = chunk_df[src_col].fillna("UNKNOWN").astype(str).tolist() if src_col else ["UNKNOWN"] * n_rows
            dst_col = None
            for c in ("Destination IP", "Dst IP", "dst_ip", "dest_ip"):
                if c in chunk_df.columns:
                    dst_col = c
                    break
            dst_ips = chunk_df[dst_col].fillna("UNKNOWN").astype(str).tolist() if dst_col else ["UNKNOWN"] * n_rows
            dport_col = None
            for c in ("Destination Port", "Dst Port", "dst_port", "dest_port"):
                if c in chunk_df.columns:
                    dport_col = c
                    break
            dst_ports = chunk_df[dport_col].fillna(0).astype(int).tolist() if dport_col else [0] * n_rows

            # Expect CSV to have unified behavioral feature columns (or reindex with 0 fill)
            df_norm = chunk_df.reindex(columns=UNIFIED_BEHAVIORAL_FEATURE_NAMES, fill_value=0.0).astype(np.float32)
            del chunk_df
            if df_norm.empty:
                gc.collect()
                if prog is not None:
                    prog.update(min(buffer.bytes_read, total_bytes), stats.get("total_processed", 0))
                continue

            X_full = np.asarray(df_norm.values, dtype=np.float32)
            del df_norm
            if X_full.size == 0:
                gc.collect()
                if prog is not None:
                    prog.update(min(buffer.bytes_read, total_bytes), stats.get("total_processed", 0))
                continue

            X = project_features_to_model_schema(X_full, schema)
            (
                risk,
                decisions,
                actions,
                mal_prob,
                lgbm_prob,
                lgbm_s2_types,
                lgbm_s2_conf,
                anomaly_score_if,
            ) = score_chunk(
                X,
                if_model,
                rf_model,
                scaler,
                engine,
                low_thresh,
                high_thresh,
                None,
                ml_block_threshold=ml_block_threshold,
                ml_alert_threshold=ml_alert_threshold,
                legacy_decisions=legacy_decisions,
                X_unified=X_full,
                lgbm_model=lgbm_model,
                lgbm_feature_names=lgbm_features,
                hybrid_if_lgbm=do_hybrid,
                hybrid_thresholds=hybrid_thresholds,
                lgbm_stage2_model=lgbm_stage2_model,
                lgbm_stage2_config=lgbm_stage2_config,
                if_block_threshold=if_block_threshold,
            )
            ml_decisions = list(decisions)
            ml_actions = list(actions)
            context_events_csv: List[Dict[str, Any]] = []
            if context_engine is not None:
                ctx_decisions, _, context_events_csv = context_engine.update_and_escalate(
                    src_ips,
                    dst_ips,
                    dst_ports,
                    risk.tolist(),
                    ml_decisions,
                    ml_actions,
                    None,
                    low_thresh,
                    high_thresh,
                )
                if legacy_decisions:
                    decisions = ctx_decisions
                    actions = [decision_to_action(d) for d in decisions]
                    if ml_block_threshold is not None:
                        cap_context_escalation_without_ml_confidence(
                            decisions, actions, mal_prob, ml_block_threshold, context_can_block
                        )
                else:
                    decisions, actions = merge_context_assist_only(
                        ml_decisions, ctx_decisions, context_can_block, legacy_decisions
                    )
                    cap_context_escalation_without_ml_confidence(
                        decisions, actions, mal_prob, float(LGBM_PRIMARY_BLOCK_AT), context_can_block
                    )
                write_context_events(context_events_csv, context_log_path)
            write_decisions(
                risk,
                actions,
                src_ips,
                dst_ips,
                dst_ports,
                log_path,
                lgbm_probability=lgbm_prob,
                lgbm_stage2_attack_type=lgbm_s2_types,
                anomaly_score_if=anomaly_score_if,
                ml_alert_threshold=ml_alert_threshold,
                legacy_decisions=legacy_decisions,
            )
            apply_enforcement(actions, src_ips, enforcement_engine, block_timing=block_timing)
            update_summary(stats, risk, decisions, chunk_size)

            if prog is not None:
                prog.update(min(buffer.bytes_read, total_bytes), stats.get("total_processed", 0))
            elif progress_every_n_chunks and chunk_count % progress_every_n_chunks == 0:
                total = stats.get("total_processed", 0)
                avg_r = (stats.get("sum_risk", 0) / total) if total else 0.0
                high_c = stats.get("count_high", 0)
                logger.info(
                    "Processed %d events | Avg risk %.4f | HIGH count %d",
                    total, avg_r, high_c,
                )

            del X, X_full, risk, decisions, actions, src_ips, dst_ips, dst_ports, context_events_csv
            del mal_prob, lgbm_prob, lgbm_s2_types, lgbm_s2_conf, anomaly_score_if
            gc.collect()
    finally:
        text_stream.close()
        if prog is not None:
            prog.close()

    elapsed = time.perf_counter() - start_time
    total = stats.get("total_processed", 0)
    stats["duration_sec"] = round(elapsed, 2)
    stats["throughput_events_per_sec"] = round(total / elapsed, 2) if elapsed > 0 else 0
    stats["avg_risk"] = round(stats.get("sum_risk", 0) / total, 4) if total else 0.0
    # Add first-block detection latency (if any) to the final stats.
    stats["first_block_elapsed_sec"] = block_timing.get("first_block_elapsed_sec")
    stats["first_block_wall_clock_iso"] = block_timing.get("first_block_wall_clock_iso")
    stats["first_block_src"] = block_timing.get("first_block_src")
    return stats


def stream_json_runtime(
    eve_path: Path,
    artifacts_dir: Path,
    output_dir: Path,
    chunk_size: int = DEFAULT_JSON_CHUNK_SIZE,
    low_thresh: float = DEFAULT_LOW_THRESH,
    high_thresh: float = DEFAULT_HIGH_THRESH,
    progress_every_n_chunks: int = 1,
    event_type_filter: Optional[str] = None,
    use_progress: bool = True,
    context_engine: Optional[Any] = None,
    enforcement_engine: Optional[Any] = None,
    ml_block_threshold: Optional[float] = DEFAULT_ML_BLOCK_THRESHOLD,
    ml_alert_threshold: float = DEFAULT_ML_ALERT_THRESHOLD,
    legacy_decisions: bool = False,
    context_can_block: bool = False,
    lgbm_artifacts_dir: Optional[Path] = None,
    hybrid_if_lgbm: bool = True,
    hybrid_thresholds: Optional[Dict[str, float]] = None,
    use_packaged_lgbm_fallback: bool = True,
    if_block_threshold: float = DEFAULT_IF_BLOCK_THRESHOLD,
) -> Dict[str, Any]:
    """
    Stream Suricata eve.json in chunks (never load full file). For each chunk: normalize → enforce_schema → score → write → gc.
    Time-based progress (~every 5s) by bytes read when use_progress is True.
    """
    (
        if_model,
        rf_model,
        scaler,
        config,
        schema,
        _rf_multiclass,
        _stage2_rf,
        lgbm_model,
        lgbm_config,
        hybrid_possible,
        lgbm_stage2_model,
        lgbm_stage2_config,
    ) = load_models(
        artifacts_dir,
        lgbm_artifacts_dir=lgbm_artifacts_dir,
        use_packaged_lgbm_fallback=use_packaged_lgbm_fallback,
    )
    logger.info("Base IF artifacts directory: %s", artifacts_dir)
    lgbm_features: Optional[List[str]] = (
        list(lgbm_config["feature_names"])
        if isinstance(lgbm_config, dict) and lgbm_config.get("feature_names")
        else None
    )
    do_hybrid = bool(hybrid_if_lgbm) and hybrid_possible
    logger.info("Hybrid IF+LGBM runtime merge: %s", "enabled" if do_hybrid else "disabled")
    _log_runtime_parallelism(if_model, rf_model)
    if lgbm_stage2_model is not None:
        logger.info("LGBM Stage 2 (multiclass attack_type) loaded")
    weights = config.get("weights") or (0.4, 0.4, 0.2)
    engine = RiskEngine(w1=weights[0], w2=weights[1], w3=weights[2])
    behavioral = BehavioralExtractorUnified()
    tls_tracker = TLSBehaviorTracker(window_sec=WINDOW_60_SEC)
    tcp_tracker = TCPFlagEntropyTracker(window_sec=WINDOW_60_SEC)
    dst_var_tracker = DstPortVariance300Tracker()
    iat_var_300 = FlowInterarrivalVariance300Tracker()
    dst_unique_src_60 = DstUniqueSrcIps60Tracker()
    src_flow_300 = SrcFlowCount300Tracker()
    temporal = SrcIpTemporalTracker()
    sanity = SanityCheck(UNIFIED_BEHAVIORAL_FEATURE_NAMES, FEATURE_BOUNDS, DEFAULT_FILL)
    logger.info(
        "Using unified behavioral schema (%d features)",
        len(UNIFIED_BEHAVIORAL_FEATURE_NAMES),
    )

    log_path = output_dir / "decisions.jsonl"
    context_log_path = output_dir / "context_engine_log.jsonl"
    for p in (log_path, context_log_path):
        if p.exists():
            p.unlink()
    output_dir.mkdir(parents=True, exist_ok=True)

    stats: Dict[str, Any] = {}
    start_time = time.perf_counter()
    block_timing: Dict[str, Any] = {
        "session_start_perf": start_time,
        "session_start_iso": _wall_clock_iso(),
        "first_block_logged": False,
    }
    logger.info("Runtime scoring session started at %s", block_timing["session_start_iso"])
    chunk_count = 0
    # Mutable state for progress callback (bytes_read, events_processed)
    progress_state: List[int] = [0, 0]

    def get_postfix() -> Dict[str, Any]:
        elapsed = time.perf_counter() - start_time
        events = progress_state[1]
        rate = round(events / elapsed, 1) if elapsed > 0 else 0
        return {"events": events, "events/s": rate}

    pbar, progress_callback = create_eve_progress_bar(
        eve_path,
        desc="eve.json",
        chunk_size=chunk_size,
        use_tqdm=use_progress,
        get_postfix=get_postfix,
    )

    def combined_callback(b: int, e: int) -> None:
        progress_state[0], progress_state[1] = b, e
        if progress_callback is not None:
            progress_callback(b, e)

    try:
        for chunk_events in iter_eve_chunks(
            eve_path,
            chunk_size=chunk_size,
            event_type_filter=event_type_filter,
            progress_callback=combined_callback,
        ):
            chunk_count += 1
            chunk_list = list(chunk_events)
            chunk_list.sort(key=flow_event_sort_key)
            src_ips = [str(ev.get("src_ip") or "UNKNOWN") for ev in chunk_list]
            dst_ips = [str(ev.get("dest_ip") or "UNKNOWN") for ev in chunk_list]
            dst_ports = [int(ev.get("dest_port") or 0) for ev in chunk_list]
            timestamps = [ev.get("timestamp") for ev in chunk_list]

            X_full = _build_X_chunk_unified(
                chunk_list,
                behavioral,
                sanity,
                tls_tracker,
                tcp_tracker,
                dst_var_tracker,
                iat_var_300,
                dst_unique_src_60,
                src_flow_300,
                temporal,
                sort_deterministic=True,
            )
            del chunk_events, chunk_list
            if X_full.size == 0:
                gc.collect()
                continue

            X = project_features_to_model_schema(X_full, schema)
            (
                risk,
                decisions,
                actions,
                mal_prob,
                lgbm_prob,
                lgbm_s2_types,
                lgbm_s2_conf,
                anomaly_score_if,
            ) = score_chunk(
                X,
                if_model,
                rf_model,
                scaler,
                engine,
                low_thresh,
                high_thresh,
                None,
                ml_block_threshold=ml_block_threshold,
                ml_alert_threshold=ml_alert_threshold,
                legacy_decisions=legacy_decisions,
                X_unified=X_full,
                lgbm_model=lgbm_model,
                lgbm_feature_names=lgbm_features,
                hybrid_if_lgbm=do_hybrid,
                hybrid_thresholds=hybrid_thresholds,
                lgbm_stage2_model=lgbm_stage2_model,
                lgbm_stage2_config=lgbm_stage2_config,
                if_block_threshold=if_block_threshold,
            )
            ml_decisions = list(decisions)
            ml_actions = list(actions)
            context_events_json: List[Dict[str, Any]] = []
            if context_engine is not None:
                ctx_decisions, _, context_events_json = context_engine.update_and_escalate(
                    src_ips,
                    dst_ips,
                    dst_ports,
                    risk.tolist(),
                    ml_decisions,
                    ml_actions,
                    timestamps,
                    low_thresh,
                    high_thresh,
                )
                if legacy_decisions:
                    decisions = ctx_decisions
                    actions = [decision_to_action(d) for d in decisions]
                    if ml_block_threshold is not None:
                        cap_context_escalation_without_ml_confidence(
                            decisions, actions, mal_prob, ml_block_threshold, context_can_block
                        )
                else:
                    decisions, actions = merge_context_assist_only(
                        ml_decisions, ctx_decisions, context_can_block, legacy_decisions
                    )
                    cap_context_escalation_without_ml_confidence(
                        decisions, actions, mal_prob, float(LGBM_PRIMARY_BLOCK_AT), context_can_block
                    )
                write_context_events(context_events_json, context_log_path)
            write_decisions(
                risk,
                actions,
                src_ips,
                dst_ips,
                dst_ports,
                log_path,
                lgbm_probability=lgbm_prob,
                lgbm_stage2_attack_type=lgbm_s2_types,
                anomaly_score_if=anomaly_score_if,
                ml_alert_threshold=ml_alert_threshold,
                legacy_decisions=legacy_decisions,
            )
            apply_enforcement(actions, src_ips, enforcement_engine, block_timing=block_timing)
            update_summary(stats, risk, decisions, chunk_size)

            if pbar is None and progress_every_n_chunks and chunk_count % progress_every_n_chunks == 0:
                total = stats.get("total_processed", 0)
                avg_r = (stats.get("sum_risk", 0) / total) if total else 0.0
                high_c = stats.get("count_high", 0)
                logger.info(
                    "Processed %d events | Avg risk %.4f | HIGH count %d",
                    total, avg_r, high_c,
                )

            del X, X_full, risk, decisions, actions, src_ips, dst_ips, dst_ports, context_events_json
            del mal_prob, lgbm_prob, lgbm_s2_types, lgbm_s2_conf, anomaly_score_if
            gc.collect()

    finally:
        if pbar is not None:
            pbar.close()

    elapsed = time.perf_counter() - start_time
    total = stats.get("total_processed", 0)
    stats["duration_sec"] = round(elapsed, 2)
    stats["throughput_events_per_sec"] = round(total / elapsed, 2) if elapsed > 0 else 0
    stats["avg_risk"] = round(stats.get("sum_risk", 0) / total, 4) if total else 0.0
    # Add first-block detection latency (if any) to the final stats.
    stats["first_block_elapsed_sec"] = block_timing.get("first_block_elapsed_sec")
    stats["first_block_wall_clock_iso"] = block_timing.get("first_block_wall_clock_iso")
    stats["first_block_src"] = block_timing.get("first_block_src")
    return stats


def stream_json_tail_runtime(
    eve_path: Path,
    artifacts_dir: Path,
    output_dir: Path,
    chunk_size: int = 50,
    low_thresh: float = DEFAULT_LOW_THRESH,
    high_thresh: float = DEFAULT_HIGH_THRESH,
    event_type_filter: Optional[str] = "flow",
    context_engine: Optional[Any] = None,
    enforcement_engine: Optional[Any] = None,
    expire_blocks_interval_sec: float = 60.0,
    ml_block_threshold: Optional[float] = DEFAULT_ML_BLOCK_THRESHOLD,
    ml_alert_threshold: float = DEFAULT_ML_ALERT_THRESHOLD,
    legacy_decisions: bool = False,
    context_can_block: bool = False,
    lgbm_artifacts_dir: Optional[Path] = None,
    hybrid_if_lgbm: bool = True,
    hybrid_thresholds: Optional[Dict[str, float]] = None,
    use_packaged_lgbm_fallback: bool = True,
    if_block_threshold: float = DEFAULT_IF_BLOCK_THRESHOLD,
) -> None:
    """
    Real-time tail of eve.json: read new lines continuously, run ML + ContextEngine + enforcement.
    Runs until KeyboardInterrupt. Does not load the full file; processes events as they arrive.
    """
    (
        if_model,
        rf_model,
        scaler,
        config,
        schema,
        _rf_multiclass,
        _stage2_rf,
        lgbm_model,
        lgbm_config,
        hybrid_possible,
        lgbm_stage2_model,
        lgbm_stage2_config,
    ) = load_models(
        artifacts_dir,
        lgbm_artifacts_dir=lgbm_artifacts_dir,
        use_packaged_lgbm_fallback=use_packaged_lgbm_fallback,
    )
    logger.info("Base IF artifacts directory: %s", artifacts_dir)
    lgbm_features: Optional[List[str]] = (
        list(lgbm_config["feature_names"])
        if isinstance(lgbm_config, dict) and lgbm_config.get("feature_names")
        else None
    )
    do_hybrid = bool(hybrid_if_lgbm) and hybrid_possible
    logger.info("Hybrid IF+LGBM runtime merge: %s", "enabled" if do_hybrid else "disabled")
    _log_runtime_parallelism(if_model, rf_model)
    if lgbm_stage2_model is not None:
        logger.info("LGBM Stage 2 (multiclass attack_type) loaded")
    weights = config.get("weights") or (0.4, 0.4, 0.2)
    engine = RiskEngine(w1=weights[0], w2=weights[1], w3=weights[2])
    behavioral = BehavioralExtractorUnified()
    tls_tracker = TLSBehaviorTracker(window_sec=WINDOW_60_SEC)
    tcp_tracker = TCPFlagEntropyTracker(window_sec=WINDOW_60_SEC)
    dst_var_tracker = DstPortVariance300Tracker()
    iat_var_300 = FlowInterarrivalVariance300Tracker()
    dst_unique_src_60 = DstUniqueSrcIps60Tracker()
    src_flow_300 = SrcFlowCount300Tracker()
    temporal = SrcIpTemporalTracker()
    sanity = SanityCheck(UNIFIED_BEHAVIORAL_FEATURE_NAMES, FEATURE_BOUNDS, DEFAULT_FILL)
    logger.info(
        "Using unified behavioral schema (%d features)",
        len(UNIFIED_BEHAVIORAL_FEATURE_NAMES),
    )

    log_path = output_dir / "decisions.jsonl"
    context_log_path = output_dir / "context_engine_log.jsonl"
    output_dir.mkdir(parents=True, exist_ok=True)
    # Start with a fresh log so old data from a previous run (e.g. different eve.json) doesn't appear
    for p in (log_path, context_log_path):
        if p.exists():
            p.unlink()

    stats: Dict[str, Any] = {"total_processed": 0, "count_low": 0, "count_medium": 0, "count_high": 0}
    last_expire = time.perf_counter()
    block_timing: Dict[str, Any] = {
        "session_start_perf": time.perf_counter(),
        "session_start_iso": _wall_clock_iso(),
        "first_block_logged": False,
    }
    logger.info("Runtime scoring session started at %s", block_timing["session_start_iso"])
    logger.info("Tailing %s (chunk_size=%s); Ctrl+C to stop", eve_path, chunk_size)
    try:
        for chunk_events in iter_eve_tail(
            eve_path,
            chunk_size=chunk_size,
            event_type_filter=event_type_filter,
            sleep_empty=0.1,
            flush_interval_sec=1.0,
        ):
            if not chunk_events:
                continue
            chunk_list = list(chunk_events)
            chunk_list.sort(key=flow_event_sort_key)
            src_ips = [str(ev.get("src_ip") or "UNKNOWN") for ev in chunk_list]
            dst_ips = [str(ev.get("dest_ip") or "UNKNOWN") for ev in chunk_list]
            dst_ports = [int(ev.get("dest_port") or 0) for ev in chunk_list]
            timestamps = [ev.get("timestamp") for ev in chunk_list]

            X_full = _build_X_chunk_unified(
                chunk_list,
                behavioral,
                sanity,
                tls_tracker,
                tcp_tracker,
                dst_var_tracker,
                iat_var_300,
                dst_unique_src_60,
                src_flow_300,
                temporal,
                sort_deterministic=True,
            )
            del chunk_events, chunk_list
            if X_full.size == 0:
                gc.collect()
                continue

            X = project_features_to_model_schema(X_full, schema)
            (
                risk,
                decisions,
                actions,
                mal_prob,
                lgbm_prob,
                lgbm_s2_types,
                lgbm_s2_conf,
                anomaly_score_if,
            ) = score_chunk(
                X,
                if_model,
                rf_model,
                scaler,
                engine,
                low_thresh,
                high_thresh,
                None,
                ml_block_threshold=ml_block_threshold,
                ml_alert_threshold=ml_alert_threshold,
                legacy_decisions=legacy_decisions,
                X_unified=X_full,
                lgbm_model=lgbm_model,
                lgbm_feature_names=lgbm_features,
                hybrid_if_lgbm=do_hybrid,
                hybrid_thresholds=hybrid_thresholds,
                lgbm_stage2_model=lgbm_stage2_model,
                lgbm_stage2_config=lgbm_stage2_config,
                if_block_threshold=if_block_threshold,
            )
            ml_decisions = list(decisions)
            ml_actions = list(actions)
            context_events_tail: List[Dict[str, Any]] = []
            if context_engine is not None:
                ctx_decisions, _, context_events_tail = context_engine.update_and_escalate(
                    src_ips,
                    dst_ips,
                    dst_ports,
                    risk.tolist(),
                    ml_decisions,
                    ml_actions,
                    timestamps,
                    low_thresh,
                    high_thresh,
                )
                if legacy_decisions:
                    decisions = ctx_decisions
                    actions = [decision_to_action(d) for d in decisions]
                    if ml_block_threshold is not None:
                        cap_context_escalation_without_ml_confidence(
                            decisions, actions, mal_prob, ml_block_threshold, context_can_block
                        )
                else:
                    decisions, actions = merge_context_assist_only(
                        ml_decisions, ctx_decisions, context_can_block, legacy_decisions
                    )
                    cap_context_escalation_without_ml_confidence(
                        decisions, actions, mal_prob, float(LGBM_PRIMARY_BLOCK_AT), context_can_block
                    )
                write_context_events(context_events_tail, context_log_path)
            write_decisions(
                risk,
                actions,
                src_ips,
                dst_ips,
                dst_ports,
                log_path,
                lgbm_probability=lgbm_prob,
                lgbm_stage2_attack_type=lgbm_s2_types,
                anomaly_score_if=anomaly_score_if,
                ml_alert_threshold=ml_alert_threshold,
                legacy_decisions=legacy_decisions,
            )
            apply_enforcement(actions, src_ips, enforcement_engine, block_timing=block_timing)
            update_summary(stats, risk, decisions, chunk_size)

            if enforcement_engine is not None and (time.perf_counter() - last_expire) >= expire_blocks_interval_sec:
                n = enforcement_engine.expire_blocks()
                if n:
                    logger.info("Expired %d block(s)", n)
                last_expire = time.perf_counter()

            del X, X_full, risk, decisions, actions, src_ips, dst_ips, dst_ports, context_events_tail
            del mal_prob, lgbm_prob, lgbm_s2_types, lgbm_s2_conf, anomaly_score_if
            gc.collect()
    except KeyboardInterrupt:
        logger.info("Tail stopped by user")
        # Write block timing so you can compare detection latency across runs.
        try:
            out = dict(block_timing)
            out["tail_stopped_iso"] = _wall_clock_iso()
            (output_dir / "block_timing.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
            logger.info("Block timing written to %s", output_dir / "block_timing.json")
        except Exception:
            logger.exception("Failed writing block_timing.json")
    return None


def write_runtime_summary(stats: Dict[str, Any], output_dir: Path) -> None:
    """Write runtime_summary.json with total_processed, counts per decision, avg/max risk, duration, throughput."""
    summary = {
        "total_processed": stats.get("total_processed", 0),
        "count_low": stats.get("count_low", 0),
        "count_medium": stats.get("count_medium", 0),
        "count_high": stats.get("count_high", 0),
        "avg_risk": stats.get("avg_risk", 0.0),
        "max_risk": stats.get("max_risk", 0.0),
        "duration_sec": stats.get("duration_sec", 0.0),
        "throughput_events_per_sec": stats.get("throughput_events_per_sec", 0.0),
        "first_block_elapsed_sec": stats.get("first_block_elapsed_sec"),
        "first_block_wall_clock_iso": stats.get("first_block_wall_clock_iso"),
        "first_block_src": stats.get("first_block_src"),
    }
    path = output_dir / "runtime_summary.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    logger.info("Runtime summary written to %s", path)


def main() -> int:
    _silence_lgbm_runtime()
    parser = argparse.ArgumentParser(
        description="Production runtime scoring: chunked, memory-safe, persisted logs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--artifacts",
        "--artifacts-dir",
        type=Path,
        default=_DEFAULT_RUNTIME_ARTIFACTS_IF,
        dest="artifacts",
        help="Directory with IF+scaler+RF (legacy) or HYBRID bundle (IF + LGBM Stage1 + optional Stage2 joblibs)",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=_DEFAULT_RUNTIME_EVE_INPUT,
        help="Path to CSV (CIC) or eve.json (Suricata)",
    )
    parser.add_argument("--output-dir", type=Path, default=Path(DEFAULT_OUTPUT_DIR), help="Output directory for logs and summary")
    parser.add_argument("--format", choices=("auto", "csv", "json"), default="auto", help="Input format (auto = infer from extension)")
    parser.add_argument("--chunk-size", type=int, default=None, help="Chunk size (default: 100000 CSV, 50000 JSON)")
    parser.add_argument("--low", type=float, default=DEFAULT_LOW_THRESH, help="Risk threshold below = LOW (ALLOW)")
    parser.add_argument("--high", type=float, default=DEFAULT_HIGH_THRESH, help="Risk threshold above = HIGH (BLOCK)")
    parser.add_argument("--progress-every", type=int, default=10, metavar="N", help="Log progress every N chunks when progress bar disabled (0 = disable)")
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable time-based stderr progress (~every 5s); use --progress-every for chunk log lines when off",
    )
    parser.add_argument(
        "--use-context",
        action="store_true",
        help="Enable context correlation (off by default; does nothing if --no-context / --disable-context)",
    )
    parser.add_argument(
        "--no-context",
        action="store_true",
        help="Disable context correlation layer (per-IP escalation); same as --disable-context",
    )
    parser.add_argument(
        "--disable-context",
        action="store_true",
        help="Kill switch: no context engine, escalation, context_signals, or context_engine_log events",
    )
    parser.add_argument("--context-max-entries", type=int, default=100_000, metavar="N", help="Max IPs in context store (LRU eviction)")
    parser.add_argument("--context-window-sec", type=float, default=600, metavar="SEC", help="Sliding window length in seconds (e.g. 600 = 10 min)")
    parser.add_argument("--context-ttl-sec", type=float, default=3600, metavar="SEC", help="TTL for inactive IPs in seconds (e.g. 3600 = 1 hr)")
    parser.add_argument("--context-escalate-min", type=int, default=3, metavar="N", help="Min MEDIUM/HIGH events in window to escalate to HIGH")
    parser.add_argument("--ddos-window-sec", type=float, default=DEFAULT_DDOS_WINDOW_SECONDS, metavar="SEC", help="Sliding window (sec) for DDoS aggregation")
    parser.add_argument("--ddos-flow-threshold", type=int, default=DEFAULT_DDOS_FLOW_THRESHOLD, metavar="N", help="Flows per dst_ip in window to consider DDoS")
    parser.add_argument("--ddos-unique-src-threshold", type=int, default=DEFAULT_DDOS_UNIQUE_SRC_THRESHOLD, metavar="N", help="Unique src_ips per dst_ip in window for DDoS")
    parser.add_argument("--fanout-window-sec", type=float, default=DEFAULT_FANOUT_WINDOW_SECONDS, metavar="SEC", help="Sliding window (sec) for destination port fan-out (recon)")
    parser.add_argument("--fanout-ports-threshold", type=int, default=DEFAULT_FANOUT_UNIQUE_PORTS_THRESHOLD, metavar="N", help="Unique dst_ports per dst_ip in window to trigger fan-out escalation (0=disable)")
    parser.add_argument("--fanout-velocity-threshold", type=float, default=DEFAULT_FANOUT_VELOCITY_THRESHOLD, metavar="RATE", help="Min ports/sec for fan-out (0=ignore velocity)")
    parser.add_argument("--src-burst-window-sec", type=float, default=DEFAULT_SRC_BURST_WINDOW_SECONDS, metavar="SEC", help="Window (sec) for source flow-burst detection (0=disable)")
    parser.add_argument("--src-burst-threshold", type=int, default=DEFAULT_SRC_BURST_THRESHOLD, metavar="N", help="Flows per src_ip in burst window to escalate (0=disable)")
    parser.add_argument("--src-portscan-window-sec", type=float, default=DEFAULT_SRC_PORTSCAN_WINDOW_SECONDS, metavar="SEC", help="Window (sec) for source port-scan detection (0=disable)")
    parser.add_argument("--src-portscan-ports-threshold", type=int, default=DEFAULT_SRC_PORTSCAN_PORTS_THRESHOLD, metavar="N", help="Unique dst_ports per src_ip in window to escalate (0=disable)")
    parser.add_argument("--src-dstfanout-window-sec", type=float, default=DEFAULT_SRC_DSTFANOUT_WINDOW_SECONDS, metavar="SEC", help="Window (sec) for source host-sweep detection (0=disable)")
    parser.add_argument("--src-dstfanout-hosts-threshold", type=int, default=DEFAULT_SRC_DSTFANOUT_HOSTS_THRESHOLD, metavar="N", help="Unique dst_ips per src_ip in window to escalate (0=disable)")
    parser.add_argument("--src-slowscan-window-sec", type=float, default=DEFAULT_SRC_SLOWSCAN_WINDOW_SECONDS, metavar="SEC", help="Window (sec) for slow-scan detection (0=disable)")
    parser.add_argument("--src-slowscan-ports-threshold", type=int, default=DEFAULT_SRC_SLOWSCAN_PORTS_THRESHOLD, metavar="N", help="Unique dst_ports per src_ip in slow-scan window to escalate (0=disable)")
    parser.add_argument(
        "--no-tail",
        action="store_true",
        help="Batch-process JSON instead of tailing (default: tail eve.json when input is JSON)",
    )
    parser.add_argument(
        "--tail",
        action="store_true",
        help="Same as default for JSON; kept for backward compatibility",
    )
    parser.add_argument("--enforcement", type=str, default="stub", choices=("stub", "iptables", "nftables"), help="Enforcement backend for BLOCK decisions (stub=log only)")
    parser.add_argument("--no-enforcement", action="store_true", help="Disable enforcement; do not call firewall even on BLOCK")
    parser.add_argument("--block-ttl-sec", type=float, default=DEFAULT_BLOCK_TTL_SECONDS, metavar="SEC", help="Block expiry in seconds (0=no expiry)")
    parser.add_argument("--max-blocks", type=int, default=DEFAULT_MAX_BLOCKS, metavar="N", help="Max number of IPs to block at once")
    parser.add_argument("--max-blocks-per-min", type=int, default=DEFAULT_MAX_BLOCKS_PER_MINUTE, metavar="N", help="Rate limit: max new blocks per minute (0=unlimited)")
    parser.add_argument(
        "--ml-block-threshold",
        type=float,
        default=DEFAULT_ML_BLOCK_THRESHOLD,
        metavar="P",
        help="Legacy only: RF/LGBM prob threshold for context cap and legacy ML merge. LGBM-primary uses fixed 0.7/0.4/0.05.",
    )
    parser.add_argument(
        "--ml-alert-threshold",
        type=float,
        default=DEFAULT_ML_ALERT_THRESHOLD,
        metavar="P",
        help="Legacy only: threshold for is_attack / Stage-2 floor in legacy mode. LGBM-primary uses 0.4 / 0.7.",
    )
    parser.add_argument(
        "--legacy-decisions",
        action="store_true",
        help="Legacy mode: RiskEngine risk + batch-normalized IF; context full authority + RF cap rules.",
    )
    parser.add_argument(
        "--context-can-block",
        action="store_true",
        help="Allow context escalation to BLOCK even when RF probability is below --ml-block-threshold (default: context capped to MEDIUM unless ML is confident).",
    )
    parser.add_argument(
        "--lgbm-artifacts",
        type=Path,
        default=_DEFAULT_RUNTIME_LGBM_STAGE01,
        help="Directory with Stage-1 LGBM joblibs. Sibling LGBM_STAGE02/ is used for multiclass when present.",
    )
    parser.add_argument(
        "--no-packaged-lgbm-fallback",
        action="store_true",
        help="Do not load models/bundled LGBM when trained artifacts are missing (LGBM stays disabled).",
    )
    parser.add_argument(
        "--no-hybrid-if-lgbm",
        action="store_true",
        help="Do not merge IF+LGBM hybrid tiers; LGBM still runs for logs when loaded.",
    )
    parser.add_argument(
        "--hybrid-lgbm-attack",
        type=float,
        default=DEFAULT_HYBRID_LGBM_ATTACK_THRESHOLD,
        metavar="P",
        help="Hybrid: LGBM P(attack) > P => ATTACK tier (merged with RF).",
    )
    parser.add_argument(
        "--hybrid-if-anomaly",
        type=float,
        default=DEFAULT_HYBRID_IF_ANOMALY_THRESHOLD,
        metavar="S",
        help="Hybrid: raw IF decision_function < S => ANOMALY tier (lower/more negative = more anomalous).",
    )
    parser.add_argument(
        "--if-block-threshold",
        type=float,
        default=DEFAULT_IF_BLOCK_THRESHOLD,
        metavar="A",
        help="LGBM-primary: force BLOCK when anomaly_score_if >= A (0-1). Ignored in --legacy-decisions mode.",
    )
    args = parser.parse_args()
    ml_bt: Optional[float] = None if args.legacy_decisions else float(args.ml_block_threshold)
    ctx_can_block = bool(args.legacy_decisions or args.context_can_block)
    lgbm_artifacts_cli = Path(args.lgbm_artifacts).resolve()
    hybrid_thresholds_main: Dict[str, float] = {
        "lgbm_attack": float(args.hybrid_lgbm_attack),
        "if_anomaly": float(args.hybrid_if_anomaly),
    }
    hybrid_if_lgbm_flag = bool(args.legacy_decisions) and (not bool(args.no_hybrid_if_lgbm))
    use_packaged_lgbm_fallback = not bool(args.no_packaged_lgbm_fallback)

    if args.legacy_decisions:
        logger.info(
            "Decision mode: legacy (RiskEngine + per-batch IF norm; context may escalate; cap uses --ml-block-threshold if set)"
        )
    else:
        logger.info(
            "Decision mode: LGBM-primary | BLOCK>=%.2f ALERT>=%.2f force-ALLOW<%.2f | IF log-only | context default off (--use-context to enable)",
            LGBM_PRIMARY_BLOCK_AT,
            LGBM_PRIMARY_ALERT_AT,
            LGBM_PRIMARY_FORCE_ALLOW_BELOW,
        )
        logger.info("IF anomaly override in LGBM-primary: BLOCK when anomaly_score_if >= %.2f", float(args.if_block_threshold))

    if not args.artifacts.exists():
        logger.error("Artifacts directory not found: %s", args.artifacts)
        return 1
    if not args.input.exists():
        logger.error("Input not found: %s", args.input)
        return 1

    fmt = args.format
    if fmt == "auto":
        fmt = "json" if args.input.suffix.lower() in (".json", ".jsonl") else "csv"

    tail_enabled = fmt == "json" and (not args.no_tail or bool(args.tail))
    if tail_enabled:
        if args.input.suffix.lower() not in (".json", ".jsonl"):
            logger.error("Tail mode requires JSON input (eve.json); got %s", args.input)
            return 1

    chunk_size = args.chunk_size
    if chunk_size is None:
        chunk_size = DEFAULT_JSON_CHUNK_SIZE if fmt == "json" else DEFAULT_CSV_CHUNK_SIZE

    args.output_dir.mkdir(parents=True, exist_ok=True)

    use_progress = not args.no_progress
    context_disabled = bool(args.no_context or args.disable_context)
    if bool(args.use_context) and context_disabled:
        logger.warning("--use-context ignored because context is disabled (--no-context / --disable-context)")
    context_engine = None
    if bool(args.use_context) and not context_disabled and create_context_engine is not None:
        context_engine = create_context_engine(
            enabled=True,
            window_seconds=args.context_window_sec,
            ttl_seconds=args.context_ttl_sec,
            max_entries=args.context_max_entries,
            escalate_min_events=args.context_escalate_min,
            ddos_window_seconds=args.ddos_window_sec,
            ddos_flow_threshold=args.ddos_flow_threshold,
            ddos_unique_src_threshold=args.ddos_unique_src_threshold,
            fanout_window_seconds=args.fanout_window_sec,
            fanout_unique_ports_threshold=args.fanout_ports_threshold,
            fanout_velocity_threshold=args.fanout_velocity_threshold,
            src_burst_window_seconds=args.src_burst_window_sec,
            src_burst_threshold=args.src_burst_threshold,
            src_portscan_window_seconds=args.src_portscan_window_sec,
            src_portscan_ports_threshold=args.src_portscan_ports_threshold,
            src_dstfanout_window_seconds=args.src_dstfanout_window_sec,
            src_dstfanout_hosts_threshold=args.src_dstfanout_hosts_threshold,
            src_slowscan_window_seconds=args.src_slowscan_window_sec,
            src_slowscan_ports_threshold=args.src_slowscan_ports_threshold,
        )
        logger.info(
            "Context correlation enabled: max_entries=%s, window=%ss, ttl=%ss, escalate_min=%s; ddos=%ss; fanout=%ss; src_burst=%ss/%s, src_portscan=%ss/%s, src_dstfanout=%ss/%s, src_slowscan=%ss/%s",
            args.context_max_entries, args.context_window_sec, args.context_ttl_sec, args.context_escalate_min,
            args.ddos_window_sec, args.fanout_window_sec,
            args.src_burst_window_sec, args.src_burst_threshold,
            args.src_portscan_window_sec, args.src_portscan_ports_threshold,
            args.src_dstfanout_window_sec, args.src_dstfanout_hosts_threshold,
            args.src_slowscan_window_sec, args.src_slowscan_ports_threshold,
        )
    elif context_disabled:
        logger.info(
            "Context correlation disabled (%s)",
            "--disable-context" if args.disable_context else "--no-context",
        )
    else:
        logger.info("Context correlation off (default); pass --use-context to enable.")

    enforcement_engine = None
    if not args.no_enforcement and create_enforcement_engine is not None:
        enforcement_engine = create_enforcement_engine(
            backend=args.enforcement,
            max_blocks=args.max_blocks,
            block_ttl_seconds=args.block_ttl_sec,
            max_blocks_per_minute=args.max_blocks_per_min,
            enabled=True,
        )
        if enforcement_engine is not None:
            logger.info(
                "Enforcement enabled: backend=%s max_blocks=%s block_ttl_sec=%s max_per_min=%s",
                args.enforcement, args.max_blocks, args.block_ttl_sec, args.max_blocks_per_min,
            )
    elif args.no_enforcement:
        logger.info("Enforcement disabled (--no-enforcement)")

    try:
        if tail_enabled:
            stream_json_tail_runtime(
                args.input,
                args.artifacts,
                args.output_dir,
                chunk_size=min(chunk_size, 100),
                low_thresh=args.low,
                high_thresh=args.high,
                event_type_filter="flow",
                context_engine=context_engine,
                enforcement_engine=enforcement_engine,
                expire_blocks_interval_sec=60.0,
                ml_block_threshold=ml_bt,
                ml_alert_threshold=float(args.ml_alert_threshold),
                legacy_decisions=bool(args.legacy_decisions),
                context_can_block=ctx_can_block,
                lgbm_artifacts_dir=lgbm_artifacts_cli,
                hybrid_if_lgbm=hybrid_if_lgbm_flag,
                hybrid_thresholds=hybrid_thresholds_main,
                use_packaged_lgbm_fallback=use_packaged_lgbm_fallback,
                if_block_threshold=float(args.if_block_threshold),
            )
            return 0
        if fmt == "csv":
            stats = stream_csv_runtime(
                args.input,
                args.artifacts,
                args.output_dir,
                chunk_size=chunk_size,
                low_thresh=args.low,
                high_thresh=args.high,
                progress_every_n_chunks=args.progress_every or None,
                use_progress=use_progress,
                context_engine=context_engine,
                enforcement_engine=enforcement_engine,
                ml_block_threshold=ml_bt,
                ml_alert_threshold=float(args.ml_alert_threshold),
                legacy_decisions=bool(args.legacy_decisions),
                context_can_block=ctx_can_block,
                lgbm_artifacts_dir=lgbm_artifacts_cli,
                hybrid_if_lgbm=hybrid_if_lgbm_flag,
                hybrid_thresholds=hybrid_thresholds_main,
                use_packaged_lgbm_fallback=use_packaged_lgbm_fallback,
                if_block_threshold=float(args.if_block_threshold),
            )
        else:
            stats = stream_json_runtime(
                args.input,
                args.artifacts,
                args.output_dir,
                chunk_size=chunk_size,
                low_thresh=args.low,
                high_thresh=args.high,
                progress_every_n_chunks=args.progress_every or None,
                event_type_filter=None,
                use_progress=use_progress,
                context_engine=context_engine,
                enforcement_engine=enforcement_engine,
                ml_block_threshold=ml_bt,
                ml_alert_threshold=float(args.ml_alert_threshold),
                legacy_decisions=bool(args.legacy_decisions),
                context_can_block=ctx_can_block,
                lgbm_artifacts_dir=lgbm_artifacts_cli,
                hybrid_if_lgbm=hybrid_if_lgbm_flag,
                hybrid_thresholds=hybrid_thresholds_main,
                use_packaged_lgbm_fallback=use_packaged_lgbm_fallback,
                if_block_threshold=float(args.if_block_threshold),
            )
        write_runtime_summary(stats, args.output_dir)
        logger.info(
            "Done. Total %d | LOW %d MEDIUM %d HIGH %d | Avg risk %.4f | %.2f events/s",
            stats.get("total_processed", 0),
            stats.get("count_low", 0), stats.get("count_medium", 0), stats.get("count_high", 0),
            stats.get("avg_risk", 0), stats.get("throughput_events_per_sec", 0),
        )
        return 0
    except Exception as e:
        logger.exception("Runtime scoring failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
