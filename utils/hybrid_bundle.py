"""
Load a unified HYBRID deployment directory: IF + scaler + LGBM Stage 1 + optional Stage 2.

Expected layout (``artifacts/Saved_models/HYBRID/``)::

  isolation_forest.joblib
  scaler.joblib
  IF_config.joblib          # or config.joblib
  random_forest.joblib      # optional; placeholder OK for LGBM-primary hybrid
  lgbm_stage01_model.joblib
  lgbm_stage01_config.joblib
  lgbm_stage02_model.joblib # optional
  lgbm_stage02_config.joblib
"""

from __future__ import annotations

import joblib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ingestion.unified_behavioral_schema import UNIFIED_BEHAVIORAL_FEATURE_NAMES


HYBRID_STAGE01_MODEL = "lgbm_stage01_model.joblib"
HYBRID_STAGE01_CONFIG = "lgbm_stage01_config.joblib"
HYBRID_STAGE02_MODEL = "lgbm_stage02_model.joblib"
HYBRID_STAGE02_CONFIG = "lgbm_stage02_config.joblib"
IF_CONFIG_CANDIDATES = ("IF_config.joblib", "config.joblib")


def is_hybrid_bundle(path: Path) -> bool:
    p = Path(path)
    if not p.is_dir():
        return False
    s1 = p / HYBRID_STAGE01_MODEL
    c1 = p / HYBRID_STAGE01_CONFIG
    return s1.is_file() and c1.is_file()


def _load_if_config(p: Path) -> Dict[str, Any]:
    for name in IF_CONFIG_CANDIDATES:
        fp = p / name
        if fp.is_file():
            return joblib.load(fp)
    raise FileNotFoundError(f"No IF config in {p} (tried {IF_CONFIG_CANDIDATES})")


def load_hybrid_models(path: Path) -> Dict[str, Any]:
    """
    Load all components from a HYBRID directory.

    Returns dict with keys:
      if_model, scaler, if_config, rf_model (optional),
      lgbm_stage01, config_stage01, lgbm_stage02 (optional), config_stage02 (optional).
    """
    p = Path(path).resolve()
    if not p.is_dir():
        raise NotADirectoryError(str(p))

    if_model = joblib.load(p / "isolation_forest.joblib")
    scaler = joblib.load(p / "scaler.joblib")
    if_config = _load_if_config(p)

    rf_path = p / "random_forest.joblib"
    rf_model = joblib.load(rf_path) if rf_path.is_file() else None

    lgbm_stage01 = joblib.load(p / HYBRID_STAGE01_MODEL)
    config_stage01 = joblib.load(p / HYBRID_STAGE01_CONFIG)
    if not isinstance(config_stage01, dict) or "feature_names" not in config_stage01:
        raise ValueError("lgbm_stage01_config.joblib must be a dict with feature_names")

    lgbm_stage02 = None
    config_stage02 = None
    m2 = p / HYBRID_STAGE02_MODEL
    c2 = p / HYBRID_STAGE02_CONFIG
    if m2.is_file() and c2.is_file():
        lgbm_stage02 = joblib.load(m2)
        config_stage02 = joblib.load(c2)
        if not isinstance(config_stage02, dict) or "feature_names" not in config_stage02:
            raise ValueError("lgbm_stage02_config.joblib must be a dict with feature_names")

    return {
        "if_model": if_model,
        "scaler": scaler,
        "if_config": if_config,
        "rf_model": rf_model,
        "lgbm_stage01": lgbm_stage01,
        "config_stage01": config_stage01,
        "lgbm_stage02": lgbm_stage02,
        "config_stage02": config_stage02,
    }


def validate_lgbm_feature_schema(
    names_a: List[str],
    names_b: Optional[List[str]],
    *,
    n_unified: int,
) -> None:
    if len(names_a) != n_unified:
        raise ValueError(f"LGBM Stage 1 expects {n_unified} features, config has {len(names_a)}")
    canonical = list(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    for i, (a, b) in enumerate(zip(names_a, canonical)):
        if a != b:
            raise ValueError(
                f"LGBM feature_names must match unified schema order; mismatch at index {i}: {a!r} != {b!r}"
            )
    if names_b is not None and names_a != names_b:
        raise ValueError("LGBM Stage 1 and Stage 2 feature_names differ; align training exports.")
