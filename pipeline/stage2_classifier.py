#!/usr/bin/env python3
"""
Stage-2 attack family classifier wrapper.

This module is intentionally lightweight:
- Loads a RandomForestClassifier from the artifacts directory used for runtime
  (preferred) or from models/stage2_attack_classifier.joblib (fallback).
- Provides batch and single-row prediction helpers.
- Never influences firewall decisions (used only for logging / telemetry).

If the model file is missing or fails to load, the helpers return None/empty
and callers must treat Stage-2 as disabled.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parent.parent

_STAGE2_MODEL: Optional[Any] = None


def load_stage2_model(artifacts_dir: Path) -> Optional[Any]:
    """
    Load the Stage-2 RandomForest attack classifier once and cache it.

    Lookup order:
      1. <artifacts_dir>/stage2_attack_classifier.joblib
      2. models/stage2_attack_classifier.joblib (project-level fallback)

    Returns the model or None if no file exists or loading fails.
    """
    global _STAGE2_MODEL
    if _STAGE2_MODEL is not None:
        return _STAGE2_MODEL

    # Preferred: per-artifacts directory model
    primary = artifacts_dir / "stage2_attack_classifier.joblib"
    candidates = [primary, ROOT / "models" / "stage2_attack_classifier.joblib"]

    for path in candidates:
        if not path.exists():
            continue
        try:
            _STAGE2_MODEL = joblib.load(path)
            return _STAGE2_MODEL
        except Exception:
            _STAGE2_MODEL = None

    return None


def _normalize_label(label: Any) -> Optional[str]:
    """Best-effort string normalization for attack family labels."""
    if label is None:
        return None
    s = str(label).strip()
    return s or None


def predict_attack_family_batch(model: Any, X: np.ndarray) -> List[Optional[str]]:
    """
    Predict attack family for a batch of feature vectors.

    Parameters
    ----------
    model : fitted RandomForestClassifier or compatible estimator
    X : np.ndarray of shape (n_samples, n_features)

    Returns
    -------
    List[Optional[str]]: one label per row; None when prediction is unavailable.
    """
    if model is None:
        return [None] * int(X.shape[0])

    X = np.asarray(X)
    if X.ndim != 2 or X.shape[0] == 0:
        return []

    try:
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X)
            idx = np.argmax(proba, axis=1)
            raw_labels = [model.classes_[i] for i in idx]
        else:
            raw_labels = list(model.predict(X))
    except Exception:
        return [None] * int(X.shape[0])

    return [_normalize_label(lab) for lab in raw_labels]


def predict_attack_family(model: Any, features: np.ndarray) -> Optional[str]:
    """
    Convenience wrapper for single-row prediction.
    """
    features = np.asarray(features, dtype=float).reshape(1, -1)
    fams = predict_attack_family_batch(model, features)
    return fams[0] if fams else None

