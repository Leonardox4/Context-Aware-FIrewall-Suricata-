"""
Isolation Forest for anomaly detection. Train on benign traffic only.
Output: normalized anomaly score in [0, 1] (higher = more anomalous).

Feature input: vectors from ingestion.unified_behavioral_schema (UNIFIED_BEHAVIORAL_FEATURE_NAMES).
"""

from sklearn.ensemble import IsolationForest
import numpy as np


def build_isolation_forest(contamination=0.1, n_estimators=100, random_state=42):
    return IsolationForest(
        contamination=contamination,
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
    )


def anomaly_score_to_01(decision_scores, legacy_batch_norm: bool = True):
    """
    Map IsolationForest decision_function output to [0, 1] with higher = more anomalous.

    sklearn: more anomalous → *lower* decision_function. We invert with -s before sigmoid.

    Parameters
    ----------
    legacy_batch_norm : bool, default True
        If True, min–max normalize within the batch (legacy; unstable for chunk size 1 / --tail).
        If False, per-sample sigmoid(-score): stable streaming, same row → same score regardless of batch.
    """
    s = np.asarray(decision_scores, dtype=np.float64)
    if s.size == 0:
        return s.astype(np.float32)
    if legacy_batch_norm:
        smin, smax = s.min(), s.max()
        if smax <= smin:
            return np.zeros(s.shape, dtype=np.float32)
        return ((smax - s) / (smax - smin)).astype(np.float32)
    raw = np.clip(-s, -50.0, 50.0)
    out = 1.0 / (1.0 + np.exp(-raw))
    return out.astype(np.float32)
