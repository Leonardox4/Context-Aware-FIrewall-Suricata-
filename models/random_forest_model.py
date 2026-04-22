"""
Random Forest for attack classification. Train on labeled behavioral feature vectors with balanced class weights.
Output: probability of attack class (0-1).

Feature input: vectors from ingestion.unified_behavioral_schema (UNIFIED_BEHAVIORAL_FEATURE_NAMES).
"""

from sklearn.ensemble import RandomForestClassifier
import numpy as np


def build_random_forest(n_estimators=100, max_depth=12, class_weight="balanced", random_state=42):
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight=class_weight,
        random_state=random_state,
        n_jobs=-1,
    )


def attack_probability(model, X):
    """Return P(attack) = proba for class 1."""
    proba = model.predict_proba(X)
    if proba.shape[1] < 2:
        return np.zeros(len(X))
    return proba[:, 1]


def multiclass_predict(model, X, class_names):
    """
    Run multiclass RF: returns (attack_types, confidences).
    attack_types: list of str (class name per row); confidences: np.ndarray max proba per row.
    If model or class_names invalid, returns (["benign"]*n, zeros).
    """
    if model is None or not hasattr(model, "predict_proba"):
        n = X.shape[0] if hasattr(X, "shape") else len(X)
        return ["benign"] * n, np.zeros(n, dtype=np.float32)
    proba = model.predict_proba(X)
    if proba.size == 0:
        return [], np.array([], dtype=np.float32)
    idx = np.argmax(proba, axis=1)
    confidences = np.max(proba, axis=1).astype(np.float32)
    if hasattr(model, "classes_") and model.classes_ is not None and len(model.classes_) == proba.shape[1]:
        names = [str(model.classes_[i]) for i in idx]
    elif class_names and len(class_names) == proba.shape[1]:
        names = [class_names[i] for i in idx]
    else:
        names = [str(i) for i in idx]
    return names, confidences
