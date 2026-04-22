"""
Save/load models and scaler with joblib.
"""

import joblib
from pathlib import Path


def save_artifacts(if_model, rf_model, scaler, config, path_dir):
    path_dir = Path(path_dir)
    path_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(if_model, path_dir / "isolation_forest.joblib")
    # RF is optional in LGBM-primary deployments.
    if rf_model is not None:
        joblib.dump(rf_model, path_dir / "random_forest.joblib")
    joblib.dump(scaler, path_dir / "scaler.joblib")
    joblib.dump(config, path_dir / "config.joblib")


def load_artifacts(path_dir):
    path_dir = Path(path_dir)
    if_model = joblib.load(path_dir / "isolation_forest.joblib")
    rf_path = path_dir / "random_forest.joblib"
    rf_model = joblib.load(rf_path) if rf_path.exists() else None
    scaler = joblib.load(path_dir / "scaler.joblib")
    config = joblib.load(path_dir / "config.joblib")
    return if_model, rf_model, scaler, config


def load_multiclass_rf(path_dir):
    """
    Load optional multiclass Random Forest (attack type: benign, bot, backdoor, dos, ddos, bruteforce, scan).
    Returns None if rf_multiclass.joblib is not present (pipeline runs without attack_type/attack_confidence).
    """
    path_dir = Path(path_dir)
    p = path_dir / "rf_multiclass.joblib"
    if not p.exists():
        return None
    return joblib.load(p)


# Canonical class order for multiclass RF (must match training)
MULTICLASS_ATTACK_TYPES = ["benign", "bot", "backdoor", "dos", "ddos", "bruteforce", "scan"]
