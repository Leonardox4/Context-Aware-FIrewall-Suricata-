#!/usr/bin/env python3
"""
Train Stage-2 attack family classifier (multiclass RandomForest) for logging/telemetry.

This script trains a RandomForestClassifier that predicts high-level attack
families (Bot, Backdoor, DoS, DDoS, Bruteforce, Recon, WebAttacks) using the
same feature vector and scaler as the Stage-1 binary RF/IF pipeline.

The resulting model is saved as models/stage2_attack_classifier.joblib and is
used ONLY for Stage-2 logging in the runtime pipeline. It does NOT influence
firewall decisions.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

# Ensure Model2_development project root is on path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.serialization import load_artifacts
from utils.logging import log

# Reuse the existing streaming + join logic so features match Stage-1 exactly.
from training.Randomforest_training_pipeline import _join_flows_with_labels, _prepare_labels_csv  # type: ignore


FAMILIES: List[str] = ["Bot", "Backdoor", "DoS", "DDoS", "Bruteforce", "Recon", "WebAttacks"]


def _default_family_map(attack_subclass: str) -> Optional[str]:
    """
    Heuristic mapping from attack_subclass/attack_type string to one of the 7 Stage-2 families.

    If we cannot map, return None and the row will be dropped from Stage-2 training.
    """
    s = (attack_subclass or "").strip().lower()
    if not s or s in ("benign", "none", "unknown", "normal"):
        return None
    if "bot" in s:
        return "Bot"
    if "backdoor" in s:
        return "Backdoor"
    if "ddos" in s:
        return "DDoS"
    # check "dos" after "ddos"
    if "dos" in s:
        return "DoS"
    if "brute" in s or "bruteforce" in s or "ssh" in s or "ftp" in s:
        return "Bruteforce"
    if "recon" in s or "scan" in s or "portscan" in s or "sweep" in s:
        return "Recon"
    if "web" in s or "sql" in s or "xss" in s or "injection" in s:
        return "WebAttacks"
    return None


def _load_custom_map(path: Path) -> Dict[str, str]:
    """
    Load a JSON mapping file: { "raw_attack_type": "Family", ... }.
    Keys are matched case-insensitively after strip().
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("family map JSON must be an object/dict")
    out: Dict[str, str] = {}
    for k, v in data.items():
        kk = str(k).strip().lower()
        vv = str(v).strip()
        if vv not in FAMILIES:
            raise ValueError(f"Invalid family {vv!r} for key {k!r}. Must be one of: {FAMILIES}")
        out[kk] = vv
    return out


def _map_family(raw: Any, custom: Optional[Dict[str, str]]) -> Optional[str]:
    s = str(raw).strip()
    if not s:
        return None
    if custom is not None:
        hit = custom.get(s.lower())
        if hit is not None:
            return hit
    return _default_family_map(s)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Train Stage-2 attack family RandomForestClassifier (logging-only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--eve", type=Path, required=True, help="Path to labeled Suricata eve.json (JSONL, flow events).")
    p.add_argument("--labels-csv", type=Path, required=True, help="Path to labels CSV (binary_label + attack_subclass/attack_type).")
    p.add_argument(
        "--artifacts-in",
        type=Path,
        required=True,
        help="Artifacts directory containing scaler + config (feature_names). Must match runtime Stage-1 schema.",
    )
    p.add_argument(
        "--features-parquet",
        type=Path,
        default=None,
        help="Optional cached Parquet from RF feature builder (contains binary_label and attack_subclass).",
    )
    p.add_argument("--rebuild-features", action="store_true", help="Rebuild Parquet even if it exists.")
    p.add_argument(
        "--output-model",
        type=Path,
        default=(ROOT / "models" / "stage2_attack_classifier.joblib"),
        help="Where to save the trained Stage-2 model.",
    )
    p.add_argument(
        "--family-map-json",
        type=Path,
        default=None,
        help="Optional JSON mapping from raw attack_subclass/attack_type → family.",
    )
    p.add_argument("--seed", type=int, default=42, help="Random seed.")
    p.add_argument("--n-estimators", type=int, default=300, help="RF trees.")
    p.add_argument("--max-depth", type=int, default=None, help="RF max depth (None = unlimited).")
    p.add_argument("--min-attack-samples", type=int, default=1000, help="Minimum labeled attack rows required to train Stage-2.")
    p.add_argument(
        "--force-python-extract",
        action="store_true",
        help="Use Python feature extraction instead of required Rust eve_extractor (slow).",
    )
    args = p.parse_args()

    if not args.eve.exists():
        log(f"--eve not found: {args.eve}", level="ERROR")
        return 1
    if not args.labels_csv.exists():
        log(f"--labels-csv not found: {args.labels_csv}", level="ERROR")
        return 1
    if not args.artifacts_in.exists():
        log(f"--artifacts-in not found: {args.artifacts_in}", level="ERROR")
        return 1

    custom_map = _load_custom_map(args.family_map_json) if args.family_map_json else None

    # Load artifacts to get scaler + schema (feature_names)
    if_model, rf_model, scaler, config = load_artifacts(args.artifacts_in)
    schema = list(config.get("feature_names") or [])
    if not schema:
        log("Artifacts config missing feature_names; cannot align features.", level="ERROR")
        return 1
    log(f"Stage-2 training using Stage-1 schema length={len(schema)}")

    # Build or load features parquet (same as RF training pipeline)
    feats_path: Path
    if args.features_parquet is not None:
        feats_path = args.features_parquet
    else:
        feats_path = args.output_model.parent / "stage2_dataset.parquet"
    if feats_path.exists() and not args.rebuild_features:
        log(f"Loading cached features parquet: {feats_path}")
    else:
        log(f"Building features parquet for Stage-2: {feats_path}")
        labels_df, tol = _prepare_labels_csv(args.labels_csv, time_tolerance=1.0)
        _join_flows_with_labels(
            args.eve,
            labels_df,
            tol,
            max_events=None,
            chunk_size=50_000,
            output_parquet_path=feats_path,
            force_python_extract=args.force_python_extract,
        )

    feats_df = pd.read_parquet(feats_path)
    if "binary_label" not in feats_df.columns:
        log("Feature parquet missing binary_label; cannot train Stage-2.", level="ERROR")
        return 1
    if "attack_subclass" not in feats_df.columns:
        log(
            "Feature parquet missing attack_subclass. Stage-2 needs attack_type/attack_subclass labels.\n"
            "Fix: ensure labels CSV has an 'attack_type' column (will be normalized to attack_subclass), "
            "or add 'attack_subclass' directly.",
            level="ERROR",
        )
        return 1

    # Stage-2 trains ONLY on attacks (binary_label==1)
    df_att = feats_df.loc[feats_df["binary_label"].astype(int) == 1].copy()
    if df_att.empty:
        log("No attack rows (binary_label==1) found; cannot train Stage-2.", level="ERROR")
        return 1

    df_att["family"] = df_att["attack_subclass"].map(lambda x: _map_family(x, custom_map))
    before = len(df_att)
    df_att = df_att.loc[~df_att["family"].isna()].copy()
    dropped = before - len(df_att)
    if dropped:
        log(f"Dropped {dropped} attack rows with unmapped attack_subclass (provide --family-map-json to map them).", level="WARN")

    if len(df_att) < args.min_attack_samples:
        log(
            f"Not enough mapped attack samples for Stage-2: {len(df_att)} < {args.min_attack_samples}.",
            level="ERROR",
        )
        return 1

    # Global shuffle to break up long contiguous runs (clumped families) before split
    df_att = df_att.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    # X must align with schema exactly (same as runtime Stage-1)
    X = df_att.reindex(columns=schema, fill_value=0.0).astype(np.float64).values
    y = df_att["family"].astype(str).values

    # Stage-1 pipeline uses scaled features; train Stage-2 on the same scaled space.
    X_scaled = scaler.transform(X)

    # Ensure sklearn compatibility when pandas uses Arrow-backed columns.
    # Both X_scaled and y must be plain NumPy arrays before train_test_split.
    if hasattr(X_scaled, "to_numpy"):
        X_scaled = X_scaled.to_numpy()
    if hasattr(y, "to_numpy"):
        y = y.to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled,
        y,
        test_size=0.2,
        stratify=y,
        random_state=args.seed,
    )
    log(f"Stage-2 train/test split: {len(y_train)} train, {len(y_test)} test")

    clf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        random_state=args.seed,
        n_jobs=-1,
        max_depth=args.max_depth,
        class_weight="balanced_subsample",
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    log("=== Stage-2 Attack Family Evaluation (held-out) ===")
    log("Classes: " + ", ".join(list(clf.classes_)))
    log("Confusion matrix:\n" + str(confusion_matrix(y_test, y_pred, labels=clf.classes_)))
    log("\n" + classification_report(y_test, y_pred, labels=clf.classes_, zero_division=0))

    args.output_model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, args.output_model)
    log(f"Saved Stage-2 model to {args.output_model}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

