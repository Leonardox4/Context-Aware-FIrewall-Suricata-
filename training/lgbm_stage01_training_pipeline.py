#!/usr/bin/env python3
"""
LightGBM Stage 1 — binary detection (benign vs attack) on cached behavioral Parquet.
If ``--dataset`` is JSONL, the script auto-materializes a parquet cache first.

Raw features only (no scaling). GroupShuffleSplit on identity_key / flow_key / src_ip.
Post-train audits (GroupKFold, shuffle, weak model, noise, drop-top-features, uniqueness,
separability) run by default; use ``--skip-audit`` to disable.

Usage::

  python -m training.lgbm_stage01_training_pipeline
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from training.lgbm_audit_utils import (
    LGBM_QUIET_KWARGS,
    run_binary_post_train_audits,
    silence_lightgbm,
)

silence_lightgbm()

LABEL_COL = "binary_label"
META_DROP_STAGE01 = (
    "binary_label",
    "attack_subclass",
    "attack_type",
    "identity_key",
    "flow_key",
)
DEFAULT_DATASET = ROOT / "artifacts/Cached_Training_Dataset/rf_training_dataset.parquet"
DEFAULT_OUTPUT_DIR = ROOT / "artifacts/Saved_models/LGBM_STAGE01"
MODEL_FILENAME = "lgbm_stage01_model.joblib"
CONFIG_FILENAME = "config.joblib"
N_UNIFIED_EXPECT = 39


def _log(msg: str, *, audit: bool = False) -> None:
    prefix = "[AUDIT]" if audit else "[INFO]"
    print(f"{prefix} {msg}", file=sys.stderr, flush=True)


def _parse_drop_features(s: Optional[str]) -> List[str]:
    if not s or not str(s).strip():
        return []
    return [c.strip() for c in str(s).split(",") if c.strip()]


def _build_Xy_stage01(
    df: pd.DataFrame,
    *,
    extra_drop: Sequence[str],
) -> Tuple[pd.DataFrame, pd.Series]:
    if LABEL_COL not in df.columns:
        raise ValueError(f"Dataset must contain label column {LABEL_COL!r}.")
    drop_x = [c for c in META_DROP_STAGE01 if c in df.columns] + [c for c in extra_drop if c in df.columns]
    y = df[LABEL_COL].astype(int)
    X = df.drop(columns=drop_x, errors="ignore")
    if X.shape[1] == 0:
        raise ValueError("No feature columns left after dropping label and metadata columns.")
    return X, y


def _resolve_groups(df: pd.DataFrame) -> Tuple[np.ndarray, str]:
    for col in ("identity_key", "flow_key", "src_ip"):
        if col not in df.columns:
            continue
        s = df[col].astype(str).str.strip()
        if s.nunique() >= 2:
            return s.values, col
    _log(
        "No identity_key / flow_key / src_ip with ≥2 distinct values; using row index as group.",
        audit=True,
    )
    return np.arange(len(df), dtype=np.int64), "row_index"


def _audit_group_overlap(groups: np.ndarray, train_idx: np.ndarray, test_idx: np.ndarray) -> None:
    g = np.asarray(groups)
    tr = set(np.asarray(g[train_idx], dtype=str))
    te = set(np.asarray(g[test_idx], dtype=str))
    ov = tr.intersection(te)
    _log(f"Unique groups train={len(tr)} test={len(te)} overlap={len(ov)} (must be 0)", audit=True)


def _materialize_tabular_cache(dataset_path: Path, output_dir: Path) -> Path:
    """
    Convert JSON/JSONL/CSV dataset to a cached Parquet file and return its path.

    Cache key is deterministic from absolute path + size + mtime_ns, so repeated runs
    avoid reparsing unchanged JSONL.
    """
    st = dataset_path.stat()
    cache_key = f"{dataset_path.resolve()}::{st.st_size}::{st.st_mtime_ns}"
    short = hashlib.sha1(cache_key.encode("utf-8")).hexdigest()[:12]
    cache_dir = output_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{dataset_path.stem}.{short}.parquet"
    if cache_path.exists():
        _log(f"Using cached parquet dataset: {cache_path}")
        return cache_path

    ext = dataset_path.suffix.lower()
    _log(f"Materializing dataset cache ({ext}): {dataset_path} -> {cache_path}")
    if ext in {".jsonl", ".json"}:
        df = pd.read_json(dataset_path, lines=True)
    elif ext == ".csv":
        df = pd.read_csv(dataset_path)
    else:
        raise ValueError(f"Unsupported dataset extension for cache: {ext}")
    if df.empty:
        raise ValueError(f"Dataset is empty: {dataset_path}")
    if LABEL_COL not in df.columns:
        raise ValueError(
            f"Dataset must include {LABEL_COL!r} for Stage 1 training. "
            f"Found columns={list(df.columns)}"
        )
    df.to_parquet(cache_path, index=False)
    _log(f"Wrote cached parquet rows={len(df)} cols={len(df.columns)}: {cache_path}")
    return cache_path


def _build_labeled_cache_from_eve(
    *,
    eve_path: Path,
    labels_csv: Path,
    cache_parquet: Path,
    time_tolerance_sec: float,
    rebuild_cache: bool,
) -> Path:
    if cache_parquet.exists() and not rebuild_cache:
        _log(f"Using existing labeled cache: {cache_parquet}")
        return cache_parquet
    _log(f"Building labeled cache from EVE + ground truth CSV -> {cache_parquet}")
    from training.Randomforest_training_pipeline import _join_flows_with_labels, _prepare_labels_csv

    labels_df, tol = _prepare_labels_csv(labels_csv, time_tolerance_sec)
    _join_flows_with_labels(
        eve_path=eve_path,
        labels_df=labels_df,
        time_tolerance=tol,
        max_events=None,
        chunk_size=50_000,
        output_parquet_path=cache_parquet,
    )
    return cache_parquet


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="LightGBM Stage 1: binary detection (benign vs attack), raw features, no scaling."
    )
    p.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help="Dataset path: parquet (preferred) or jsonl/json/csv (auto-cached to parquet)",
    )
    p.add_argument("--eve", type=Path, default=None, help="Suricata EVE JSONL (build labeled cache from this)")
    p.add_argument("--labels-csv", type=Path, default=None, help="Ground truth CSV for EVE join")
    p.add_argument("--cache-parquet", type=Path, default=None, help="Path for generated labeled cache parquet")
    p.add_argument("--time-tolerance-sec", type=float, default=1.0, help="Flow-key time bucket tolerance for labels CSV")
    p.add_argument("--cache-only", action="store_true", help="Only generate/reuse cache and exit")
    p.add_argument("--rebuild-cache", action="store_true", help="Force rebuilding cache parquet")
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Output directory")
    p.add_argument("--drop-features", type=str, default="", help="Extra comma-separated columns to drop from X")
    p.add_argument("--group-column", type=str, default="", help="Force grouping column")
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--random-state", type=int, default=42)
    p.add_argument("--skip-audit", action="store_true", help="Skip default post-train audit refits")
    args = p.parse_args(list(argv) if argv is not None else None)

    output_dir = Path(args.output_dir).resolve()
    dataset_path = Path(args.dataset).resolve()
    extra_drop = _parse_drop_features(args.drop_features)
    rs = int(args.random_state)

    if args.eve is not None or args.labels_csv is not None:
        if args.eve is None or args.labels_csv is None:
            _log("When using RF-style cache build, both --eve and --labels-csv are required.", audit=True)
            return 1
        eve_path = Path(args.eve).resolve()
        labels_csv = Path(args.labels_csv).resolve()
        if not eve_path.is_file():
            _log(f"--eve not found: {eve_path}", audit=True)
            return 1
        if not labels_csv.is_file():
            _log(f"--labels-csv not found: {labels_csv}", audit=True)
            return 1
        cache_path = (
            Path(args.cache_parquet).resolve()
            if args.cache_parquet is not None
            else (output_dir / "cache" / "lgbm_stage01_training_dataset.parquet")
        )
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            dataset_path = _build_labeled_cache_from_eve(
                eve_path=eve_path,
                labels_csv=labels_csv,
                cache_parquet=cache_path,
                time_tolerance_sec=float(args.time_tolerance_sec),
                rebuild_cache=bool(args.rebuild_cache),
            )
        except Exception as e:
            _log(f"Failed to build labeled cache from EVE: {e}", audit=True)
            return 1
        if args.cache_only:
            _log("Cache-only requested; exiting after cache generation.")
            return 0
    else:
        if not dataset_path.is_file():
            _log(f"Dataset not found: {dataset_path}", audit=True)
            return 1

        if dataset_path.suffix.lower() in {".jsonl", ".json", ".csv"}:
            try:
                dataset_path = _materialize_tabular_cache(dataset_path, output_dir)
            except Exception as e:
                _log(f"Failed to cache dataset: {e}", audit=True)
                return 1

    _log(f"Stage 1 dataset path: {dataset_path}")
    df = pd.read_parquet(dataset_path)
    _log(f"Loaded rows={len(df)} columns={len(df.columns)}")
    df = df.reset_index(drop=True)

    y_full_s = df[LABEL_COL].astype(int)
    counts = y_full_s.value_counts().sort_index().to_dict()
    _log(f"Label distribution ({LABEL_COL}): {counts}")

    if str(args.group_column).strip():
        gc = str(args.group_column).strip()
        if gc not in df.columns:
            _log(f"--group-column {gc!r} missing.", audit=True)
            return 1
        groups = df[gc].astype(str).str.strip().values
        group_src = gc
    else:
        groups, group_src = _resolve_groups(df)

    X, y_ser = _build_Xy_stage01(df, extra_drop=extra_drop)
    y_int = y_ser.astype(int).values

    gss = GroupShuffleSplit(n_splits=1, test_size=float(args.test_size), random_state=rs)
    train_idx, test_idx = next(gss.split(X, y_int, groups=groups))
    _log(
        f"Train/test GroupShuffleSplit groups={group_src!r} train={len(train_idx)} test={len(test_idx)}",
        audit=True,
    )
    _audit_group_overlap(groups, train_idx, test_idx)

    X_train = X.iloc[train_idx].reset_index(drop=True)
    X_test = X.iloc[test_idx].reset_index(drop=True)
    y_train = y_int[train_idx]
    y_test = y_int[test_idx]

    s_tr = pd.Series(y_train).value_counts(normalize=True).sort_index()
    s_te = pd.Series(y_test).value_counts(normalize=True).sort_index()
    _log(f"Train class proportion (0=benign, 1=attack):\n{s_tr.to_string()}", audit=True)
    _log(f"Test class proportion:\n{s_te.to_string()}", audit=True)

    n_feat = X_train.shape[1]
    _log(f"Feature count: {n_feat} (expect ~{N_UNIFIED_EXPECT})")

    training_params = dict(
        objective="binary",
        n_estimators=400,
        learning_rate=0.05,
        num_leaves=64,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight="balanced",
        random_state=rs,
        n_jobs=-1,
        **LGBM_QUIET_KWARGS,
    )
    model = LGBMClassifier(**training_params)
    _log("Fitting Stage 1 LGBMClassifier (binary) …")
    model.fit(X_train, y_train)

    proba_test = model.predict_proba(X_test)
    proba_attack = proba_test[:, 1] if proba_test.shape[1] >= 2 else np.zeros(len(X_test))
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    try:
        roc = roc_auc_score(y_test, proba_attack)
    except ValueError:
        roc = float("nan")
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        cm_str = f"[[{tn} {fp}] [{fn} {tp}]]"
    else:
        cm_str = str(cm.tolist())

    _log("=== Stage 1 holdout evaluation ===")
    _log(f"Accuracy: {acc:.4f}")
    _log(f"ROC-AUC: {roc:.4f}" if not np.isnan(roc) else "ROC-AUC: N/A")
    _log(f"Confusion matrix: {cm_str}")
    _log("Classification report:\n" + classification_report(y_test, y_pred, target_names=["benign", "attack"]))

    names = list(X_train.columns)
    importances = model.feature_importances_
    order = np.argsort(-importances)
    _log("Top 25 feature importances:")
    for rank, j in enumerate(order[:25], start=1):
        _log(f"  {rank:2d}. {names[int(j)]}: {importances[int(j)]:.6f}")

    audit_metrics = run_binary_post_train_audits(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        X_full=X,
        y_full=y_int,
        groups=groups,
        feature_names=names,
        importances=importances,
        rs=rs,
        log=_log,
        skip_audits=bool(args.skip_audit),
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / MODEL_FILENAME
    config_path = output_dir / CONFIG_FILENAME
    joblib.dump(model, model_path)

    config: Dict[str, Any] = {
        "feature_names": names,
        "label_column": LABEL_COL,
        "model_type": "lgbm_stage01_binary",
        "num_classes": 2,
        "training_params": training_params,
        "dataset_path": str(dataset_path),
        "n_features": n_feat,
        "dropped_columns": [c for c in META_DROP_STAGE01 if c in df.columns] + [c for c in extra_drop if c in df.columns],
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "random_state": rs,
        "split_method": "GroupShuffleSplit",
        "group_column": group_src,
        "test_size": float(args.test_size),
        "holdout_accuracy": float(acc),
        "audit_metrics": audit_metrics,
    }
    joblib.dump(config, config_path)
    _log(f"Saved model: {model_path}")
    _log(f"Saved config: {config_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
