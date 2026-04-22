#!/usr/bin/env python3
"""
LightGBM Stage 2 — multiclass ``attack_type`` on attack-only rows (``binary_label == 1``).

GroupShuffleSplit, default post-train audits (shared with Stage 1 style). ``--skip-audit`` to disable.

Usage::

  python -m training.lgbm_stage02_training_pipeline \\
    --dataset artifacts/Cached_Training_Dataset/Stage02_training_dataset.parquet \\
    --output-dir artifacts/Saved_models/LGBM_STAGE02
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
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import LabelEncoder

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from training.lgbm_audit_utils import (
    LGBM_QUIET_KWARGS,
    run_multiclass_post_train_audits,
    silence_lightgbm,
)

silence_lightgbm()

LABEL_COL = "attack_type"
BINARY_COL = "binary_label"
META_DROP_STAGE02 = (
    "attack_type",
    "attack_subclass",
    "binary_label",
    "identity_key",
    "flow_key",
)
DEFAULT_DATASET = ROOT / "artifacts/Cached_Training_Dataset/Stage02_training_dataset.parquet"
DEFAULT_OUTPUT_DIR = ROOT / "artifacts/Saved_models/LGBM_STAGE02"
MODEL_FILENAME = "lgbm_stage02_model.joblib"
CONFIG_FILENAME = "config.joblib"
NUM_CLASSES_STAGE02 = 6
N_UNIFIED_EXPECT = 39
SHUFFLE_ACC_FAIL_STRICT = 0.33


def _log(msg: str, *, audit: bool = False) -> None:
    prefix = "[AUDIT]" if audit else "[INFO]"
    print(f"{prefix} {msg}", file=sys.stderr, flush=True)


def _parse_drop_features(s: Optional[str]) -> List[str]:
    if not s or not str(s).strip():
        return []
    return [c.strip() for c in str(s).split(",") if c.strip()]


def _ensure_attack_type_column(df: pd.DataFrame) -> pd.DataFrame:
    if LABEL_COL in df.columns:
        return df
    if "attack_subclass" in df.columns:
        _log("Column attack_type missing; using attack_subclass as multiclass label.")
        out = df.copy()
        out[LABEL_COL] = out["attack_subclass"]
        return out
    raise ValueError("Stage 2 requires 'attack_type' or 'attack_subclass'.")


def _build_Xy_stage02(
    df: pd.DataFrame,
    *,
    extra_drop: Sequence[str],
) -> Tuple[pd.DataFrame, pd.Series]:
    drop_x = [c for c in META_DROP_STAGE02 if c in df.columns] + [c for c in extra_drop if c in df.columns]
    y = df[LABEL_COL]
    X = df.drop(columns=drop_x, errors="ignore")
    if X.shape[1] == 0:
        raise ValueError("No feature columns left.")
    return X, y


def _resolve_groups(df: pd.DataFrame) -> Tuple[np.ndarray, str]:
    for col in ("identity_key", "flow_key", "src_ip"):
        if col not in df.columns:
            continue
        s = df[col].astype(str).str.strip()
        if s.nunique() >= 2:
            return s.values, col
    _log("Using row_index groups (no entity column).", audit=True)
    return np.arange(len(df), dtype=np.int64), "row_index"


def _audit_group_overlap(groups: np.ndarray, train_idx: np.ndarray, test_idx: np.ndarray) -> int:
    g = np.asarray(groups)
    tr = set(np.asarray(g[train_idx], dtype=str))
    te = set(np.asarray(g[test_idx], dtype=str))
    ov = tr.intersection(te)
    _log(f"Unique groups train={len(tr)} test={len(te)} overlap={len(ov)} (must be 0)", audit=True)
    return len(ov)


def _log_normalized_class_balance(y_train: np.ndarray, y_test: np.ndarray, class_names: List[str]) -> float:
    s_tr = pd.Series(y_train).value_counts(normalize=True).sort_index()
    s_te = pd.Series(y_test).value_counts(normalize=True).sort_index()
    max_diff = 0.0
    for k in range(NUM_CLASSES_STAGE02):
        name = class_names[k] if k < len(class_names) else str(k)
        p_tr = float(s_tr.get(k, 0.0))
        p_te = float(s_te.get(k, 0.0))
        max_diff = max(max_diff, abs(p_tr - p_te))
        _log(f"  class [{k}] {name}: train={p_tr:.4f} test={p_te:.4f}", audit=True)
    _log(f"Max |Δ proportion| train vs test: {max_diff:.4f} (GroupShuffleSplit is not stratified)", audit=True)
    return max_diff


def _audit_feature_label_correlation(X: pd.DataFrame, y_enc: np.ndarray) -> int:
    n_hits = 0
    ye = np.asarray(y_enc, dtype=np.float64)
    for col in X.columns:
        xc = pd.to_numeric(X[col], errors="coerce").fillna(0.0).to_numpy(dtype=np.float64)
        if np.nanstd(xc) < 1e-12 or np.nanstd(ye) < 1e-12:
            continue
        c = np.corrcoef(xc, ye)[0, 1]
        if np.isfinite(c) and abs(c) > 0.9:
            n_hits += 1
            _log(f"[LEAKAGE] High |corr| label: {col} → {abs(c):.4f}", audit=True)
    return n_hits


def _audit_duplicates(X: pd.DataFrame, X_train: pd.DataFrame, X_test: pd.DataFrame) -> Tuple[int, int]:
    dup = int(X.duplicated().sum())
    _log(f"Exact duplicate rows (full set): {dup}", audit=True)

    def _rows(sub: pd.DataFrame) -> set:
        arr = np.round(sub.to_numpy(dtype=np.float64, copy=True), decimals=6)
        return set(map(tuple, arr))

    cross = len(_rows(X_train).intersection(_rows(X_test)))
    _log(f"Cross-split near-duplicate rows: {cross}", audit=True)
    return dup, cross


def _temporal_benchmark(df: pd.DataFrame, enc: LabelEncoder, extra_drop: Sequence[str], rs: int) -> None:
    if "timestamp" not in df.columns:
        return
    try:
        df_ts = df.sort_values("timestamp").reset_index(drop=True)
    except Exception:
        return
    split_i = int(len(df_ts) * 0.8)
    if split_i < 1 or split_i >= len(df_ts):
        return
    tr, te = df_ts.iloc[:split_i], df_ts.iloc[split_i:]
    X_tr, _ = _build_Xy_stage02(tr, extra_drop=extra_drop)
    X_te, _ = _build_Xy_stage02(te, extra_drop=extra_drop)
    y_tr = enc.transform(tr[LABEL_COL].astype(str).str.strip())
    y_te = enc.transform(te[LABEL_COL].astype(str).str.strip())
    m = LGBMClassifier(
        objective="multiclass",
        num_class=NUM_CLASSES_STAGE02,
        n_estimators=120,
        learning_rate=0.05,
        num_leaves=32,
        class_weight="balanced",
        random_state=rs,
        n_jobs=-1,
        **LGBM_QUIET_KWARGS,
    )
    m.fit(X_tr, y_tr)
    acc = accuracy_score(y_te, m.predict(X_te))
    _log(f"Temporal 80/20 benchmark accuracy: {acc:.4f}", audit=True)


def _evaluate_external(
    path: Path,
    enc: LabelEncoder,
    extra_drop: Sequence[str],
    model: LGBMClassifier,
    feature_names: List[str],
) -> Optional[float]:
    if not path.is_file():
        return None
    df_e = pd.read_parquet(path)
    df_e = _ensure_attack_type_column(df_e)
    df_e = df_e.loc[df_e[BINARY_COL].astype(int) == 1].copy()
    yr = df_e[LABEL_COL].astype(str).str.strip()
    df_e = df_e.loc[yr.isin(enc.classes_)].copy()
    if len(df_e) == 0:
        return None
    X_e, _ = _build_Xy_stage02(df_e, extra_drop=extra_drop)
    if any(c not in X_e.columns for c in feature_names):
        return None
    X_e = X_e[feature_names]
    y_e = enc.transform(df_e[LABEL_COL].astype(str).str.strip())
    acc = accuracy_score(y_e, model.predict(X_e))
    _log(f"External validation accuracy ({path.name}): {acc:.4f}", audit=True)
    return float(acc)


def _write_audit_plots(X: pd.DataFrame, y_str: pd.Series, top_features: List[str], audit_dir: Path, rs: int) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        _log("matplotlib missing; skip plots.", audit=True)
        return
    audit_dir.mkdir(parents=True, exist_ok=True)
    yb = y_str.astype(str).str.strip()
    Xn = X.apply(pd.to_numeric, errors="coerce").fillna(0.0)
    for feat in top_features:
        if feat not in Xn.columns:
            continue
        plt.figure(figsize=(8, 4))
        for cls in sorted(yb.unique()):
            sub = Xn.loc[yb == cls, feat].dropna()
            if len(sub) == 0:
                continue
            plt.hist(sub.values, bins=50, alpha=0.35, label=str(cls), density=True)
        plt.title(feat)
        plt.legend(fontsize=7)
        plt.tight_layout()
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in feat)[:80]
        plt.savefig(audit_dir / f"separability_{safe}.png", dpi=120)
        plt.close()
    c = Xn.corr(numeric_only=True)
    if c.shape[0] > 0:
        side = min(16.0, max(8.0, 0.22 * float(c.shape[0])))
        fig, ax = plt.subplots(figsize=(side, side))
        im = ax.imshow(c.values, vmin=-1, vmax=1, cmap="coolwarm", aspect="auto")
        ax.set_xticks(range(len(c.columns)))
        ax.set_yticks(range(len(c.columns)))
        ax.set_xticklabels(list(c.columns), rotation=90, fontsize=5)
        ax.set_yticklabels(list(c.columns), fontsize=5)
        plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        plt.tight_layout()
        plt.savefig(audit_dir / "feature_correlation_heatmap.png", dpi=140)
        plt.close()
    _log(f"Audit plots -> {audit_dir}", audit=True)


def _verdict(
    overlap: int,
    label_hits: int,
    acc_main: float,
    shuffle_acc: Optional[float],
    max_bal: float,
    external: Optional[float],
    audit_ran: bool,
    audit_metrics: Dict[str, Any],
) -> Tuple[str, List[str]]:
    b: List[str] = []
    if overlap:
        return "❌ Invalid split (group overlap)", [f"overlap={overlap}"]
    if audit_ran and shuffle_acc is not None and shuffle_acc > SHUFFLE_ACC_FAIL_STRICT:
        return "❌ Shuffle test suggests leakage", [f"shuffle_acc={shuffle_acc:.3f}"]
    if label_hits:
        b.append(f"{label_hits} features |corr(label)|>0.9")
    if max_bal > 0.12:
        b.append(f"Class proportion skew max Δ={max_bal:.3f}")
    cv = audit_metrics.get("group_cv_mean")
    if cv is not None:
        b.append(f"GroupKFold mean={cv:.4f}")
    if external is not None:
        b.append(f"external_acc={external:.4f} vs holdout={acc_main:.4f}")
    if not audit_ran:
        b.append("Audits skipped (--skip-audit).")
    head = "✅ No hard leakage flags; confirm on unseen data before production."
    return head, b


def _materialize_tabular_cache(dataset_path: Path, output_dir: Path) -> Path:
    """
    Convert JSON/JSONL/CSV dataset to a cached Parquet file and return its path.
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
    if BINARY_COL not in df.columns:
        raise ValueError(
            f"Dataset must include {BINARY_COL!r} for Stage 2 filtering. "
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
    p = argparse.ArgumentParser(description="LightGBM Stage 2 multiclass attack_type.")
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
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--drop-features", type=str, default="")
    p.add_argument("--group-column", type=str, default="")
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--random-state", type=int, default=42)
    p.add_argument("--skip-audit", action="store_true")
    p.add_argument("--strict-audit", action="store_true")
    p.add_argument("--write-audit-plots", action="store_true")
    p.add_argument("--external-test-parquet", type=Path, default=None)
    args = p.parse_args(list(argv) if argv is not None else None)

    dataset_path = Path(args.dataset).resolve()
    output_dir = Path(args.output_dir).resolve()
    extra_drop = _parse_drop_features(args.drop_features)
    rs = int(args.random_state)
    strict_failures: List[str] = []

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
            else (output_dir / "cache" / "lgbm_stage02_training_dataset.parquet")
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

    _log(f"Stage 2 dataset: {dataset_path}")
    df = pd.read_parquet(dataset_path)
    if BINARY_COL not in df.columns:
        return 1
    df = _ensure_attack_type_column(df)
    df = df.loc[df[BINARY_COL].astype(int) == 1].copy()
    y_raw = df[LABEL_COL].astype(str).str.strip()
    df = df.loc[y_raw.notna() & (y_raw != "") & (y_raw.str.lower() != "nan")].copy()
    if df[LABEL_COL].astype(str).str.strip().nunique() != NUM_CLASSES_STAGE02:
        _log("Need exactly 6 classes.", audit=True)
        return 1

    df = df.reset_index(drop=True)
    enc = LabelEncoder()
    enc.fit(df[LABEL_COL].astype(str).str.strip())
    classes_list = enc.classes_.tolist()
    _log(f"Classes: {classes_list}", audit=True)

    if str(args.group_column).strip():
        gc = str(args.group_column).strip()
        groups = df[gc].astype(str).str.strip().values
        group_src = gc
    else:
        groups, group_src = _resolve_groups(df)

    X, y_str = _build_Xy_stage02(df, extra_drop=extra_drop)
    y_str = y_str.astype(str).str.strip()
    y_int = enc.transform(y_str)

    gss = GroupShuffleSplit(n_splits=1, test_size=float(args.test_size), random_state=rs)
    tr_i, te_i = next(gss.split(X, y_int, groups=groups))
    overlap_n = _audit_group_overlap(groups, tr_i, te_i)
    if overlap_n:
        strict_failures.append("group_overlap")

    X_train, X_test = X.iloc[tr_i].reset_index(drop=True), X.iloc[te_i].reset_index(drop=True)
    y_train, y_test = y_int[tr_i], y_int[te_i]
    max_bal = _log_normalized_class_balance(y_train, y_test, classes_list)

    label_hits = _audit_feature_label_correlation(X, y_int)
    dup_full, cross_dup = _audit_duplicates(X, X_train, X_test)
    thr = max(20, int(0.02 * max(len(X_test), 1)))
    if cross_dup > thr:
        strict_failures.append("cross_dup")

    _temporal_benchmark(df, enc, extra_drop, rs)

    training_params = dict(
        objective="multiclass",
        num_class=NUM_CLASSES_STAGE02,
        n_estimators=500,
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
    _log("Fitting Stage 2 LGBM …")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc_main = accuracy_score(y_test, y_pred)
    _log("=== Holdout evaluation ===")
    _log(f"Accuracy: {acc_main:.4f}")
    _log("Classification report:\n" + classification_report(y_test, y_pred, target_names=classes_list, zero_division=0))
    _log(f"Confusion matrix:\n{confusion_matrix(y_test, y_pred)}")

    names = list(X_train.columns)
    imp = model.feature_importances_
    order = np.argsort(-imp)
    top5 = [names[int(j)] for j in order[:5]]
    for r, j in enumerate(order[:25], 1):
        _log(f"  {r:2d}. {names[int(j)]}: {imp[int(j)]:.6f}")

    if args.write_audit_plots:
        _write_audit_plots(X, y_str, top5, output_dir / "stage02_audit", rs)

    audit_ran = not args.skip_audit
    audit_metrics = run_multiclass_post_train_audits(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        X_full=X,
        y_full=y_int,
        y_str_full=y_str,
        groups=groups,
        feature_names=names,
        importances=imp,
        num_class=NUM_CLASSES_STAGE02,
        rs=rs,
        log=_log,
        skip_audits=bool(args.skip_audit),
    )
    shuf = audit_metrics.get("shuffle_label_accuracy") if audit_ran else None
    if shuf is not None and shuf > SHUFFLE_ACC_FAIL_STRICT:
        strict_failures.append("shuffle")

    ext = None
    if args.external_test_parquet:
        ext = _evaluate_external(Path(args.external_test_parquet).resolve(), enc, extra_drop, model, names)

    v_head, v_bullets = _verdict(overlap_n, label_hits, acc_main, shuf, max_bal, ext, audit_ran, audit_metrics)
    _log("=== Verdict ===", audit=True)
    for x in v_bullets:
        _log(x, audit=True)
    _log(v_head, audit=True)

    if args.strict_audit and strict_failures:
        _log(f"Strict audit fail: {strict_failures}", audit=True)
        return 2

    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_dir / MODEL_FILENAME)
    cfg: Dict[str, Any] = {
        "feature_names": names,
        "label_column": LABEL_COL,
        "model_type": "lgbm_stage02_multiclass",
        "num_classes": NUM_CLASSES_STAGE02,
        "training_params": training_params,
        "classes": classes_list,
        "dataset_path": str(dataset_path),
        "n_features": len(names),
        "dropped_columns": [c for c in META_DROP_STAGE02 if c in df.columns] + list(extra_drop),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "random_state": rs,
        "split_method": "GroupShuffleSplit",
        "group_column": group_src,
        "test_size": float(args.test_size),
        "holdout_accuracy": float(acc_main),
        "audit_metrics": audit_metrics,
        "verdict": v_head,
        "verdict_bullets": v_bullets,
    }
    joblib.dump(cfg, output_dir / CONFIG_FILENAME)
    _log(f"Saved {output_dir / MODEL_FILENAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
