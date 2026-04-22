"""
Shared LightGBM training audits (Stage 1 + Stage 2) and quiet logging.

All audit messages should be emitted via a logger using prefix ``[AUDIT]``.
"""

from __future__ import annotations

import warnings
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import GroupKFold

LogFn = Callable[[str, bool], None]

LGBM_QUIET_KWARGS: Dict[str, Any] = dict(
    verbose=-1,
    min_gain_to_split=1e-3,
)

AUDIT_CV_N_ESTIMATORS = 120
AUDIT_STRESS_N_ESTIMATORS = 150
NOISE_WEAK = 0.1
NOISE_STRONG = 0.5
DROP_TOP_N = 5
GROUP_CV_SPLITS = 5


def silence_lightgbm() -> None:
    """Suppress sklearn/LightGBM chatter (e.g. 'No further splits with positive gain')."""
    warnings.filterwarnings("ignore", category=UserWarning)
    warnings.filterwarnings("ignore", message=".*No further splits.*")
    try:
        import lightgbm as lgb

        lgb.register_logger(lambda _: None)
    except Exception:
        pass


def audit_uniqueness_scan(X: pd.DataFrame, log: LogFn, *, threshold: float = 0.9) -> None:
    n = len(X)
    if n == 0:
        return
    for col in X.columns:
        ur = X[col].nunique() / n
        if ur > threshold:
            log(f"[LEAKAGE] Feature uniqueness ratio {ur:.3f} > {threshold}: {col}", audit=True)


def audit_top_feature_separability_binary(
    X: pd.DataFrame,
    y: np.ndarray,
    top_features: Sequence[str],
    log: LogFn,
) -> None:
    yv = np.asarray(y).ravel()
    Xn = X.apply(pd.to_numeric, errors="coerce").fillna(0.0)
    for feat in top_features:
        if feat not in Xn.columns:
            continue
        log(f"Separability (binary) for {feat!r} — mean±std by class:", audit=True)
        for cls in (0, 1):
            m = yv == cls
            sub = Xn.loc[m, feat]
            if len(sub) == 0:
                continue
            log(f"  label={cls}: mean={sub.mean():.6g} std={sub.std():.6g} n={len(sub)}", audit=True)


def audit_top_feature_separability_multiclass(
    X: pd.DataFrame,
    y_str: pd.Series,
    top_features: Sequence[str],
    log: LogFn,
) -> None:
    yb = y_str.astype(str).str.strip()
    Xn = X.apply(pd.to_numeric, errors="coerce").fillna(0.0)
    for feat in top_features:
        if feat not in Xn.columns:
            continue
        log(f"Separability (multiclass) for {feat!r}:", audit=True)
        for cls in sorted(yb.unique()):
            sub = Xn.loc[yb == cls, feat]
            if len(sub) == 0:
                continue
            log(f"  {cls}: mean={sub.mean():.6g} std={sub.std():.6g} n={len(sub)}", audit=True)


def _group_kfold_scores(
    X: pd.DataFrame,
    y: np.ndarray,
    groups: np.ndarray,
    *,
    n_splits: int,
    rs: int,
    log: LogFn,
    objective: str,
    num_class: Optional[int],
    class_weight: str | dict | None,
) -> Optional[List[float]]:
    n_groups = len(np.unique(groups))
    if n_groups < n_splits:
        log(
            f"GroupKFold skipped: need ≥{n_splits} groups, have {n_groups}.",
            audit=True,
        )
        return None
    gkf = GroupKFold(n_splits=n_splits)
    scores: List[float] = []
    fold = 0
    for tr, te in gkf.split(X, y, groups=groups):
        fold += 1
        kw = dict(
            **LGBM_QUIET_KWARGS,
            n_estimators=AUDIT_CV_N_ESTIMATORS,
            learning_rate=0.05,
            num_leaves=48,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=rs + fold,
            n_jobs=-1,
        )
        if objective == "binary":
            clf = LGBMClassifier(
                objective="binary",
                class_weight=class_weight or "balanced",
                **kw,
            )
        else:
            clf = LGBMClassifier(
                objective="multiclass",
                num_class=int(num_class or 2),
                class_weight=class_weight or "balanced",
                **kw,
            )
        clf.fit(X.iloc[tr], y[tr])
        acc = accuracy_score(y[te], clf.predict(X.iloc[te]))
        scores.append(float(acc))
        log(f"GroupKFold fold {fold}/{n_splits} accuracy: {acc:.4f}", audit=True)
    mean_s, std_s = float(np.mean(scores)), float(np.std(scores))
    log(f"GroupKFold mean={mean_s:.4f} std={std_s:.4f} scores={scores}", audit=True)
    return scores


def run_binary_post_train_audits(
    *,
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: np.ndarray,
    y_test: np.ndarray,
    X_full: pd.DataFrame,
    y_full: np.ndarray,
    groups: np.ndarray,
    feature_names: List[str],
    importances: np.ndarray,
    rs: int,
    log: LogFn,
    skip_audits: bool,
) -> Dict[str, Any]:
    """Default audit suite after main binary model fit. Returns metrics for config."""
    out: Dict[str, Any] = {"audit_skipped": skip_audits}
    if skip_audits:
        log("Post-train audits skipped (--skip-audit).", audit=True)
        return out

    log("--- Default audit suite (binary) ---", audit=True)
    audit_uniqueness_scan(X_full, log)
    order = np.argsort(-importances)
    topn = [feature_names[int(j)] for j in order[: max(5, DROP_TOP_N)]]
    audit_top_feature_separability_binary(X_full, y_full, topn[:5], log)

    cv_scores = _group_kfold_scores(
        X_full,
        y_full,
        groups,
        n_splits=GROUP_CV_SPLITS,
        rs=rs,
        log=log,
        objective="binary",
        num_class=None,
        class_weight="balanced",
    )
    out["group_cv_scores"] = cv_scores
    if cv_scores:
        out["group_cv_mean"] = float(np.mean(cv_scores))
        out["group_cv_std"] = float(np.std(cv_scores))

    rng = np.random.default_rng(rs)
    y_shuf = rng.permutation(y_train)
    m_shuf = LGBMClassifier(
        objective="binary",
        n_estimators=AUDIT_STRESS_N_ESTIMATORS,
        learning_rate=0.05,
        num_leaves=48,
        class_weight="balanced",
        random_state=rs,
        n_jobs=-1,
        **LGBM_QUIET_KWARGS,
    )
    m_shuf.fit(X_train, y_shuf)
    acc_shuf = accuracy_score(y_test, m_shuf.predict(X_test))
    log(f"Shuffle-label test accuracy: {acc_shuf:.4f} (expect ~0.5 if no leakage)", audit=True)
    out["shuffle_label_accuracy"] = acc_shuf

    m_weak = LGBMClassifier(
        objective="binary",
        n_estimators=50,
        num_leaves=8,
        max_depth=3,
        learning_rate=0.05,
        class_weight="balanced",
        random_state=rs,
        n_jobs=-1,
        **LGBM_QUIET_KWARGS,
    )
    m_weak.fit(X_train, y_train)
    acc_weak = accuracy_score(y_test, m_weak.predict(X_test))
    log(f"Weak-model accuracy: {acc_weak:.4f}", audit=True)
    out["weak_model_accuracy"] = acc_weak

    for sigma, label in ((NOISE_WEAK, "0.1"), (NOISE_STRONG, "0.5")):
        ntr = rng.normal(0.0, 1.0, size=X_train.shape).astype(np.float32)
        nte = rng.normal(0.0, 1.0, size=X_test.shape).astype(np.float32)
        Xtr_n = X_train + sigma * ntr
        Xte_n = X_test + sigma * nte
        m_n = LGBMClassifier(
            objective="binary",
            n_estimators=AUDIT_STRESS_N_ESTIMATORS,
            learning_rate=0.05,
            num_leaves=48,
            class_weight="balanced",
            random_state=rs,
            n_jobs=-1,
            **LGBM_QUIET_KWARGS,
        )
        m_n.fit(Xtr_n, y_train)
        acc_n = accuracy_score(y_test, m_n.predict(Xte_n))
        log(f"Noise σ={label} train+test accuracy: {acc_n:.4f}", audit=True)
        out[f"noise_sigma_{label.replace('.', '_')}_accuracy"] = acc_n

    drop_cols = [feature_names[int(j)] for j in order[:DROP_TOP_N] if feature_names[int(j)] in X_train.columns]
    if drop_cols:
        m_d = LGBMClassifier(
            objective="binary",
            n_estimators=AUDIT_STRESS_N_ESTIMATORS,
            learning_rate=0.05,
            num_leaves=48,
            class_weight="balanced",
            random_state=rs,
            n_jobs=-1,
            **LGBM_QUIET_KWARGS,
        )
        m_d.fit(X_train.drop(columns=drop_cols), y_train)
        acc_d = accuracy_score(y_test, m_d.predict(X_test.drop(columns=drop_cols)))
        log(f"Drop-top-{len(drop_cols)} features accuracy: {acc_d:.4f}", audit=True)
        out["drop_top_features_accuracy"] = acc_d

    return out


def run_multiclass_post_train_audits(
    *,
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: np.ndarray,
    y_test: np.ndarray,
    X_full: pd.DataFrame,
    y_full: np.ndarray,
    y_str_full: pd.Series,
    groups: np.ndarray,
    feature_names: List[str],
    importances: np.ndarray,
    num_class: int,
    rs: int,
    log: LogFn,
    skip_audits: bool,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"audit_skipped": skip_audits}
    if skip_audits:
        log("Post-train audits skipped (--skip-audit).", audit=True)
        return out

    log("--- Default audit suite (multiclass) ---", audit=True)
    audit_uniqueness_scan(X_full, log)
    order = np.argsort(-importances)
    topn = [feature_names[int(j)] for j in order[:5]]
    audit_top_feature_separability_multiclass(X_full, y_str_full, topn, log)

    cv_scores = _group_kfold_scores(
        X_full,
        y_full,
        groups,
        n_splits=GROUP_CV_SPLITS,
        rs=rs,
        log=log,
        objective="multiclass",
        num_class=num_class,
        class_weight="balanced",
    )
    out["group_cv_scores"] = cv_scores
    if cv_scores:
        out["group_cv_mean"] = float(np.mean(cv_scores))
        out["group_cv_std"] = float(np.std(cv_scores))

    rng = np.random.default_rng(rs)
    y_shuf = rng.permutation(y_train)
    m_shuf = LGBMClassifier(
        objective="multiclass",
        num_class=num_class,
        n_estimators=AUDIT_STRESS_N_ESTIMATORS,
        learning_rate=0.05,
        num_leaves=48,
        class_weight="balanced",
        random_state=rs,
        n_jobs=-1,
        **LGBM_QUIET_KWARGS,
    )
    m_shuf.fit(X_train, y_shuf)
    acc_shuf = accuracy_score(y_test, m_shuf.predict(X_test))
    exp = 1.0 / num_class
    log(f"Shuffle-label test accuracy: {acc_shuf:.4f} (expect ~{exp:.3f} if no leakage)", audit=True)
    out["shuffle_label_accuracy"] = acc_shuf

    m_weak = LGBMClassifier(
        objective="multiclass",
        num_class=num_class,
        n_estimators=50,
        num_leaves=8,
        max_depth=3,
        learning_rate=0.05,
        class_weight="balanced",
        random_state=rs,
        n_jobs=-1,
        **LGBM_QUIET_KWARGS,
    )
    m_weak.fit(X_train, y_train)
    acc_weak = accuracy_score(y_test, m_weak.predict(X_test))
    log(f"Weak-model accuracy: {acc_weak:.4f}", audit=True)
    out["weak_model_accuracy"] = acc_weak

    for sigma, label in ((NOISE_WEAK, "0.1"), (NOISE_STRONG, "0.5")):
        ntr = rng.normal(0.0, 1.0, size=X_train.shape).astype(np.float32)
        nte = rng.normal(0.0, 1.0, size=X_test.shape).astype(np.float32)
        m_n = LGBMClassifier(
            objective="multiclass",
            num_class=num_class,
            n_estimators=AUDIT_STRESS_N_ESTIMATORS,
            learning_rate=0.05,
            num_leaves=48,
            class_weight="balanced",
            random_state=rs,
            n_jobs=-1,
            **LGBM_QUIET_KWARGS,
        )
        m_n.fit(X_train + sigma * ntr, y_train)
        acc_n = accuracy_score(y_test, m_n.predict(X_test + sigma * nte))
        log(f"Noise σ={label} train+test accuracy: {acc_n:.4f}", audit=True)
        out[f"noise_sigma_{label.replace('.', '_')}_accuracy"] = acc_n

    drop_cols = [feature_names[int(j)] for j in order[:DROP_TOP_N] if feature_names[int(j)] in X_train.columns]
    if drop_cols:
        m_d = LGBMClassifier(
            objective="multiclass",
            num_class=num_class,
            n_estimators=AUDIT_STRESS_N_ESTIMATORS,
            learning_rate=0.05,
            num_leaves=48,
            class_weight="balanced",
            random_state=rs,
            n_jobs=-1,
            **LGBM_QUIET_KWARGS,
        )
        m_d.fit(X_train.drop(columns=drop_cols), y_train)
        acc_d = accuracy_score(y_test, m_d.predict(X_test.drop(columns=drop_cols)))
        log(f"Drop-top-{len(drop_cols)} features accuracy: {acc_d:.4f}", audit=True)
        out["drop_top_features_accuracy"] = acc_d

    return out
