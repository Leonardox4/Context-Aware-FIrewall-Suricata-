#!/usr/bin/env python3
"""
Plot RandomForestClassifier feature importances for a Model2 artifact bundle.

Requires:
  - <artifacts>/random_forest.joblib
  - <artifacts>/config.joblib  (uses config["feature_names"] when present)

Isolation Forest has no feature_importances_ in scikit-learn; use this for the binary RF only.

Usage:
  pip install matplotlib
  python scripts/plot_rf_feature_importance.py --artifacts /path/to/bundle --output rf_importance.png
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ingestion.unified_behavioral_schema import UNIFIED_BEHAVIORAL_FEATURE_NAMES


def _load_rf_and_names(artifacts_dir: Path) -> tuple:
    rf_path = artifacts_dir / "random_forest.joblib"
    cfg_path = artifacts_dir / "config.joblib"
    if not rf_path.is_file():
        raise FileNotFoundError(
            f"Missing {rf_path}. Put your trained bundle here or pass --artifacts to the directory "
            "that contains random_forest.joblib and config.joblib."
        )
    rf = joblib.load(rf_path)
    if rf is None:
        raise ValueError(f"{rf_path} loaded as None.")
    if not hasattr(rf, "feature_importances_"):
        raise TypeError(f"Loaded object has no feature_importances_: {type(rf)}")
    imp = np.asarray(rf.feature_importances_, dtype=np.float64)
    names: list[str]
    if cfg_path.is_file():
        cfg = joblib.load(cfg_path)
        names = list(cfg.get("feature_names") or [])
    else:
        names = []
    if len(names) != len(imp):
        n = len(imp)
        if n == len(UNIFIED_BEHAVIORAL_FEATURE_NAMES):
            names = list(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
        else:
            names = [f"f{i}" for i in range(n)]
    return imp, names


def main() -> int:
    p = argparse.ArgumentParser(description="Plot binary RF feature importances from joblib bundle.")
    p.add_argument("--artifacts", type=Path, required=True, help="Directory with random_forest.joblib (+ config.joblib)")
    p.add_argument("--output", type=Path, default=Path("rf_feature_importance.png"), help="PNG path")
    p.add_argument("--top", type=int, default=43, help="Show top N features (default: all)")
    args = p.parse_args()

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("Install matplotlib: pip install matplotlib", file=sys.stderr)
        return 1

    imp, names = _load_rf_and_names(args.artifacts.resolve())
    order = np.argsort(imp)[::-1]
    top = min(max(1, args.top), len(imp))
    order = order[:top]
    y_names = [names[i] for i in order]
    y_vals = imp[order]

    fig_h = max(6.0, 0.22 * top + 1.5)
    fig, ax = plt.subplots(figsize=(10, fig_h))
    y_pos = np.arange(len(y_names))
    ax.barh(y_pos, y_vals, color="#2c5282", edgecolor="none")
    ax.set_yticks(y_pos)
    ax.set_yticklabels(y_names, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Gini importance (mean decrease impurity)")
    ax.set_title(f"Random forest feature importances (top {top} of {len(imp)})")
    ax.set_xlim(0, max(float(y_vals.max()) * 1.08, 1e-6))
    fig.tight_layout()
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError, TypeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
