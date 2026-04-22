#!/usr/bin/env python3
"""
Build packaged LGBM fallback under models/bundled/ (binary classifier, unified schema).

Run from Model2_development/ after installing lightgbm::

  python scripts/generate_packaged_lgbm_fallback.py

Regenerate whenever UNIFIED_BEHAVIORAL_FEATURE_NAMES changes.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
from lightgbm import LGBMClassifier

from ingestion.unified_behavioral_schema import UNIFIED_BEHAVIORAL_FEATURE_NAMES


def main() -> int:
    out = ROOT / "models" / "bundled"
    out.mkdir(parents=True, exist_ok=True)
    n = len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)
    rng = np.random.default_rng(42)
    X = rng.standard_normal((800, n)).astype(np.float32)
    y = (rng.random(800) > 0.5).astype(np.int32)
    clf = LGBMClassifier(
        objective="binary",
        n_estimators=48,
        learning_rate=0.05,
        num_leaves=24,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X, y)
    joblib.dump(clf, out / "lgbm_stage01_model.joblib")
    cfg = {
        "feature_names": list(UNIFIED_BEHAVIORAL_FEATURE_NAMES),
        "label_column": "binary_label",
        "model_type": "lgbm_fallback_packaged",
        "note": (
            "Shipped fallback when trained LGBM artifacts are missing; not trained on real traffic. "
            "Train Stage 1 and point --lgbm-artifacts at LGBM_STAGE01 for production."
        ),
    }
    joblib.dump(cfg, out / "config.joblib")
    print(f"Wrote packaged fallback to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
