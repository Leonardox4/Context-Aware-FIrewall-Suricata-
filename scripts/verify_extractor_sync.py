#!/usr/bin/env python3
"""
Verify Python behavioral schema matches the compiled eve_extractor (Rust).

Run from Model2_development/:
  python scripts/verify_extractor_sync.py

Exit code 0 = OK; 1 = mismatch (rebuild: cd rust/eve_extractor && maturin develop --release).
If eve_extractor is not installed, exits 0 with a notice (optional dependency).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    from ingestion.flow_identity import FLOW_KEY_BUCKET_SEC
    from ingestion.unified_behavioral_schema import (
        N_UNIFIED_BEHAVIORAL_FEATURES,
        UNIFIED_BEHAVIORAL_FEATURE_NAMES,
    )

    try:
        import eve_extractor as ee  # type: ignore[import-untyped]
    except ImportError:
        print(
            "[verify_extractor_sync] eve_extractor not installed; skipping Rust checks.",
            file=sys.stderr,
        )
        return 0

    errors: list[str] = []
    py_n = N_UNIFIED_BEHAVIORAL_FEATURES
    if len(UNIFIED_BEHAVIORAL_FEATURE_NAMES) != py_n:
        errors.append("internal: len(UNIFIED_BEHAVIORAL_FEATURE_NAMES) != N_UNIFIED_BEHAVIORAL_FEATURES")

    try:
        mod_n = int(ee.N_FEATURES)
    except AttributeError:
        errors.append("eve_extractor missing N_FEATURES (rebuild extension from this repo)")
        mod_n = -1
    if mod_n >= 0 and mod_n != py_n:
        errors.append(f"eve_extractor.N_FEATURES={mod_n} != Python N_UNIFIED_BEHAVIORAL_FEATURES={py_n}")

    eng = ee.RustUnifiedExtractor(False)
    if int(eng.n_features) != py_n:
        errors.append(f"RustUnifiedExtractor.n_features={eng.n_features} != Python {py_n}")

    try:
        rb = float(ee.FLOW_KEY_BUCKET_SEC)
        if abs(rb - FLOW_KEY_BUCKET_SEC) > 1e-9:
            errors.append(
                f"eve_extractor.FLOW_KEY_BUCKET_SEC={rb} != ingestion.flow_identity "
                f"FLOW_KEY_BUCKET_SEC={FLOW_KEY_BUCKET_SEC}"
            )
    except AttributeError:
        errors.append("eve_extractor missing FLOW_KEY_BUCKET_SEC (rebuild extension from this repo)")

    if errors:
        print("[verify_extractor_sync] FAIL:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "  Rebuild: cd Model2_development/rust/eve_extractor && maturin develop --release",
            file=sys.stderr,
        )
        return 1

    print(
        f"[verify_extractor_sync] OK: N_FEATURES={py_n}, FLOW_KEY_BUCKET_SEC={FLOW_KEY_BUCKET_SEC}, "
        f"feature names={len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
