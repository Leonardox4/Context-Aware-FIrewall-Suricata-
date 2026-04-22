#!/usr/bin/env python3
"""
Assemble a unified HYBRID artifact directory from IF + LGBM Stage01 + optional Stage02 outputs.

Example::

  python -m training.assemble_hybrid_bundle \\
    --if-dir artifacts/Saved_models/IF \\
    --stage01-dir artifacts/Saved_models/LGBM_STAGE01 \\
    --stage02-dir artifacts/Saved_models/LGBM_STAGE02 \\
    --out-dir artifacts/Saved_models/HYBRID

Copies/renames:
  IF: isolation_forest.joblib, scaler.joblib, config.joblib -> IF_config.joblib, random_forest.joblib
  Stage01: lgbm_stage01_model.joblib, lgbm_stage01_config.joblib
  Stage02: lgbm_stage02_model.joblib, lgbm_stage02_config.joblib (optional)
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    p = argparse.ArgumentParser(description="Build HYBRID deployment bundle.")
    p.add_argument("--if-dir", type=Path, required=True)
    p.add_argument("--stage01-dir", type=Path, required=True)
    p.add_argument("--stage02-dir", type=Path, default=None)
    p.add_argument("--out-dir", type=Path, required=True)
    args = p.parse_args()

    if_dir = Path(args.if_dir).resolve()
    s1 = Path(args.stage01_dir).resolve()
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    for src, dst in [
        (if_dir / "isolation_forest.joblib", out / "isolation_forest.joblib"),
        (if_dir / "scaler.joblib", out / "scaler.joblib"),
        (if_dir / "random_forest.joblib", out / "random_forest.joblib"),
    ]:
        if not src.is_file():
            print(f"[ERROR] Missing {src}", file=sys.stderr)
            return 1
        shutil.copy2(src, dst)

    cfg_if = if_dir / "config.joblib"
    if not cfg_if.is_file():
        print(f"[ERROR] Missing {cfg_if}", file=sys.stderr)
        return 1
    shutil.copy2(cfg_if, out / "IF_config.joblib")

    for src, dst in [
        (s1 / "lgbm_stage01_model.joblib", out / "lgbm_stage01_model.joblib"),
        (s1 / "config.joblib", out / "lgbm_stage01_config.joblib"),
    ]:
        if not src.is_file():
            print(f"[ERROR] Missing {src}", file=sys.stderr)
            return 1
        shutil.copy2(src, dst)

    if args.stage02_dir:
        s2 = Path(args.stage02_dir).resolve()
        for src, dst in [
            (s2 / "lgbm_stage02_model.joblib", out / "lgbm_stage02_model.joblib"),
            (s2 / "config.joblib", out / "lgbm_stage02_config.joblib"),
        ]:
            if not src.is_file():
                print(f"[ERROR] Missing {src}", file=sys.stderr)
                return 1
            shutil.copy2(src, dst)

    print(f"[INFO] HYBRID bundle written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
