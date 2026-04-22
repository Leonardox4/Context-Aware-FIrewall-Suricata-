#!/usr/bin/env python3
"""
Compatibility wrapper for unified inference command.

It maps user-friendly flags to `python -m inference.runtime_scoring`.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Unified inference: Stage1 detection + optional Stage2 + optional enforcement"
    )
    parser.add_argument("--stage1-model", type=Path, required=True, help="Path to Stage 1 model file")
    parser.add_argument("--stage2-model", type=Path, default=None, help="Path to Stage 2 model file")
    parser.add_argument("--threshold", type=float, default=0.7, help="Attack threshold (Stage 1)")
    parser.add_argument("--enforce", action="store_true", help="Enable firewall enforcement")
    parser.add_argument("--firewall-backend", choices=("iptables", "nftables"), default="iptables")
    parser.add_argument("--block-duration", type=int, default=300)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("logs"))
    parser.add_argument(
        "--if-artifacts",
        type=Path,
        default=Path("artifacts/Saved_models/IF"),
        help="Path to IF artifact directory (isolation_forest/scaler/config, RF optional)",
    )
    parser.add_argument(
        "--if-block-threshold",
        type=float,
        default=0.80,
        help="In LGBM-primary mode, promote to BLOCK when anomaly_score_if >= this value",
    )
    parser.add_argument("--tail", action="store_true", help="Tail JSON input continuously")
    args = parser.parse_args()

    if not args.stage1_model.exists():
        raise SystemExit(f"Stage 1 model not found: {args.stage1_model}")
    if args.stage2_model is not None and not args.stage2_model.exists():
        raise SystemExit(f"Stage 2 model not found: {args.stage2_model}")

    # runtime_scoring loads Stage-1 from a bundle directory, so map file -> parent dir.
    lgbm_stage1_dir = args.stage1_model.resolve().parent

    cmd = [
        "python3",
        "-m",
        "inference.runtime_scoring",
        "--artifacts",
        str(args.if_artifacts),
        "--lgbm-artifacts",
        str(lgbm_stage1_dir),
        "--input",
        str(args.input),
        "--output-dir",
        str(args.output_dir),
        "--ml-block-threshold",
        str(float(args.threshold)),
        "--ml-alert-threshold",
        str(float(args.threshold)),
        "--block-ttl-sec",
        str(int(args.block_duration)),
        "--if-block-threshold",
        str(float(args.if_block_threshold)),
    ]

    if not args.tail:
        cmd.append("--no-tail")
    if args.enforce:
        cmd.extend(["--enforcement", args.firewall_backend])
    else:
        cmd.append("--no-enforcement")

    # Stage 2 is auto-discovered in runtime from sibling LGBM_STAGE02; keep this
    # wrapper argument for compatibility and explicit operator intent.
    if args.stage2_model is not None:
        print(f'[INFO] stage2-model provided: "{args.stage2_model}" (runtime auto-loads sibling LGBM_STAGE02 bundle)')

    p = subprocess.run(cmd)
    return int(p.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
