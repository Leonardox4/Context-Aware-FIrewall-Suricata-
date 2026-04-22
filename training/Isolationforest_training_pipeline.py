#!/usr/bin/env python3
"""
Isolation Forest training pipeline (behavioral anomaly model) for Suricata eve.json.

This is a thin wrapper around the existing streaming trainer:
`training/stream_suricata_training.py`.

Use this entry point for IF training:

  python training/Isolationforest_training_pipeline.py --dataset path/to/eve.json [options]

Rust `eve_extractor` is **required** by default (same as RF pipeline). Use **--force-python-extract**
only if you explicitly need Python. **--validate-rust-vs-python** compares Rust vs Python on a prefix.

The underlying behavior, feature schema, and artifacts layout are unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
from typing import Sequence

# Ensure Model2_development project root is on path (same pattern as other training scripts)
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def _derive_if_cache_path(dataset: Path, output_dir: Path) -> Path:
    st = dataset.stat()
    cache_key = f"{dataset.resolve()}::{st.st_size}::{st.st_mtime_ns}"
    short = hashlib.sha1(cache_key.encode("utf-8")).hexdigest()[:12]
    cache_dir = output_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"if_training_features.{short}.parquet"


def _inject_default_feature_cache(argv: Sequence[str]) -> list[str]:
    """
    Inject a deterministic --features-parquet cache path when caller didn't provide one.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--features-parquet", type=Path)
    parser.add_argument("--rebuild-features", action="store_true")
    parser.add_argument("--cache-only", action="store_true")
    args, _unknown = parser.parse_known_args(list(argv))

    if args.dataset is None or args.features_parquet is not None:
        return list(argv)

    dataset = Path(args.dataset).resolve()
    if not dataset.exists():
        return list(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir is not None else (ROOT / "artifacts/Saved_models/IF")
    cache_path = _derive_if_cache_path(dataset, output_dir)

    out = list(argv) + ["--features-parquet", str(cache_path)]
    if not cache_path.exists() and not args.rebuild_features:
        # First run for this dataset fingerprint should force cache build.
        out.append("--rebuild-features")
    return out


def main(argv: Sequence[str] | None = None) -> int:
    # Delegates to the original streaming trainer, but auto-injects a deterministic feature cache.
    effective_argv = _inject_default_feature_cache(sys.argv[1:] if argv is None else argv)
    try:
        from training.stream_suricata_training import main as _stream_main  # type: ignore
    except Exception as e:
        print(
            "[ERROR] Missing training.stream_suricata_training backend. "
            "Isolation Forest pipeline cannot run in this workspace state.\n"
            f"Import error: {e}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    old = sys.argv
    try:
        sys.argv = [old[0]] + effective_argv
        return _stream_main()
    finally:
        sys.argv = old


if __name__ == "__main__":
    sys.exit(main())

