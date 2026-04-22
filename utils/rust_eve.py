"""
Optional Rust-accelerated EVE flow → unified behavioral features (PyO3 extension `eve_extractor`).

Build (from primary repo ``Model2_development``):
  cd Model2_development/rust/eve_extractor && maturin develop --release

Disable at runtime:
  export EVE_EXTRACT_USE_RUST=0
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, List, Optional, Tuple, Type

_RUST_CLASS: Optional[Any] = None
_RUST_TRIED: bool = False


def rust_eve_extract_wanted() -> bool:
    v = os.environ.get("EVE_EXTRACT_USE_RUST", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def get_rust_unified_extractor_class() -> Optional[Any]:
    """Return `RustUnifiedExtractor` class if built & importable, else None."""
    global _RUST_CLASS, _RUST_TRIED
    if not rust_eve_extract_wanted():
        return None
    if _RUST_TRIED:
        return _RUST_CLASS
    _RUST_TRIED = True
    try:
        from eve_extractor import RustUnifiedExtractor  # type: ignore[import-untyped]

        _RUST_CLASS = RustUnifiedExtractor
    except ImportError:
        _RUST_CLASS = None
    return _RUST_CLASS


def join_eve_labels_parquet_native(
    eve_jsonl: Path,
    labels_csv: Path,
    output_parquet: Path,
    *,
    use_subclass: bool = False,
) -> int:
    """
    Full native path: Rust opens EVE JSONL, extracts features, joins labels, writes Parquet.
    Releases the GIL for the entire run.

    ``labels_csv`` must be a small export with headers ``identity_key``, ``binary_label``
    (and ``attack_subclass`` if ``use_subclass``), produced from Python ``_prepare_labels_csv``.
    """
    try:
        from eve_extractor import join_eve_labels_to_parquet  # type: ignore[import-untyped]
    except ImportError as e:
        raise RuntimeError(
            "join_eve_labels_to_parquet missing from eve_extractor. Rebuild with arrow/parquet: "
            "cd Model2_development/rust/eve_extractor && maturin develop --release"
        ) from e
    n = join_eve_labels_to_parquet(
        str(eve_jsonl.resolve()),
        str(labels_csv.resolve()),
        str(output_parquet.resolve()),
        use_subclass,
    )
    return int(n)


def unpack_rust_process_batch(engine: Any, lines: List[str]) -> Tuple[Any, Any, Any, Any, Any]:
    """
    ``process_batch`` must return exactly 5 elements (Rust ≥ split flow_id/flow_key).

    Stale wheels return 4 values and will raise with a rebuild hint.
    """
    out = engine.process_batch(lines)
    try:
        n = len(out)
    except TypeError as e:
        raise RuntimeError(
            "eve_extractor.process_batch did not return a sequence; rebuild the extension: "
            "cd Model2_development/rust/eve_extractor && maturin develop --release"
        ) from e
    if n != 5:
        raise RuntimeError(
            f"eve_extractor.process_batch returned {n} values (expected 5: is_flow, idx, "
            "flow_ids, flow_keys, feature_bytes). Rebuild: "
            "cd Model2_development/rust/eve_extractor && maturin develop --release"
        )
    return out[0], out[1], out[2], out[3], out[4]


def assert_rust_extractor_matches_python_schema(engine: Any) -> int:
    """
    Ensure the compiled eve_extractor matches Python schema:

    - Row width vs `N_UNIFIED_BEHAVIORAL_FEATURES` / `UNIFIED_BEHAVIORAL_FEATURE_NAMES`.
    - `FLOW_KEY_BUCKET_SEC` vs `ingestion.flow_identity.FLOW_KEY_BUCKET_SEC`.

    Stale wheels (wrong N_FEATURES) cause batch reshape errors; bucket mismatch causes join misses.
    """
    from ingestion.flow_identity import FLOW_KEY_BUCKET_SEC
    from ingestion.unified_behavioral_schema import N_UNIFIED_BEHAVIORAL_FEATURES

    py_n = N_UNIFIED_BEHAVIORAL_FEATURES
    rust_n = int(getattr(engine, "n_features", py_n))
    if rust_n != py_n:
        raise RuntimeError(
            f"eve_extractor reports n_features={rust_n} but Python "
            f"N_UNIFIED_BEHAVIORAL_FEATURES={py_n}. The installed wheel is out of sync.\n"
            f"Rebuild: cd Model2_development/rust/eve_extractor && maturin develop --release"
        )
    try:
        import eve_extractor as ee  # type: ignore[import-untyped]

        mod_n = int(ee.N_FEATURES)
        if mod_n != py_n:
            raise RuntimeError(
                f"eve_extractor.N_FEATURES={mod_n} != Python N_UNIFIED_BEHAVIORAL_FEATURES={py_n}. "
                f"Rebuild: cd Model2_development/rust/eve_extractor && maturin develop --release"
            )
        rb = float(ee.FLOW_KEY_BUCKET_SEC)
        if abs(rb - FLOW_KEY_BUCKET_SEC) > 1e-9:
            raise RuntimeError(
                f"eve_extractor.FLOW_KEY_BUCKET_SEC={rb} != Python FLOW_KEY_BUCKET_SEC={FLOW_KEY_BUCKET_SEC}. "
                f"Rebuild: cd Model2_development/rust/eve_extractor && maturin develop --release"
            )
    except AttributeError:
        pass  # Older wheel without module-level constants; engine.n_features + bucket check above still guard width
    return rust_n
