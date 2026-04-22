#!/usr/bin/env python3
"""
Stratified benign subsample: preserve diversity across CICIDS benign CSVs (by source file + proto).

Typical layout (benign ground-truth CSVs live under ``CSV/``):

  Refined_Training_Dataset/CSV/benign_Friday-02-03-2018.csv
  Refined_Training_Dataset/CSV/benign_Tuesday-20-02-2018.csv
  ... (see CICIDS_CONTEXT_BENIGN_FILES)

Usage (pass dataset root — script will use ``CSV/`` if no benign_*.csv in root):

  python3 scripts/stratify_benign_799k.py \\
    --data-dir /path/to/Refined_Training_Dataset \\
    --output benign_stratified_799k.csv

Or point directly at the CSV folder:

  python3 scripts/stratify_benign_799k.py --data-dir /path/to/Refined_Training_Dataset/CSV

Default sources: CICIDS weekday benigns + ``benign_Backdoor.csv`` (excludes benign_DoS / benign_Recon).
Use ``--all-benign-csv`` to include every other ``benign_*.csv`` in that directory.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

TARGET_N = 799_074
RANDOM_STATE = 42
CHUNK_SIZE = 500_000

EXCLUDED_FILES = frozenset(
    {
        "benign_dos.csv",
        "benign_recon.csv",
    }
)

# CICIDS capture days + TON IoT-style Backdoor benign (matches Refined_Training_Dataset/CSV layout).
CICIDS_CONTEXT_BENIGN_FILES = frozenset(
    {
        "benign_friday-02-03-2018.csv",
        "benign_tuesday-20-02-2018.csv",
        "benign_wednesday-14-02-2018.csv",
        "benign_wednesday-21-02-2018.csv",
        "benign_backdoor.csv",
    }
)


def resolve_search_directory(root: Path, csv_subdir: str) -> Path:
    """
    If ``root`` has no benign_*.csv but ``root/csv_subdir`` does (e.g. CSV/), use the subfolder.
    """
    root = root.resolve()
    if not root.is_dir():
        raise FileNotFoundError(str(root))
    if any(root.glob("benign_*.csv")):
        return root
    sub = root / csv_subdir
    if sub.is_dir() and any(sub.glob("benign_*.csv")):
        print(f"[INFO] Using {csv_subdir}/ for benign_*.csv (none in data-dir root).", file=sys.stderr)
        return sub.resolve()
    return root


def discover_benign_csvs(search_dir: Path, cicids_context_only: bool) -> List[Path]:
    paths = sorted(search_dir.glob("benign_*.csv"))
    out: List[Path] = []
    for p in paths:
        low = p.name.lower()
        if low in EXCLUDED_FILES:
            continue
        if cicids_context_only and low not in CICIDS_CONTEXT_BENIGN_FILES:
            continue
        out.append(p)
    return out


def _valid_mask(df: pd.DataFrame) -> pd.Series:
    if "label" not in df.columns:
        raise ValueError("CSV missing required column: label")
    ok = df["label"].notna()
    if "flow_id" not in df.columns:
        raise ValueError("CSV missing required column: flow_id")
    fid = df["flow_id"]
    ok &= fid.notna()
    ok &= fid.astype(str).str.strip().ne("") & fid.astype(str).str.lower().ne("nan")
    return ok


def count_strata_chunked(path: Path) -> Tuple[Dict[str, int], int]:
    """Return (counts per proto -> n valid rows), total valid rows for this file."""
    per_proto: Dict[str, int] = defaultdict(int)
    total = 0
    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE, low_memory=False):
        if "proto" not in chunk.columns:
            chunk["proto"] = "UNKNOWN"
        chunk["proto"] = chunk["proto"].fillna("UNKNOWN").astype(str)
        m = _valid_mask(chunk)
        sub = chunk.loc[m, "proto"]
        vc = sub.value_counts()
        for proto, c in vc.items():
            per_proto[str(proto)] += int(c)
        total += int(m.sum())
    return dict(per_proto), total


def allocate_exact_int(weights: Dict[str, int], n: int) -> Dict[str, int]:
    """Largest-remainder: nonnegative integer quotas summing to exactly n."""
    keys = [k for k, w in weights.items() if w > 0]
    if not keys:
        return {k: 0 for k in weights}
    w_arr = np.array([weights[k] for k in keys], dtype=np.float64)
    s = float(w_arr.sum())
    if s <= 0:
        return {k: 0 for k in weights}
    raw = n * w_arr / s
    base = np.floor(raw).astype(np.int64)
    rem = int(n - base.sum())
    frac = raw - base
    order = np.argsort(-frac)
    for i in range(rem):
        base[order[i]] += 1
    return {keys[i]: int(base[i]) for i in range(len(keys))}


def allocate_nested(
    file_totals: Dict[str, int],
    file_proto: Dict[str, Dict[str, int]],
    n: int,
) -> Dict[str, Dict[str, int]]:
    """Per-file quotas summing to n; within each file, per-proto quotas summing to file quota."""
    f_quotas = allocate_exact_int(file_totals, n)
    out: Dict[str, Dict[str, int]] = {}
    for fname, fq in f_quotas.items():
        if fq <= 0:
            out[fname] = {}
            continue
        pcounts = file_proto[fname]
        out[fname] = allocate_exact_int(pcounts, fq)
    return out


def cap_quotas_to_availability(
    quotas: Dict[str, Dict[str, int]],
    avail: Dict[str, Dict[str, int]],
    target_n: int,
) -> Dict[str, Dict[str, int]]:
    """
    Clip requested (file, proto) quotas to observed counts, then greedily add rows up to target_n
    where spare capacity exists (avoids shortfall when a stratum is empty in data).
    """
    out: Dict[str, Dict[str, int]] = {}
    for fname, pq in quotas.items():
        if fname not in out:
            out[fname] = {}
        for proto, q in pq.items():
            cap = avail.get(fname, {}).get(proto, 0)
            out[fname][proto] = min(q, cap)

    for fname, pmap in avail.items():
        if fname not in out:
            out[fname] = {}
        for proto in pmap:
            out[fname].setdefault(proto, 0)

    def total_assigned() -> int:
        return sum(sum(d.values()) for d in out.values())

    need = target_n - total_assigned()
    while need > 0:
        best_f, best_p, best_spare = "", "", -1
        for fname, pmap in avail.items():
            for proto, cap in pmap.items():
                spare = cap - out[fname].get(proto, 0)
                if spare > best_spare:
                    best_spare, best_f, best_p = spare, fname, proto
        if best_spare <= 0:
            break
        out[best_f][best_p] = out[best_f].get(best_p, 0) + 1
        need -= 1
    return out


def _trim_excess_deterministic(df: pd.DataFrame, drop_n: int) -> pd.DataFrame:
    if drop_n <= 0:
        return df
    sort_cols = [c for c in ("flow_key", "source_file", "proto", "timestamp") if c in df.columns]
    if sort_cols:
        s = df.sort_values(sort_cols, kind="mergesort")
    else:
        s = df.sort_index(kind="mergesort")
    return s.iloc[:-drop_n].reset_index(drop=True)


def sample_file(
    path: Path,
    source_name: str,
    proto_quotas: Dict[str, int],
) -> pd.DataFrame:
    """Load one file, filter valid rows, sample without replacement per proto."""
    df = pd.read_csv(path, low_memory=False)
    if "proto" not in df.columns:
        df["proto"] = "UNKNOWN"
    df["proto"] = df["proto"].fillna("UNKNOWN").astype(str)
    m = _valid_mask(df)
    df = df.loc[m].copy()
    df["source_file"] = source_name

    picks: List[pd.DataFrame] = []
    for proto, k in proto_quotas.items():
        if k <= 0:
            continue
        pool = df[df["proto"] == proto]
        if pool.empty:
            continue
        take = min(k, len(pool))
        if take > 0:
            picks.append(pool.sample(n=take, random_state=RANDOM_STATE, replace=False))

    if not picks:
        return df.iloc[:0].copy()

    out = pd.concat(picks, ignore_index=True)
    out["label"] = 0
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Stratified benign sample to exactly 799,074 rows.")
    ap.add_argument(
        "--data-dir",
        type=Path,
        required=True,
        help="Dataset root (e.g. Refined_Training_Dataset) or path to the folder containing benign_*.csv",
    )
    ap.add_argument(
        "--csv-subdir",
        type=str,
        default="CSV",
        help="If data-dir has no benign_*.csv, try this subdirectory (default: CSV)",
    )
    ap.add_argument(
        "--all-benign-csv",
        action="store_true",
        help="Use every benign_*.csv in the search directory (still excludes DoS/Recon). "
        "Default: only the five CICIDS-context files (four 2018 days + Backdoor).",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=Path("benign_stratified_799k.csv"),
        help="Output CSV path",
    )
    ap.add_argument("--target-n", type=int, default=TARGET_N, help="Exact output row count")
    args = ap.parse_args()

    try:
        data_dir = resolve_search_directory(args.data_dir, args.csv_subdir)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    if not data_dir.is_dir():
        print(f"Error: not a directory: {data_dir}", file=sys.stderr)
        return 1

    cicids_only = not args.all_benign_csv
    files = discover_benign_csvs(data_dir, cicids_context_only=cicids_only)
    if not files:
        hint = (
            f"Expected under {data_dir}:\n  "
            + "\n  ".join(sorted(CICIDS_CONTEXT_BENIGN_FILES))
            + "\n  (and not empty after label/flow_id filters). Try --all-benign-csv or fix --data-dir."
        )
        print(f"Error: no matching benign_*.csv in {data_dir}\n{hint}", file=sys.stderr)
        return 1
    if cicids_only and len(files) < len(CICIDS_CONTEXT_BENIGN_FILES):
        missing = sorted(CICIDS_CONTEXT_BENIGN_FILES - {f.name.lower() for f in files})
        print(
            f"[WARN] CICIDS-context mode: only {len(files)}/{len(CICIDS_CONTEXT_BENIGN_FILES)} files found; "
            f"proportions use available files only. Missing (not on disk or wrong name): {missing}",
            file=sys.stderr,
        )
    print(f"[INFO] Search directory: {data_dir}", file=sys.stderr)
    print(f"[INFO] Input files ({len(files)}): {[p.name for p in files]}", file=sys.stderr)

    # Pass 1: counts
    file_totals: Dict[str, int] = {}
    file_proto: Dict[str, Dict[str, int]] = {}
    for p in files:
        key = p.name
        pcounts, tot = count_strata_chunked(p)
        if tot <= 0:
            continue
        file_proto[key] = pcounts
        file_totals[key] = tot

    grand_total = sum(file_totals.values())
    if grand_total < args.target_n:
        print(
            f"Error: only {grand_total:,} valid rows (need {args.target_n:,}).",
            file=sys.stderr,
        )
        return 1

    raw_quotas = allocate_nested(file_totals, file_proto, args.target_n)
    quotas = cap_quotas_to_availability(raw_quotas, file_proto, args.target_n)

    # Pass 2: sample per file
    parts: List[pd.DataFrame] = []
    for p in files:
        key = p.name
        pq = quotas.get(key, {})
        if not pq or sum(pq.values()) == 0:
            continue
        parts.append(sample_file(p, key, pq))

    combined = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()
    combined["label"] = 0

    if len(combined) > args.target_n:
        combined = _trim_excess_deterministic(combined, len(combined) - args.target_n)
    elif len(combined) < args.target_n:
        need = args.target_n - len(combined)
        # Fill from largest files: reload and take rows not in combined (by flow_id if present)
        existing_keys = set()
        if "flow_id" in combined.columns:
            existing_keys = set(combined["flow_id"].astype(str) + "|" + combined["source_file"].astype(str))

        extra_rows: List[pd.DataFrame] = []
        files_by_size = sorted(files, key=lambda fp: file_totals.get(fp.name, 0), reverse=True)
        for p in files_by_size:
            if need <= 0:
                break
            df = pd.read_csv(p, low_memory=False)
            if "proto" not in df.columns:
                df["proto"] = "UNKNOWN"
            df["proto"] = df["proto"].fillna("UNKNOWN").astype(str)
            m = _valid_mask(df)
            df = df.loc[m].copy()
            df["source_file"] = p.name
            df["label"] = 0
            if existing_keys and "flow_id" in df.columns:
                k = df["flow_id"].astype(str) + "|" + df["source_file"].astype(str)
                df = df.loc[~k.isin(existing_keys)]
            take = min(need, len(df))
            if take > 0:
                add = df.sample(n=take, random_state=RANDOM_STATE + 11, replace=False)
                extra_rows.append(add)
                need -= take
                if "flow_id" in combined.columns:
                    existing_keys.update(
                        add["flow_id"].astype(str) + "|" + add["source_file"].astype(str)
                    )
        if extra_rows:
            combined = pd.concat([combined] + extra_rows, ignore_index=True)
        if len(combined) < args.target_n:
            print(
                f"Error: could not fill to {args.target_n:,} without replacement (got {len(combined):,}).",
                file=sys.stderr,
            )
            return 1
        if len(combined) > args.target_n:
            combined = _trim_excess_deterministic(combined, len(combined) - args.target_n)

    # Validation output (required)
    total = len(combined)
    per_file = combined["source_file"].value_counts()
    print("=== stratified benign validation ===")
    print(f"total_rows: {total:,}")
    print("rows_per_source_file:")
    for name in sorted(per_file.index):
        c = int(per_file[name])
        pct = 100.0 * c / total if total else 0.0
        print(f"  {name}: {c:,} ({pct:.4f}%)")

    combined.to_csv(args.output, index=False)
    print(f"wrote: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
