#!/usr/bin/env python3
"""
Generic stratified downsampling for attack/benign label CSVs.

Goal
- Reduce large classes (e.g. DoS) without collapsing behavioral diversity.

How
- Downsample each selected class using multi-axis strata:
  1) time_bucket (timestamp, coarse; e.g. 60s)
  2) time_phase (optional) equal-width bins over the class's real time span so early
     traffic (e.g. standard DoS) and later traffic (e.g. outage DoS) both get quota
  3) event_type (flow/http/...)
  4) src_ip (capped contribution per source)
  5) dst_port_bucket (well-known / registered / dynamic)
  6) duration_bucket (if duration-like column exists)

Notes
- **Only** classes named in `--target` are downsampled. Smaller families (Bruteforce, DDoS, …)
  stay at full size unless you also `--target` them — so they are never “crushed” by the script.
- After downsampling a huge class (e.g. DoS), that class can still **dominate the row mix** vs
  smaller attacks. Use **`--relative-cap-factor`** to auto-cap each `--target` at
  `factor × (max count among classes not in --target)` so e.g. DoS ≤ 2× the largest other family.
- If flow_key exists, optional dedup can enforce one row per flow_key.
- Use --label-col attack_subclass when coarse families (DoS, Bruteforce, …) live there.

Example (rough class totals: DoS ~28M, others ~500k combined):
  # Cap DoS at 2× the largest *other* family (e.g. Backdoor ~124k → ceiling ~248k), plus phases.
  python3 scripts/downsample_stratified_labels.py \\
    --input-csv attacks_all.csv --output-csv attacks_balanced.csv \\
    --label-col attack_subclass \\
    --target dos=999999999 \\
    --relative-cap-factor 2 \\
    --phase-buckets 3 \\
    --time-bucket-sec 60 --dedup-flow-key

Examples
1) Cap only DoS to 250k:
   python3 scripts/downsample_stratified_labels.py \
     --input-csv attack_all.csv --output-csv attack_all_ds.csv \
     --target dos=250000

2) Cap multiple classes:
   python3 scripts/downsample_stratified_labels.py \
     --input-csv attack_all.csv --output-csv attack_all_ds.csv \
     --target dos=300000 --target recon=120000 --target backdoor=120000

3) Keep one row per flow key:
   python3 scripts/downsample_stratified_labels.py ... --dedup-flow-key
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd


def _choose_label_col(df: pd.DataFrame, override: str | None) -> str:
    if override:
        if override not in df.columns:
            raise ValueError(f"--label-col {override!r} not in CSV columns")
        return override
    for c in ("attack_type", "attack_subclass", "attack_family", "label", "class"):
        if c in df.columns:
            return c
    raise ValueError(
        "Could not find label column. Pass --label-col or add one of: "
        "attack_type, attack_subclass, attack_family, label, class"
    )


def _choose_time_col(df: pd.DataFrame) -> str | None:
    for c in ("timestamp", "flow_start", "time", "ts"):
        if c in df.columns:
            return c
    return None


def _choose_duration_col(df: pd.DataFrame) -> str | None:
    for c in ("duration", "flow_duration", "age", "flow_age"):
        if c in df.columns:
            return c
    return None


def _dst_port_bucket(series: pd.Series) -> pd.Series:
    x = pd.to_numeric(series, errors="coerce").fillna(-1)
    out = pd.Series(np.where(x < 0, "unknown", "dynamic"), index=series.index, dtype="object")
    out[(x >= 0) & (x <= 1023)] = "well_known"
    out[(x >= 1024) & (x <= 49151)] = "registered"
    return out


def _duration_bucket(series: pd.Series) -> pd.Series:
    x = pd.to_numeric(series, errors="coerce")
    # Bucket edges chosen to separate microflows from medium/long flows.
    bins = [-np.inf, 0.05, 0.5, 2.0, 10.0, np.inf]
    labels = ["d_micro", "d_short", "d_medium", "d_long", "d_very_long"]
    return pd.cut(x, bins=bins, labels=labels).astype("object").fillna("d_unknown")


def _add_time_phase_column(df: pd.DataFrame, time_col: str, phase_buckets: int) -> None:
    """
    In-place: assign time_phase = phase_0..phase_{B-1} by equal-width wall-clock span
    within this dataframe (typically one attack family). Preserves early vs late regimes
    when allocating a downsample budget (e.g. standard DoS then outage DoS later).
    """
    if phase_buckets <= 1:
        df["time_phase"] = "phase_0"
        return
    ts = pd.to_datetime(df[time_col], utc=True, errors="coerce")
    df["time_phase"] = "phase_unknown"
    mask = ts.notna()
    if not bool(mask.any()):
        return
    t_ns = ts.loc[mask].astype("int64").to_numpy(dtype=np.int64)
    lo = float(np.min(t_ns))
    hi = float(np.max(t_ns))
    if hi <= lo:
        df.loc[mask, "time_phase"] = "phase_0"
        return
    rel = (t_ns.astype(np.float64) - lo) / (hi - lo)
    rel = np.clip(rel, 0.0, 1.0)
    bid = np.minimum((rel * phase_buckets).astype(np.int64), phase_buckets - 1)
    phases = np.array([f"phase_{int(i)}" for i in bid], dtype=object)
    df.loc[mask, "time_phase"] = phases


def _allocate_exact(weights: pd.Series, total: int) -> Dict[object, int]:
    if total <= 0 or weights.empty:
        return {}
    w = weights.astype(float)
    if float(w.sum()) <= 0:
        w = pd.Series(np.ones(len(w)), index=w.index, dtype=float)
    probs = (w / w.sum()).to_numpy()
    raw = probs * total
    base = np.floor(raw).astype(int)
    rem = int(total - base.sum())
    if rem > 0:
        frac = raw - base
        order = np.argsort(-frac)
        for i in order[:rem]:
            base[i] += 1
    out: Dict[object, int] = {}
    for k, v in zip(w.index, base):
        if v > 0:
            out[k] = int(v)
    return out


def _parse_targets(items: List[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Invalid --target '{item}'. Expected format class=count")
        k, v = item.split("=", 1)
        k = k.strip().lower()
        out[k] = int(v)
        if out[k] < 0:
            raise ValueError(f"Target count must be >= 0 for class '{k}'")
    return out


def _apply_relative_cap_factor(
    df: pd.DataFrame,
    label_col: str,
    targets: Dict[str, int],
    factor: float | None,
    exclude_from_baseline_lower: set[str],
) -> Tuple[Dict[str, int], int | None]:
    """
    Shrink each target toward parity with smaller classes: for each class in ``targets``,
    use min(requested, ceil(factor * M)) where M is the max per-class count among labels
    that are not in ``targets`` and not in ``exclude_from_baseline_lower``.
    """
    if factor is None or factor <= 0:
        return dict(targets), None
    vc = df[label_col].astype(str).str.lower().value_counts()
    tgt = set(targets.keys())
    max_other = 0
    for lab, cnt in vc.items():
        if lab in tgt or lab in exclude_from_baseline_lower:
            continue
        max_other = max(max_other, int(cnt))
    if max_other <= 0:
        print(
            "[WARN] --relative-cap-factor has no effect: every row is a --target class (or only "
            "excluded labels exist). M=max(non-target counts)=0, so your huge --target cap is unchanged. "
            "Fix: use a combined attack CSV that includes other families (Bruteforce, DDoS, …), or set "
            "an explicit --target dos=250000 instead.",
            file=sys.stderr,
        )
        return dict(targets), None
    ceiling = max(1, int(np.ceil(max_other * factor)))
    out = {k: min(v, ceiling) for k, v in targets.items()}
    return out, ceiling


def _read_labels_csv(path: Path) -> pd.DataFrame:
    """Load full CSV (downsample needs all columns for output). Warn on huge files; try PyArrow parser."""
    path = Path(path)
    if path.exists():
        sz = path.stat().st_size
        if sz >= 500_000_000:
            print(
                f"[WARN] Input is {sz / (1024**3):.2f} GiB — expect several minutes and large RAM for a full load.",
                file=sys.stderr,
            )
        elif sz >= 80_000_000:
            print(
                f"[INFO] Input is {sz / (1024**2):.0f} MiB; loading full CSV into memory…",
                file=sys.stderr,
            )
    try:
        return pd.read_csv(path, engine="pyarrow")
    except (ImportError, ValueError, TypeError, OSError):
        return pd.read_csv(path, low_memory=False)


def _stratified_sample(
    cls_df: pd.DataFrame,
    target_n: int,
    per_src_cap: int,
    min_per_stratum: int,
    seed: int,
    gcols: List[str],
) -> pd.DataFrame:
    if target_n <= 0:
        return cls_df.iloc[:0].copy()
    if len(cls_df) <= target_n:
        return cls_df.copy()

    n_rows = len(cls_df)
    if n_rows > 500_000:
        print(
            f"[INFO] Stratified sample: grouping {n_rows:,} rows on {gcols} (may take a few minutes)…",
            file=sys.stderr,
            flush=True,
        )

    gb = cls_df.groupby(gcols, dropna=False, sort=False)
    sizes = gb.size()
    alloc = _allocate_exact(sizes, target_n)

    if n_rows > 500_000:
        print(
            f"[INFO] {len(alloc):,} strata; drawing per-stratum samples (no long silent hang)…",
            file=sys.stderr,
            flush=True,
        )

    picks: List[pd.DataFrame] = []
    strata_done = 0
    strata_with_quota = sum(1 for v in alloc.values() if v > 0)
    for key, n in alloc.items():
        if n <= 0:
            continue
        try:
            chunk = gb.get_group(key)
        except KeyError:
            continue
        if chunk.empty:
            continue

        # Source cap first to avoid one attacker/source dominating.
        chunk = chunk.sample(frac=1.0, random_state=seed)
        chunk = chunk.groupby("src_ip_strat", group_keys=False).head(per_src_cap)

        k = min(len(chunk), max(min_per_stratum, n))
        picks.append(chunk.sample(n=k, random_state=seed) if len(chunk) > k else chunk)

        strata_done += 1
        if n_rows > 500_000 and strata_done % 2000 == 0:
            print(
                f"[INFO]   … {strata_done:,} / {strata_with_quota:,} strata processed",
                file=sys.stderr,
                flush=True,
            )

    sampled = pd.concat(picks, ignore_index=False) if picks else cls_df.iloc[:0].copy()

    # Trim overshoot or top-up undershoot from remaining rows in class.
    if len(sampled) > target_n:
        sampled = sampled.sample(n=target_n, random_state=seed)
    elif len(sampled) < target_n:
        need = target_n - len(sampled)
        remaining = cls_df.drop(index=sampled.index, errors="ignore")
        if len(remaining) > 0:
            add_n = min(need, len(remaining))
            sampled = pd.concat([sampled, remaining.sample(n=add_n, random_state=seed)], ignore_index=False)

    return sampled


def downsample(
    df: pd.DataFrame,
    targets: Dict[str, int],
    time_bucket_sec: int,
    per_src_cap: int,
    min_per_stratum: int,
    dedup_flow_key: bool,
    seed: int,
    label_col_override: str | None,
    phase_buckets: int,
    extra_strata_cols: List[str],
) -> pd.DataFrame:
    label_col = _choose_label_col(df, label_col_override)
    work = df.copy()

    # Strat columns
    time_col = _choose_time_col(work)
    if time_col is not None:
        ts = pd.to_datetime(work[time_col], utc=True, errors="coerce")
        # pandas >=2 removed Series.view for this path; astype is compatible.
        t_ns = ts.astype("int64")
        b_ns = int(max(1, time_bucket_sec)) * 1_000_000_000
        work["time_bucket"] = np.where(ts.notna(), (t_ns // b_ns).astype(str), "t_unknown")
    else:
        work["time_bucket"] = "t_unknown"

    work["event_type_strat"] = work["event_type"].astype(str) if "event_type" in work.columns else "event_unknown"
    work["src_ip_strat"] = work["src_ip"].astype(str) if "src_ip" in work.columns else "src_unknown"
    work["dst_port_bucket"] = _dst_port_bucket(work["dst_port"]) if "dst_port" in work.columns else "unknown"

    dcol = _choose_duration_col(work)
    if dcol is not None:
        work["duration_bucket"] = _duration_bucket(work[dcol])
    else:
        work["duration_bucket"] = "d_unknown"

    # Preserve every non-target class as-is.
    lower_labels = work[label_col].astype(str).str.lower()
    target_set = set(targets.keys())
    keep_parts = [work[~lower_labels.isin(target_set)]]

    base_gcols = ["time_bucket", "event_type_strat", "dst_port_bucket", "duration_bucket"]
    for col in extra_strata_cols:
        if col not in work.columns:
            raise ValueError(f"--extra-strata-cols: column {col!r} not in CSV")
        safe = f"_strata_{col}"
        work[safe] = work[col].astype(str).fillna("")
        base_gcols.append(safe)

    for cls, target_n in targets.items():
        cdf = work[lower_labels == cls].copy()
        if cdf.empty:
            print(f"[WARN] class '{cls}' not found; skipping")
            continue
        if len(cdf) > 500_000:
            print(
                f"[INFO] Downsampling class {cls!r}: {len(cdf):,} rows → target {target_n:,}",
                file=sys.stderr,
                flush=True,
            )
        gcols = list(base_gcols)
        if phase_buckets > 1 and time_col is not None:
            _add_time_phase_column(cdf, time_col, phase_buckets)
            gcols.insert(1, "time_phase")
        sampled = _stratified_sample(
            cls_df=cdf,
            target_n=target_n,
            per_src_cap=per_src_cap,
            min_per_stratum=min_per_stratum,
            seed=seed,
            gcols=gcols,
        )
        keep_parts.append(sampled)

    if len(keep_parts) > 1 or (keep_parts and len(keep_parts[0]) > 500_000):
        print("[INFO] Concatenating parts…", file=sys.stderr, flush=True)
    out = pd.concat(keep_parts, ignore_index=True)

    if dedup_flow_key and "flow_key" in out.columns:
        print("[INFO] Deduplicating flow_key…", file=sys.stderr, flush=True)
        out = out.drop_duplicates(subset=["flow_key"], keep="first")

    # Drop helper cols and shuffle.
    drop_helpers = [
        "time_bucket",
        "time_phase",
        "event_type_strat",
        "src_ip_strat",
        "dst_port_bucket",
        "duration_bucket",
    ]
    for col in extra_strata_cols:
        drop_helpers.append(f"_strata_{col}")
    out = out.drop(columns=drop_helpers, errors="ignore")
    out = out.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generic stratified downsampler for label CSVs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--input-csv", required=True)
    ap.add_argument("--output-csv", required=True)
    ap.add_argument(
        "--target",
        action="append",
        default=[],
        help="Class target in form class=count; repeat for multiple classes (e.g. --target dos=250000)",
    )
    ap.add_argument("--time-bucket-sec", type=int, default=60)
    ap.add_argument("--per-src-cap", type=int, default=500)
    ap.add_argument("--min-per-stratum", type=int, default=10)
    ap.add_argument("--dedup-flow-key", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--label-col",
        default=None,
        help="Column for class names (e.g. attack_subclass for DoS/Bruteforce/Recon/...).",
    )
    ap.add_argument(
        "--phase-buckets",
        type=int,
        default=1,
        help="Within each downsampled class, split wall-clock span into N equal-width phases "
        "(default 1=off). Use 3–5 so early vs late traffic (e.g. standard vs outage DoS) both get quota.",
    )
    ap.add_argument(
        "--relative-cap-factor",
        type=float,
        default=None,
        help="Optional. Each --target count becomes min(requested, ceil(factor * M)) where M is the "
        "largest class count among labels NOT listed in --target (smaller attacks unchanged). "
        "Example: factor=2 with Bruteforce~112k and Backdoor~124k → M=124k → cap ~248k. "
        "Requires rows whose label is NOT in --target (e.g. a DoS-only CSV cannot compute M — use explicit "
        "--target dos=N or merge with other attack types). "
        "Use a huge --target dos=... as upper bound when M exists, then this tightens the cap.",
    )
    ap.add_argument(
        "--relative-cap-exclude",
        action="append",
        default=[],
        help="Lowercase label names to ignore when computing M (repeatable), e.g. benign so a huge "
        "benign column does not raise the cap.",
    )
    ap.add_argument(
        "--extra-strata-cols",
        default="",
        help="Comma-separated columns to add as stratification keys (e.g. dataset_day for merged benign).",
    )
    args = ap.parse_args()

    if not args.target:
        raise ValueError("Provide at least one --target class=count")

    targets = _parse_targets(args.target)

    df = _read_labels_csv(Path(args.input_csv))
    label_col = _choose_label_col(df, args.label_col)

    print("[INFO] Label column:", label_col)
    print("[INFO] Before counts:")
    print(df[label_col].astype(str).str.lower().value_counts(dropna=False).to_string())

    excl = {x.strip().lower() for x in args.relative_cap_exclude if x.strip()}
    targets, ceiling = _apply_relative_cap_factor(
        df, label_col, targets, args.relative_cap_factor, excl
    )
    if ceiling is not None:
        print(
            f"[INFO] Relative cap (factor={args.relative_cap_factor}): "
            f"per-target ceiling = {ceiling:,} (max non-target class × factor, exclusions={sorted(excl) or 'none'})",
            file=sys.stderr,
        )
        print("[INFO] Effective targets after relative cap:", targets)

    extra_strata = [c.strip() for c in args.extra_strata_cols.split(",") if c.strip()]

    out = downsample(
        df=df,
        targets=targets,
        time_bucket_sec=args.time_bucket_sec,
        per_src_cap=args.per_src_cap,
        min_per_stratum=args.min_per_stratum,
        dedup_flow_key=args.dedup_flow_key,
        seed=args.seed,
        label_col_override=args.label_col,
        phase_buckets=max(1, int(args.phase_buckets)),
        extra_strata_cols=extra_strata,
    )

    print("[INFO] After counts:")
    print(out[label_col].astype(str).str.lower().value_counts(dropna=False).to_string())

    out.to_csv(args.output_csv, index=False)
    print(f"[INFO] Wrote: {args.output_csv} (rows={len(out):,})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
