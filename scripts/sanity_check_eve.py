#!/usr/bin/env python3
"""
Sanity-check Suricata EVE JSONL without loading the whole file.

Reports:
  - event_type counts (streaming)
  - For flow events: sample of dest_port distribution (optional reservoir sample)
  - Optional: one extracted feature row (needs Model2_development on PYTHONPATH)

Usage (from Model2_development/):
  python3 scripts/sanity_check_eve_composition.py Datasets/BenignHeavy/master_eve.json
  python3 scripts/sanity_check_eve_composition.py path/to/eve.json --sample-flow-features
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

# Project root for optional feature extraction
ROOT = Path(__file__).resolve().parent.parent


def stream_event_types(path: Path, max_lines: Optional[int] = None) -> Counter:
    c: Counter = Counter()
    n = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if max_lines is not None and n >= max_lines:
                break
            n += 1
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                c["__json_error__"] += 1
                continue
            if not isinstance(ev, dict):
                continue
            et = ev.get("event_type", "__missing__")
            c[str(et)] += 1
    return c


def reservoir_dst_ports_flows(
    path: Path,
    k: int,
    max_lines: Optional[int],
) -> List[int]:
    """Reservoir sample of dest_port from flow events (uniform over flows seen)."""
    sample: List[int] = []
    seen = 0
    n = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if max_lines is not None and n >= max_lines:
                break
            n += 1
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(ev, dict) or ev.get("event_type") != "flow":
                continue
            dp = ev.get("dest_port")
            try:
                port = int(dp) if dp is not None else -1
            except (TypeError, ValueError):
                port = -1
            seen += 1
            if len(sample) < k:
                sample.append(port)
            else:
                j = random.randint(1, seen)
                if j <= k:
                    sample[j - 1] = port
    return sample


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("eve", type=Path, help="Path to EVE JSONL")
    ap.add_argument(
        "--max-lines",
        type=int,
        default=None,
        help="Stop after this many non-empty lines (default: entire file)",
    )
    ap.add_argument(
        "--port-sample",
        type=int,
        default=5000,
        help="Reservoir sample size of flow dest_port (0=skip)",
    )
    ap.add_argument(
        "--sample-flow-features",
        action="store_true",
        help="Extract features for first valid flow (imports ingestion/)",
    )
    args = ap.parse_args()

    if not args.eve.exists():
        print(f"ERROR: file not found: {args.eve}", file=sys.stderr)
        return 1

    print(f"File: {args.eve}")
    print("Counting event_type (streaming)...")
    counts = stream_event_types(args.eve, max_lines=args.max_lines)
    total = sum(counts.values())
    print(f"Lines parsed (with dict events): {total}")
    for et, n in counts.most_common(30):
        pct = 100.0 * n / total if total else 0.0
        print(f"  {et!r}: {n} ({pct:.2f}%)")
    if len(counts) > 30:
        print(f"  ... ({len(counts)} distinct event_type values)")

    only_flow = len(counts) <= 2 and counts.get("flow", 0) > 0 and all(
        k in ("flow", "stats", "__json_error__", "__missing__") for k in counts
    )
    if only_flow:
        print(
            "\n>>> Composition looks flow-centric (flows dominate; little/no http/dns/tls in file)."
        )
        print(
            "    That usually means the Suricata run that wrote this file used a config"
        )
        print(
            "    that only enabled those EVE types, OR a different config than you expect."
        )

    if args.port_sample > 0:
        random.seed(42)
        ports = reservoir_dst_ports_flows(args.eve, args.port_sample, args.max_lines)
        if ports:
            pc = Counter(ports)
            print(f"\nTop dest_port values in reservoir sample (n={len(ports)}):")
            for p, n in pc.most_common(15):
                print(f"  port {p}: {n}")

    if args.sample_flow_features:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from ingestion.src_ip_temporal_features import SrcIpTemporalTracker
        from ingestion.unified_behavioral_pipeline import (
            BehavioralExtractorUnified,
            DstPortVariance300Tracker,
            DstUniqueSrcIps60Tracker,
            FlowInterarrivalVariance300Tracker,
            SrcFlowCount300Tracker,
            TCPFlagEntropyTracker,
            TLSBehaviorTracker,
            WINDOW_60_SEC,
            extract_unified_behavioral_row,
        )
        from ingestion.unified_behavioral_schema import (
            FEATURE_BOUNDS,
            UNIFIED_BEHAVIORAL_FEATURE_NAMES,
            DEFAULT_FILL,
        )
        from ingestion.unified_behavioral_pipeline import SanityCheck

        behavioral = BehavioralExtractorUnified()
        tls_t = TLSBehaviorTracker(window_sec=WINDOW_60_SEC)
        tcp_t = TCPFlagEntropyTracker(window_sec=WINDOW_60_SEC)
        dst_var_t = DstPortVariance300Tracker()
        iat_var_t = FlowInterarrivalVariance300Tracker()
        dst_unique_t = DstUniqueSrcIps60Tracker()
        src_flow_t = SrcFlowCount300Tracker()
        temporal = SrcIpTemporalTracker()
        sanity = SanityCheck(UNIFIED_BEHAVIORAL_FEATURE_NAMES, FEATURE_BOUNDS, DEFAULT_FILL)
        first: Optional[Dict[str, Any]] = None
        with args.eve.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(ev, dict) and ev.get("event_type") == "flow":
                    first = ev
                    break
        if not first:
            print("\nNo flow event found for --sample-flow-features.")
            return 0
        row = extract_unified_behavioral_row(
            first,
            behavioral,
            tls_t,
            tcp_t,
            dst_var_t,
            iat_var_t,
            dst_unique_t,
            src_flow_t,
            temporal,
        )
        fixed = sanity.check_and_fix(row)
        nz = [k for k in UNIFIED_BEHAVIORAL_FEATURE_NAMES if fixed.get(k, 0) != 0]
        print("\nFirst flow: non-zero feature names (sanity):")
        for k in nz[:40]:
            print(f"  {k} = {fixed[k]}")
        if len(nz) > 40:
            print(f"  ... and {len(nz) - 40} more non-zero")
        print(f"\nTotal non-zero of {len(UNIFIED_BEHAVIORAL_FEATURE_NAMES)}: {len(nz)}")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
