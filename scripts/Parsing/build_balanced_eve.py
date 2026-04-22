#!/usr/bin/env python3
"""
Build a balanced Suricata eve.json (NDJSON) from a refined dataset.

Two modes:

1) Directory mode (attacks_all.csv + benign_all.csv + master_eve.json):

   Refined_Training_Dataset/
       attacks_all.csv
       benign_all.csv
       master_eve.json

   python build_balanced_eve.py --dataset-dir Refined_Training_Dataset

2) Direct mode (rf_labels.csv + merged_eve.json):

   python build_balanced_eve.py \\
       --labels-csv path/to/rf_labels.csv \\
       --eve path/to/merged_eve.json \\
       --output path/to/balanced_eve.json

The script:

- Loads flow_key values from the CSV(s) (rf_labels.csv or attacks_all + benign_all)
- Streams the eve file line-by-line (NDJSON)
- For each event with a matching flow_key, writes it to the output eve file
- Keeps both "flow" and "http" events
- Skips events missing src_ip or dest_ip
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Set

_MODEL2_ROOT = Path(__file__).resolve().parents[2]
if str(_MODEL2_ROOT) not in sys.path:
    sys.path.insert(0, str(_MODEL2_ROOT))

from build_ground_truth import _event_timestamp_epoch  # noqa: E402
from ingestion.flow_identity import flow_key_with_time_bucket  # noqa: E402

try:
    import orjson  # type: ignore
except ImportError:
    orjson = None  # type: ignore

import json


PROGRESS_EVERY = 1_000_000


def load_flow_keys(csv_paths) -> Set[str]:
    """Load flow_key values from one or more CSV files into a set."""
    keys: Set[str] = set()
    total_rows = 0
    for path in csv_paths:
        path = Path(path)
        if not path.exists():
            print(f"[WARNING] CSV not found, skipping: {path}", file=sys.stderr)
            continue
        print(f"[INFO] Loading flow_key from {path}", file=sys.stderr)
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            if "flow_key" not in reader.fieldnames:
                print(f"[WARNING] CSV {path} has no 'flow_key' column; skipping.", file=sys.stderr)
                continue
            for row in reader:
                total_rows += 1
                fk = row.get("flow_key")
                if fk:
                    keys.add(fk.strip())
        print(f"[INFO] Loaded {len(keys)} unique flow_key values after {path.name}", file=sys.stderr)
    print(f"[INFO] Total rows scanned across CSVs: {total_rows}", file=sys.stderr)
    print(f"[INFO] Final unique flow_key count: {len(keys)}", file=sys.stderr)
    return keys


def build_flow_key(ev: dict, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> str:
    """Build time-bucketed flow_key (matches ingestion.flow_identity + eve_extractor)."""
    ts = _event_timestamp_epoch(ev) or 0.0
    return flow_key_with_time_bucket(src_ip, src_port, dst_ip, dst_port, proto, ts)


def parse_int(val, default: int = 0) -> int:
    try:
        return int(val)
    except Exception:
        return default


def dumps_json(obj) -> str:
    """Serialize JSON using orjson if available, else stdlib json."""
    if orjson is not None:
        return orjson.dumps(obj).decode("utf-8")
    return json.dumps(obj, separators=(",", ":"))


def filter_eve(
    master_path: Path,
    output_path: Path,
    flow_keys: Set[str],
) -> None:
    """Stream master_eve.json and write only events whose flow_key is in flow_keys."""
    total = 0
    kept = 0
    decode_errors = 0

    print(f"[INFO] Streaming {master_path} and writing matches to {output_path}", file=sys.stderr)

    with master_path.open("r", encoding="utf-8", errors="replace") as fin, \
            output_path.open("w", encoding="utf-8", newline="") as fout:

        for line in fin:
            total += 1
            line = line.strip()
            if not line:
                continue
            try:
                if orjson is not None:
                    ev = orjson.loads(line)
                else:
                    ev = json.loads(line)
            except Exception as e:
                decode_errors += 1
                if decode_errors <= 10:
                    print(f"[WARNING] JSON decode error at line {total}: {e}", file=sys.stderr)
                continue

            # Must have src/dest IPs
            src_ip = (ev.get("src_ip") or "").strip()
            dst_ip = (ev.get("dest_ip") or "").strip()
            if not src_ip or not dst_ip:
                continue

            src_port = parse_int(ev.get("src_port", 0) or 0, 0)
            dst_port = parse_int(ev.get("dest_port", 0) or 0, 0)
            proto = str(ev.get("proto") or "").strip().upper()
            if not proto:
                continue

            fk = build_flow_key(ev, src_ip, src_port, dst_ip, dst_port, proto)
            if fk in flow_keys:
                fout.write(dumps_json(ev) + "\n")
                kept += 1

            if total % PROGRESS_EVERY == 0:
                print(
                    f"[INFO] Processed {total:,} events | kept {kept:,} | decode_errors={decode_errors}",
                    file=sys.stderr,
                )

    print(f"[INFO] Done. Total events processed: {total:,}", file=sys.stderr)
    print(f"[INFO] Events kept (matched flow_key): {kept:,}", file=sys.stderr)
    if decode_errors > 0:
        print(f"[INFO] Total JSON decode errors: {decode_errors}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build balanced_eve.json from labels CSV(s) and eve.json (by flow_key).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=None,
        help="Directory containing attacks_all.csv, benign_all.csv, master_eve.json (optional if --labels-csv and --eve are set)",
    )
    parser.add_argument(
        "--labels-csv",
        type=Path,
        default=None,
        help="Single labels CSV with flow_key column (e.g. rf_labels.csv). Use with --eve to skip dataset-dir.",
    )
    parser.add_argument(
        "--eve",
        type=Path,
        default=None,
        help="Input eve.json (e.g. merged_eve.json). Use with --labels-csv.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output balanced eve file (default: same dir as --eve, file balanced_eve.json)",
    )
    args = parser.parse_args()

    if args.labels_csv is not None and args.eve is not None:
        # Direct mode: rf_labels.csv + merged_eve.json
        if not args.labels_csv.exists():
            print(f"[ERROR] Labels CSV not found: {args.labels_csv}", file=sys.stderr)
            return 1
        if not args.eve.exists():
            print(f"[ERROR] Eve file not found: {args.eve}", file=sys.stderr)
            return 1
        flow_keys = load_flow_keys([args.labels_csv])
        if not flow_keys:
            print("[ERROR] No flow_key values in labels CSV; ensure it has a 'flow_key' column.", file=sys.stderr)
            return 1
        out_path = args.output if args.output is not None else args.eve.parent / "balanced_eve.json"
        filter_eve(args.eve, out_path, flow_keys)
        print(f"[INFO] Balanced eve written to {out_path}", file=sys.stderr)
        return 0

    # Directory mode
    base = args.dataset_dir or Path("Refined_Training_Dataset")
    attacks_csv = base / "attacks_all.csv"
    benign_csv = base / "benign_all.csv"
    master_eve = base / "master_eve.json"
    balanced_eve = base / "balanced_eve.json"

    if not master_eve.exists():
        print(f"[ERROR] master_eve.json not found at {master_eve}", file=sys.stderr)
        return 1

    flow_keys = load_flow_keys([attacks_csv, benign_csv])
    if not flow_keys:
        print("[ERROR] No flow_key values loaded from CSVs; nothing to filter.", file=sys.stderr)
        return 1

    filter_eve(master_eve, balanced_eve, flow_keys)
    print(f"[INFO] Balanced eve written to {balanced_eve}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())