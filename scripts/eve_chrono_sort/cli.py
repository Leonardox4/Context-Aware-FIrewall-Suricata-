#!/usr/bin/env python3
"""
CLI for EVE JSONL chronological reordering (external sort by extracted timestamp).

Phases:
  1) Scan original JSONL -> timestamp_index.bin (ts_ns, byte_offset)
  2) External sort -> sorted_timestamp_index.bin
  3) Replay original file by sorted offsets -> sorted_eve.jsonl
  4) Optional worker manifest over sorted index (safe to use if sorted JSONL deleted)
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from typing import List


def _parse_fields(s: str) -> List[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def main(argv: List[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="Suricata EVE JSONL chronological sort (external sort)")
    p.add_argument("--input", required=True, help="Input JSONL (may be huge, not time-ordered)")
    p.add_argument(
        "--output",
        default="",
        help="Output sorted JSONL path (default: <input>.sorted.jsonl next to input)",
    )
    p.add_argument(
        "--index",
        default="",
        help="Phase1 index output (default: <input>.timestamp_index.bin)",
    )
    p.add_argument(
        "--sorted-index",
        default="",
        help="Phase2 sorted index (default: <input>.sorted_timestamp_index.bin)",
    )
    p.add_argument(
        "--timestamp-field",
        default="timestamp,flow.start",
        help="Comma-separated extraction order, e.g. timestamp,flow.start",
    )
    p.add_argument("--chunk-lines", type=int, default=2_000_000, help="External sort chunk size (lines)")
    p.add_argument("--buffer-mb", type=int, default=8, help="Read/write buffer size per handle (MiB)")
    p.add_argument("--temp-dir", default="", help="Temp dir for sort chunks (default: system temp)")
    p.add_argument("--keep-sort-chunks", action="store_true", help="Keep intermediate chunk files")
    p.add_argument(
        "--skip-sort-if-monotonic",
        action="store_true",
        help="If scan shows non-decreasing extracted keys in file order, skip sort (copy index only)",
    )
    p.add_argument("--workers", type=int, default=0, help="If >0, write partition manifest for N workers")
    p.add_argument(
        "--partition-manifest",
        default="",
        help="Partition JSON path (default: <output>.partitions.json)",
    )
    p.add_argument(
        "--warmup-pairs",
        type=int,
        default=0,
        help="Extra leading index pairs each worker reads before its emit range (sliding windows)",
    )
    p.add_argument(
        "--warmup-seconds",
        type=float,
        default=0.0,
        help="With --workers, estimate warmup-pairs from Phase1 scan throughput (rough)",
    )
    p.add_argument(
        "--delete-sorted-output",
        action="store_true",
        help="Remove sorted JSONL after successful completion (keep indexes + manifest)",
    )
    args = p.parse_args(argv)

    inp = os.path.abspath(args.input)
    if not os.path.isfile(inp):
        print("error: input not found:", inp, file=sys.stderr)
        return 2

    out = args.output or (inp + ".sorted.jsonl")
    out = os.path.abspath(out)
    index_path = args.index or (inp + ".timestamp_index.bin")
    sorted_index_path = args.sorted_index or (inp + ".sorted_timestamp_index.bin")
    manifest_path = args.partition_manifest or (out + ".partitions.json")

    buffer_size = max(64 * 1024, args.buffer_mb * 1024 * 1024)

    from .timestamp_extract import build_extractor_chain, default_field_order

    fields = _parse_fields(args.timestamp_field)
    if not fields:
        fields = default_field_order()
    try:
        extract = build_extractor_chain(fields)
    except ValueError as e:
        print("error:", e, file=sys.stderr)
        return 2

    def log(msg: str) -> None:
        print("[%s] %s" % (time.strftime("%Y-%m-%dT%H:%M:%S"), msg), flush=True)

    t0 = time.time()
    from .phase1_index import index_file
    from .phase2_sort import sort_index_external
    from .phase3_rebuild import rebuild_sorted_jsonl
    from .partition import build_index_pair_manifest, suggest_warmup_pairs, write_manifest

    log("Fields: %s" % fields)

    t_phase1 = time.time()
    n_lines, _n_idx, n_miss, bytes_read, monotonic = index_file(
        inp, index_path, extract, buffer_size=buffer_size, log=log
    )
    phase1_elapsed = max(time.time() - t_phase1, 1e-6)

    warmup_pairs = max(0, int(args.warmup_pairs))
    if args.workers > 0 and args.warmup_seconds > 0:
        est = suggest_warmup_pairs(n_lines, phase1_elapsed, float(args.warmup_seconds))
        warmup_pairs = max(warmup_pairs, est)
        log("Estimated warmup_pairs from --warmup-seconds: %s" % est)

    skip_sort = bool(args.skip_sort_if_monotonic and monotonic)
    if skip_sort:
        log("Input appears monotonic in extracted key order; copying index to sorted-index (no reorder)")
        shutil.copyfile(index_path, sorted_index_path)
    else:
        sort_index_external(
            index_path,
            sorted_index_path,
            chunk_lines=args.chunk_lines,
            temp_dir=args.temp_dir or None,
            keep_chunks=args.keep_sort_chunks,
            log=log,
        )

    if skip_sort:
        shutil.copyfile(inp, out)
    else:
        rebuild_sorted_jsonl(inp, sorted_index_path, out, buffer_size=buffer_size, log=log)

    if args.workers > 0:
        man = build_index_pair_manifest(
            inp,
            sorted_index_path,
            args.workers,
            warmup_pairs=warmup_pairs,
            sorted_jsonl_path=None if args.delete_sorted_output else out,
        )
        write_manifest(manifest_path, man)
        log("Wrote partition manifest: %s" % manifest_path)

    if args.delete_sorted_output:
        try:
            os.remove(out)
            log("Deleted sorted output per flag: %s" % out)
        except OSError as e:
            print("error: could not delete output:", e, file=sys.stderr)
            return 1

    log("Done in %.1fs" % (time.time() - t0,))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
