#!/usr/bin/env python3
"""
Convert flat per-flow JSONL (e.g. Refined_Training_Dataset training_dataset.jsonl) into
Suricata-EVE-shaped JSONL so RustUnifiedExtractor / Randomforest_training_pipeline can parse it.

Flat format (example):
  flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, proto,
  pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, duration, ...

Suricata expects:
  event_type == "flow", dest_ip / dest_port, nested "flow": { pkts_*, bytes_*, age, start, ... }

Lines that already look like EVE flow events are copied through unchanged.

Usage:
  python3 scripts/flat_flow_to_suricata_eve_jsonl.py in.jsonl out.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict


def is_eve_flow(ev: Dict[str, Any]) -> bool:
    if str(ev.get("event_type", "")).lower() != "flow":
        return False
    if not isinstance(ev.get("flow"), dict):
        return False
    if ev.get("dest_ip") is None and ev.get("dst_ip") is None:
        return False
    return True


def is_flat_flow(ev: Dict[str, Any]) -> bool:
    if ev.get("event_type"):
        return False
    need = ("src_ip", "src_port", "pkts_toserver", "pkts_toclient")
    if not all(k in ev for k in need):
        return False
    if "dst_ip" not in ev and "dest_ip" not in ev:
        return False
    if "dst_port" not in ev and "dest_port" not in ev:
        return False
    return True


def _as_int(x: Any, default: int = 0) -> int:
    if x is None:
        return default
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


def convert_flat_to_eve(rec: Dict[str, Any]) -> Dict[str, Any]:
    dst_ip = rec.get("dest_ip") or rec.get("dst_ip")
    dst_port = rec.get("dest_port") if rec.get("dest_port") is not None else rec.get("dst_port")
    ts = rec.get("timestamp")
    dur = float(rec.get("duration") or 0.0)
    if dur <= 0.0:
        dur = 0.001

    flow_id = rec.get("flow_id")
    out: Dict[str, Any] = {
        "timestamp": ts,
        "event_type": "flow",
        "src_ip": rec.get("src_ip"),
        "dest_ip": dst_ip,
        "src_port": _as_int(rec.get("src_port")),
        "dest_port": _as_int(dst_port),
        "proto": str(rec.get("proto", "TCP")).upper(),
        "flow": {
            "pkts_toserver": _as_int(rec.get("pkts_toserver")),
            "pkts_toclient": _as_int(rec.get("pkts_toclient")),
            "bytes_toserver": _as_int(rec.get("bytes_toserver")),
            "bytes_toclient": _as_int(rec.get("bytes_toclient")),
            "age": dur,
            "start": ts,
            "end": ts,
        },
        # Minimal TCP flags so extractor entropy features are defined
        "tcp": {
            "syn": True,
            "ack": True,
            "fin": False,
            "rst": False,
            "psh": False,
            "urg": False,
        },
    }
    if flow_id is not None:
        out["flow_id"] = flow_id
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", type=Path, help="Flat or mixed JSONL")
    p.add_argument("output", type=Path, help="Output EVE-shaped JSONL")
    args = p.parse_args()

    if not args.input.is_file():
        print(f"[ERROR] missing {args.input}", file=sys.stderr)
        return 1

    n_in = n_flat = n_passthrough = n_skip = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with open(args.input, "r", encoding="utf-8", errors="replace") as fin, open(
        args.output, "w", encoding="utf-8", newline="\n"
    ) as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            n_in += 1
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                n_skip += 1
                continue
            if not isinstance(ev, dict):
                n_skip += 1
                continue

            if is_eve_flow(ev):
                fout.write(json.dumps(ev, separators=(",", ":")) + "\n")
                n_passthrough += 1
            elif is_flat_flow(ev):
                fout.write(json.dumps(convert_flat_to_eve(ev), separators=(",", ":")) + "\n")
                n_flat += 1
            else:
                n_skip += 1

    print(
        f"[+] lines_in={n_in} converted_flat={n_flat} passthrough_eve_flow={n_passthrough} "
        f"skipped={n_skip} → {args.output}",
        file=sys.stderr,
    )
    if n_flat + n_passthrough == 0:
        print(
            "[ERROR] No flow rows written. Input must be flat flow JSON or EVE flow events.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
