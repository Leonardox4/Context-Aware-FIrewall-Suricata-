#!/usr/bin/env python3
"""
Assign synthetic hexadecimal flow_id to each `event_type == "flow"` line in recon/synthetic JSONL.

Uses the same scheme as generate_recon_jsonl.sh: 16 lowercase hex chars, base 0xDEC0DE0000000000
+ sequential counter in file order (flow events only).

After running this, rebuild or patch your labels CSV so `flow_id` matches these strings for
recon rows (e.g. re-export labels from this JSONL, or join on flow_key only for non-recon data).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

FLOW_ID_BASE = 0xDEC0DE0000000000


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", type=Path, help="Input JSONL (e.g. scripts/recon.jsonl)")
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output path (default: INPUT with .flowid.jsonl next to it)",
    )
    p.add_argument(
        "--in-place",
        action="store_true",
        help="Overwrite INPUT; keeps a copy at INPUT.bak before replace",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Replace existing top-level flow_id on flow events",
    )
    args = p.parse_args()

    inp = args.input
    if not inp.is_file():
        print(f"[ERROR] not a file: {inp}", file=sys.stderr)
        return 1

    if args.in_place:
        out_path = inp
        tmp_dir = inp.parent
        fd, tmp_name = tempfile.mkstemp(suffix=".jsonl", dir=tmp_dir, text=True)
        tmp_p = Path(tmp_name)
    elif args.output is not None:
        out_path = args.output
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_p = out_path.with_suffix(out_path.suffix + ".tmp")
        fd = None
    else:
        out_path = inp.with_name(inp.stem + ".flowid.jsonl")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_p = out_path.with_suffix(out_path.suffix + ".tmp")
        fd = None

    if fd is not None:
        import os

        os.close(fd)

    seq = 0
    n_flow = 0
    n_skipped = 0
    n_bad = 0

    try:
        with open(inp, "r", encoding="utf-8", errors="replace") as fin, open(
            tmp_p, "w", encoding="utf-8", newline="\n"
        ) as fout:
            for line in fin:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    n_bad += 1
                    fout.write(line + "\n")
                    continue
                if not isinstance(ev, dict):
                    fout.write(line + "\n")
                    continue
                if ev.get("event_type") != "flow":
                    fout.write(json.dumps(ev, separators=(",", ":")) + "\n")
                    continue
                n_flow += 1
                existing = ev.get("flow_id")
                if existing is not None and existing != "" and not args.force:
                    n_skipped += 1
                    fout.write(json.dumps(ev, separators=(",", ":")) + "\n")
                    continue
                seq += 1
                ev["flow_id"] = f"{FLOW_ID_BASE + seq:016x}"
                fout.write(json.dumps(ev, separators=(",", ":")) + "\n")

        if args.in_place:
            bak = inp.with_suffix(inp.suffix + ".bak")
            shutil.copy2(inp, bak)
            tmp_p.replace(inp)
            print(f"[+] wrote {inp} (backup {bak})", file=sys.stderr)
        else:
            tmp_p.replace(out_path)
            print(f"[+] wrote {out_path}", file=sys.stderr)

    finally:
        if tmp_p.exists() and not args.in_place:
            try:
                tmp_p.unlink(missing_ok=True)
            except OSError:
                pass

    print(
        f"[+] flow events seen={n_flow} assigned={seq} skipped_existing={n_skipped} "
        f"bad_json_lines={n_bad}",
        file=sys.stderr,
    )
    if seq and not args.force:
        print(f"[i] first new id: {FLOW_ID_BASE + 1:016x}  last: {FLOW_ID_BASE + seq:016x}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
