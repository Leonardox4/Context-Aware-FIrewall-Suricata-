#!/usr/bin/env python3
"""
Remove only firewall rules tagged with ML_BLOCK.
"""

from __future__ import annotations

import argparse
import re
import subprocess

ML_BLOCK_TAG = "ML_BLOCK"
NFT_TABLE = "ml_ids"
NFT_CHAIN = "blocklist"


def _run(cmd: list[str], timeout: int = 5) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or p.stderr or "").strip()
        return (p.returncode == 0), out
    except Exception as exc:
        return False, str(exc)


def reset_iptables() -> int:
    removed = 0
    ok, rules = _run(["iptables-save"], timeout=5)
    if not ok:
        return 0
    for line in rules.splitlines():
        if ML_BLOCK_TAG not in line:
            continue
        if not line.startswith("-A "):
            continue
        delete_rule = line.replace("-A ", "-D ", 1).split()
        ok_del, _ = _run(["iptables"] + delete_rule, timeout=3)
        if ok_del:
            removed += 1
    return removed


def reset_nftables() -> int:
    removed = 0
    ok, out = _run(["nft", "-a", "list", "chain", "ip", NFT_TABLE, NFT_CHAIN], timeout=5)
    if not ok:
        return 0
    for line in out.splitlines():
        if ML_BLOCK_TAG not in line:
            continue
        m = re.search(r"handle\s+(\d+)", line)
        if not m:
            continue
        handle = m.group(1)
        ok_del, _ = _run(
            ["nft", "delete", "rule", "ip", NFT_TABLE, NFT_CHAIN, "handle", handle],
            timeout=3,
        )
        if ok_del:
            removed += 1
    return removed


def main() -> int:
    p = argparse.ArgumentParser(description="Remove only ML_BLOCK tagged rules")
    p.add_argument("--backend", choices=("iptables", "nftables"), required=True)
    args = p.parse_args()
    removed = reset_iptables() if args.backend == "iptables" else reset_nftables()
    print(f'{{"backend":"{args.backend}","removed_rules":{removed},"tag":"{ML_BLOCK_TAG}"}}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
