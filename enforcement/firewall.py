"""
Simple firewall enforcement helpers for inference wrappers.

This module is additive and does not replace inference.enforcement_engine.
"""

from __future__ import annotations

import ipaddress
import subprocess
import time
from typing import Dict

ML_BLOCK_TAG = "ML_BLOCK"
NFT_TABLE = "ml_ids"
NFT_CHAIN = "blocklist"

# In-memory active blocks: ip -> expiry epoch seconds.
_ACTIVE_BLOCKS: Dict[str, float] = {}


def _run(cmd: list[str], timeout: int = 5) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stderr or p.stdout or "").strip()
        return (p.returncode == 0), out
    except Exception as exc:
        return False, str(exc)


def _is_safe_to_block(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False
    # Optional safeguard: avoid private/internal ranges.
    if addr.is_private:
        return False
    return True


def _cache_allows_block(ip: str, duration: int) -> bool:
    now = time.time()
    expiry = _ACTIVE_BLOCKS.get(ip)
    if expiry is not None and expiry > now:
        return False
    _ACTIVE_BLOCKS[ip] = now + max(1, int(duration))
    return True


def _ensure_iptables_chain() -> bool:
    ok, _ = _run(["iptables", "-L", ML_BLOCK_TAG, "-n"], timeout=2)
    if not ok:
        ok, _ = _run(["iptables", "-N", ML_BLOCK_TAG], timeout=2)
        if not ok:
            return False
    ok, _ = _run(["iptables", "-C", "INPUT", "-j", ML_BLOCK_TAG], timeout=2)
    if not ok:
        ok, _ = _run(["iptables", "-A", "INPUT", "-j", ML_BLOCK_TAG], timeout=2)
        if not ok:
            return False
    return True


def block_ip_iptables(ip: str, duration: int) -> bool:
    if not _is_safe_to_block(ip):
        return False
    if not _cache_allows_block(ip, duration):
        return True
    if not _ensure_iptables_chain():
        return False
    # Prevent duplicate rules at firewall level too.
    rule = ["iptables", "-C", ML_BLOCK_TAG, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", ML_BLOCK_TAG]
    ok, _ = _run(rule, timeout=2)
    if ok:
        return True
    add = ["iptables", "-A", ML_BLOCK_TAG, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", ML_BLOCK_TAG]
    ok, _ = _run(add, timeout=2)
    return ok


def _ensure_nftables() -> bool:
    _run(["nft", "add", "table", "ip", NFT_TABLE], timeout=2)
    _run(
        [
            "nft",
            "add",
            "chain",
            "ip",
            NFT_TABLE,
            NFT_CHAIN,
            "{ type filter hook input priority 100 ; policy accept ; }",
        ],
        timeout=2,
    )
    return True


def block_ip_nftables(ip: str, duration: int) -> bool:
    if not _is_safe_to_block(ip):
        return False
    if not _cache_allows_block(ip, duration):
        return True
    _ensure_nftables()
    ok, out = _run(["nft", "list", "chain", "ip", NFT_TABLE, NFT_CHAIN], timeout=2)
    if ok and f"ip saddr {ip}" in out and ML_BLOCK_TAG in out:
        return True
    add = [
        "nft",
        "add",
        "rule",
        "ip",
        NFT_TABLE,
        NFT_CHAIN,
        "ip",
        "saddr",
        ip,
        "drop",
        "comment",
        ML_BLOCK_TAG,
    ]
    ok, _ = _run(add, timeout=2)
    return ok


def block(ip: str, backend: str = "iptables", duration: int = 300) -> bool:
    backend_norm = (backend or "").strip().lower()
    if backend_norm == "iptables":
        return block_ip_iptables(ip, duration)
    if backend_norm == "nftables":
        return block_ip_nftables(ip, duration)
    return False
