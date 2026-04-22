"""
Enforcement engine for ML IDS/IPS: apply BLOCK decisions via firewall rules.

- Maintains an in-memory blocklist (no duplicate rules).
- Supports backends: stub (log only), iptables, nftables.
- Rate limit: max new blocks per minute.
- Max blocks cap; optional TTL with automatic expiry (unblock after N seconds).
- Safe for production: rate limit, cap, and TTL prevent runaway rule growth.
"""

from __future__ import annotations

import logging
import subprocess
import time
from collections import OrderedDict
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Defaults
DEFAULT_MAX_BLOCKS = 2000
DEFAULT_BLOCK_TTL_SECONDS = 600  # 10 minutes
DEFAULT_MAX_BLOCKS_PER_MINUTE = 60
IPTABLES_CHAIN = "ML_BLOCK"
NFT_TABLE = "ml_ids"
NFT_CHAIN = "blocklist"


def _run(cmd: list[str], timeout: int = 5) -> tuple[bool, str]:
    """Run command; return (success, stderr_or_stdout)."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if r.returncode == 0:
            return True, r.stderr or r.stdout or ""
        return False, r.stderr or r.stdout or ""
    except Exception as e:
        return False, str(e)


class EnforcementEngine:
    """
    Apply and remove blocks by IP. Tracks blocklist in memory, avoids duplicate rules,
    enforces rate limit and max blocks, and supports TTL-based expiry.
    """

    def __init__(
        self,
        backend: str = "stub",
        max_blocks: int = DEFAULT_MAX_BLOCKS,
        block_ttl_seconds: float = DEFAULT_BLOCK_TTL_SECONDS,
        max_blocks_per_minute: int = DEFAULT_MAX_BLOCKS_PER_MINUTE,
    ) -> None:
        self.backend = backend.lower().strip()
        self.max_blocks = max(0, max_blocks)
        self.block_ttl_seconds = max(0.0, block_ttl_seconds)
        self.max_blocks_per_minute = max(0, max_blocks_per_minute)

        self._blocked: set[str] = set()
        self._block_times: OrderedDict[str, float] = OrderedDict()  # ip -> when blocked (for TTL + LRU)
        self._recent_add_times: list[float] = []  # for rate limit

    def _trim_recent(self) -> None:
        """Keep only add times within the last minute."""
        cutoff = time.time() - 60.0
        while self._recent_add_times and self._recent_add_times[0] < cutoff:
            self._recent_add_times.pop(0)

    def _rate_limited(self) -> bool:
        if self.max_blocks_per_minute <= 0:
            return False
        self._trim_recent()
        return len(self._recent_add_times) >= self.max_blocks_per_minute

    def _apply_stub(self, ip: str) -> bool:
        logger.warning("[ENFORCEMENT_STUB] BLOCK src=%s", ip)
        return True

    def _remove_stub(self, ip: str) -> bool:
        return True

    def _ensure_iptables_chain(self) -> bool:
        """Ensure chain ML_BLOCK exists and INPUT jumps to it."""
        ok, _ = _run(["iptables", "-L", IPTABLES_CHAIN, "-n"], timeout=2)
        if ok:
            return True
        ok, err = _run(["iptables", "-N", IPTABLES_CHAIN], timeout=2)
        if not ok:
            logger.error("iptables -N %s failed: %s", IPTABLES_CHAIN, err)
            return False
        ok, err = _run(["iptables", "-C", "INPUT", "-j", IPTABLES_CHAIN], timeout=2)
        if not ok:
            ok, err = _run(["iptables", "-A", "INPUT", "-j", IPTABLES_CHAIN], timeout=2)
            if not ok:
                logger.error("iptables -A INPUT -j %s failed: %s", IPTABLES_CHAIN, err)
                return False
        return True

    def _apply_iptables(self, ip: str) -> bool:
        if not self._ensure_iptables_chain():
            return False
        ok, err = _run(["iptables", "-A", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"], timeout=2)
        if not ok:
            logger.error("iptables block %s failed: %s", ip, err)
            return False
        return True

    def _remove_iptables(self, ip: str) -> bool:
        ok, err = _run(["iptables", "-D", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"], timeout=2)
        if not ok:
            logger.debug("iptables unblock %s (may already be gone): %s", ip, err)
        return True

    def _ensure_nftables(self) -> bool:
        """Create table and chain if they do not exist (table ml_ids, chain blocklist)."""
        _run(["nft", "add", "table", "ip", NFT_TABLE], timeout=2)
        # Chain with hook input, priority 100, policy accept; one rule will drop set members
        _run([
            "nft", "add", "chain", "ip", NFT_TABLE, NFT_CHAIN,
            "{ type filter hook input priority 100 ; policy accept ; }",
        ], timeout=2)
        return True

    def _apply_nftables(self, ip: str) -> bool:
        self._ensure_nftables()
        cmd = ["nft", "add", "rule", "ip", NFT_TABLE, NFT_CHAIN, "ip", "saddr", ip, "drop"]
        ok, err = _run(cmd, timeout=2)
        if not ok:
            logger.error("nft block %s failed: %s", ip, err)
            return False
        return True

    def _remove_nftables(self, ip: str) -> bool:
        cmd = ["nft", "delete", "rule", "ip", NFT_TABLE, NFT_CHAIN, "ip", "saddr", ip, "drop"]
        ok, err = _run(cmd, timeout=2)
        if not ok:
            logger.debug("nft unblock %s: %s", ip, err)
        return True

    def add_block(self, ip: str, reason: str = "") -> bool:
        """
        Block an IP if not already blocked, under rate limit and max_blocks.
        Returns True if the block was applied (or already blocked), False if skipped (rate limit/cap).
        """
        ip = (ip or "").strip() or "UNKNOWN"
        if ip == "UNKNOWN" or not ip:
            return False
        if ip in self._blocked:
            return True
        if self.max_blocks > 0 and len(self._blocked) >= self.max_blocks:
            # Evict oldest by TTL order (or first in _block_times)
            if self.block_ttl_seconds > 0 and self._block_times:
                oldest_ip = next(iter(self._block_times))
                self.remove_block(oldest_ip)
            else:
                logger.warning("Enforcement max_blocks=%d reached; skipping block for %s", self.max_blocks, ip)
                return False
        if self._rate_limited():
            logger.warning("Enforcement rate limit (%d/min) reached; skipping block for %s", self.max_blocks_per_minute, ip)
            return False

        if self.backend == "stub":
            ok = self._apply_stub(ip)
        elif self.backend == "iptables":
            ok = self._apply_iptables(ip)
        elif self.backend == "nftables":
            ok = self._apply_nftables(ip)
        else:
            logger.warning("Unknown enforcement backend %s; using stub", self.backend)
            ok = self._apply_stub(ip)

        if ok:
            self._blocked.add(ip)
            now = time.time()
            self._block_times[ip] = now
            self._block_times.move_to_end(ip)
            self._recent_add_times.append(now)
            logger.info("Blocked %s (reason=%s) backend=%s total_blocks=%d", ip, reason or "ml_decision", self.backend, len(self._blocked))
        return ok

    def remove_block(self, ip: str) -> bool:
        """Remove block for IP. Returns True if rule was removed or IP was not blocked."""
        ip = (ip or "").strip()
        if ip not in self._blocked:
            return True
        if self.backend == "stub":
            ok = self._remove_stub(ip)
        elif self.backend == "iptables":
            ok = self._remove_iptables(ip)
        elif self.backend == "nftables":
            ok = self._remove_nftables(ip)
        else:
            ok = True
        if ok:
            self._blocked.discard(ip)
            self._block_times.pop(ip, None)
            logger.info("Unblocked %s backend=%s", ip, self.backend)
        return ok

    def expire_blocks(self) -> int:
        """
        Remove blocks older than block_ttl_seconds. Call periodically (e.g. every 60s).
        Returns number of IPs unblocked.
        """
        if self.block_ttl_seconds <= 0:
            return 0
        cutoff = time.time() - self.block_ttl_seconds
        to_remove = [ip for ip, t in self._block_times.items() if t < cutoff]
        for ip in to_remove:
            self.remove_block(ip)
        return len(to_remove)

    def size(self) -> int:
        return len(self._blocked)

    def is_blocked(self, ip: str) -> bool:
        return (ip or "").strip() in self._blocked


def create_enforcement_engine(
    backend: str = "stub",
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    block_ttl_seconds: float = DEFAULT_BLOCK_TTL_SECONDS,
    max_blocks_per_minute: int = DEFAULT_MAX_BLOCKS_PER_MINUTE,
    enabled: bool = True,
) -> Optional[EnforcementEngine]:
    """Create an EnforcementEngine. If enabled=False or backend='none', returns None."""
    if not enabled or (backend or "").lower().strip() in ("", "none", "off"):
        return None
    return EnforcementEngine(
        backend=backend,
        max_blocks=max_blocks,
        block_ttl_seconds=block_ttl_seconds,
        max_blocks_per_minute=max_blocks_per_minute,
    )
