"""
Deprecated: use inference.enforcement_engine instead.

This stub was the original placeholder for firewall integration. The runtime pipeline
now uses EnforcementEngine (enforcement_engine.py) with backends: stub, iptables, nftables.
Kept for backward compatibility only; no longer used by runtime_scoring.py.
"""

import sys


def apply_decision(src_ip, decision, risk_score, reason=""):
    """
    decision: ALLOW | ALERT | BLOCK.
    Stub: print to stderr. Replace with real firewall calls later.
    """
    action = "ALLOW"
    if decision == "BLOCK":
        action = "BLOCK"
    elif decision == "ALERT":
        action = "ALERT"
    print(f"[FIREWALL_STUB] {action} src={src_ip} risk={risk_score:.3f} {reason}", file=sys.stderr, flush=True)
