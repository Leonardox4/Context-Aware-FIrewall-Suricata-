#!/usr/bin/env python3
"""
Suricata eve.json (JSONL) benign/attack flow analysis.

Streams the file line-by-line; safe for multi-GB files.
Only flow events (event_type == "flow") are used for benign/attack counts.
- ATTACK: flow.alerted == True
- BENIGN: flow.alerted == False or missing

Usage:
  python scripts/analyze_eve_benign.py [path_to_eve.json]
  Default path: Datasets/BenignHeavy/logs_with_suricata_rules/eve.json under repo root
"""

import json
import sys
from pathlib import Path


def analyze_eve_stream(filepath: Path) -> dict:
    """
    Stream eve.json line-by-line and compute counts.
    Returns dict with: total_events, flow_events, alert_events, benign_flows, attack_flows.
    """
    total_events = 0
    flow_events = 0
    alert_events = 0
    benign_flows = 0
    attack_flows = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total_events += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event_type = event.get("event_type") if isinstance(event, dict) else None
                if event_type == "flow":
                    flow_events += 1
                    flow = event.get("flow")
                    if isinstance(flow, dict) and flow.get("alerted") is True:
                        attack_flows += 1
                    else:
                        benign_flows += 1
                elif event_type == "alert":
                    alert_events += 1

    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except OSError as e:
        raise OSError(f"Error reading file: {e}") from e

    return {
        "total_events": total_events,
        "flow_events": flow_events,
        "alert_events": alert_events,
        "benign_flows": benign_flows,
        "attack_flows": attack_flows,
    }


def print_report(stats: dict) -> None:
    """Print the summary report in the required format."""
    total = stats["total_events"]
    flow_events = stats["flow_events"]
    alert_events = stats["alert_events"]
    benign = stats["benign_flows"]
    attack = stats["attack_flows"]

    benign_pct = (benign / flow_events * 100.0) if flow_events else 0.0
    attack_pct = (attack / flow_events * 100.0) if flow_events else 0.0

    print("----------------------------------------")
    print("EVE.JSON BENIGN ANALYSIS REPORT")
    print("----------------------------------------")
    print(f"Total events: {total}")
    print(f"Total flow events: {flow_events}")
    print(f"Total alert events: {alert_events}")
    print()
    print(f"Benign flows: {benign}")
    print(f"Attack flows: {attack}")
    print()
    print(f"Benign percentage: {benign_pct:.2f} %")
    print(f"Attack percentage: {attack_pct:.2f} %")
    print("----------------------------------------")


def main() -> int:
    if len(sys.argv) > 1:
        filepath = Path(sys.argv[1])
    else:
        repo_root = Path(__file__).resolve().parent.parent
        filepath = repo_root / "Datasets" / "BenignHeavy" / "logs_with_suricata_rules" / "eve.json"

    if not filepath.exists():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        return 1

    try:
        stats = analyze_eve_stream(filepath)
        print_report(stats)
        return 0
    except (FileNotFoundError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
