#!/usr/bin/env python3
"""
Unified ground-truth CSV builder from Suricata eve.json for multiple datasets:

- CICIDS2018 (UTC windows + directional IP labeling; date token in path selects windows)
- CICIDS2017 (weekday folder Monday..Friday → fixed calendar date; O(log n) bisect on
  precomputed America/New_York attack intervals + ATTACKERS/VICTIMS/FIREWALL IP gate)
- Synthetic   (full-attack datasets; attack_type = parent folder name of the EVE file)
- TON_IoT     (per-flow ground-truth CSV matching; no attack windows)

Processes both **flow** and **http** events. Many web attacks in CICIDS2018 appear
primarily in HTTP events; both event types are preserved and share the same schema.

Streaming, memory-safe: NDJSON/pretty-printed JSON, line-by-line, no full file load.

Usage examples:
  python build_ground_truth.py --dataset cicids2018  master_eve.json
  python build_ground_truth.py --dataset cicids2017  Monday/eve.jsonl   # path must contain weekday folder
  python build_ground_truth.py --dataset synthetic   master_eve.json
  python build_ground_truth.py --dataset toniot     master_eve.json --ton-gt ton_gt.csv

Output (per dataset_day, in project root):
  attack_<DAY>.csv
  benign_<DAY>.csv

Schema (uniform across datasets):
  dataset_day,
  timestamp,
  event_type,      # "flow" or "http"
  src_ip,
  dst_ip,
  src_port,
  dst_port,
  proto,
  flow_id,         # Suricata native flow_id when present; else empty string
  flow_key,
  http_method,     # populated only for http events
  http_host,
  http_url,
  http_user_agent,
  http_status,
  label,           # 1 = attack, 0 = benign
  attack_type,     # CICIDS2017 attacks use "Type/Subtype" (e.g. DoS/Slowloris); benign runs "benign"
  labeling_mode    # "window_based" | "full_attack_dataset" | "ground_truth_flow_match" | "cicids2017_interval_bisect" | "mawi_weak_supervision"
"""

from __future__ import annotations

import argparse
import bisect
import csv
import gc
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from zoneinfo import ZoneInfo

try:
    import orjson
except ImportError:
    orjson = None  # type: ignore

OUTPUT_HEADER = [
    "dataset_day",
    "timestamp",
    "event_type",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "flow_id",
    "flow_key",
    "http_method",
    "http_host",
    "http_url",
    "http_user_agent",
    "http_status",
    "label",
    "attack_type",
    "labeling_mode",
]

# Labeling mode values (for downstream merging/analysis)
LABELING_MODE_WINDOW_BASED = "window_based"
LABELING_MODE_FULL_ATTACK = "full_attack_dataset"
LABELING_MODE_GROUND_TRUTH = "ground_truth_flow_match"
LABELING_MODE_MAWI_WEAK = "mawi_weak_supervision"
LABELING_MODE_CICIDS2017_FAST = "cicids2017_interval_bisect"

# TON_IoT time matching tolerance (seconds) for ground-truth flow matches
TONIOT_TIME_TOLERANCE_SEC = 1.0

PROGRESS_EVERY = 1_000_000
ATTACK_STATS_EVERY = 1_000_000  # show attack IP stats every N events
ATTACK_BREAKDOWN_EVERY = 5_000_000
DETECT_PEEK_LINES = 50

EASTERN_TO_UTC_HOURS = 5

DOS_TYPES = frozenset({
    "DoS-GoldenEye", "DoS-Slowloris", "DoS-SlowHTTPTest", "DoS-Hulk",
    "DDoS attacks-LOIC-HTTP", "DDoS-LOIC-UDP", "DDOS-LOIC-UDP", "DDOS-HOIC",
    "FTP-BruteForce", "SSH-BruteForce", "SSH-Bruteforce",
})
WEB_TYPES = frozenset({"Brute Force -Web", "Brute Force -XSS", "SQL Injection"})
C2_TYPES = frozenset({"Bot", "Infiltration"})

# Attack-type specific time buffers (seconds) applied to windows
# when constructing AttackWindow: start_ts -= start_buf, end_ts += end_buf.
ATTACK_BUFFERS: Dict[str, Tuple[int, int]] = {
    # DoS / DDoS flood attacks
    "DoS-Hulk": (30, 30),
    "DoS-GoldenEye": (30, 30),
    "DDoS attacks-LOIC-HTTP": (30, 30),
    "DDoS-LOIC-UDP": (30, 30),
    "DDOS-LOIC-UDP": (30, 30),
    "DDOS-HOIC": (30, 30),
    # Slow DoS
    "DoS-Slowloris": (120, 60),
    "DoS-SlowHTTPTest": (120, 60),
    # Web attacks
    "Brute Force -Web": (60, 60),
    "Brute Force -XSS": (60, 60),
    "SQL Injection": (60, 60),
    # FTP / SSH brute force
    "FTP-BruteForce": (60, 60),
    "SSH-Bruteforce": (60, 60),
    # Bot / Infiltration
    "Bot": (180, 180),
    "Infiltration": (180, 180),
}

_DDoS_ATTACKERS = [
    "18.216.200.189", "18.216.24.42", "18.218.11.51", "18.218.115.60",
    "18.218.229.235", "18.218.55.126", "18.219.32.43", "18.219.5.43",
    "18.219.9.1", "52.14.136.135",
]
_BOT_VICTIMS = [
    "172.31.69.6", "172.31.69.8", "172.31.69.10", "172.31.69.12", "172.31.69.14",
    "172.31.69.17", "172.31.69.23", "172.31.69.26", "172.31.69.29", "172.31.69.30",
]

CICIDS2018_HARDCODED_TABLE: List[Tuple[str, int, int, int, int, int, int, int, List[str], List[str]]] = [
    ("FTP-BruteForce", 2018, 2, 14, 10, 32, 12, 9, ["18.221.219.4", "172.31.70.4"], ["172.31.69.25"]),
    ("SSH-Bruteforce", 2018, 2, 14, 14, 1, 15, 31, ["13.58.98.64", "172.31.70.6"], ["172.31.69.25"]),
    ("DoS-GoldenEye", 2018, 2, 15, 9, 26, 10, 9, ["18.219.211.138", "172.31.70.46"], ["172.31.69.25"]),
    ("DoS-Slowloris", 2018, 2, 15, 10, 59, 11, 40, ["18.217.165.70", "172.31.70.8"], ["172.31.69.25"]),
    ("DoS-SlowHTTPTest", 2018, 2, 16, 10, 12, 11, 8, ["13.59.126.31", "172.31.70.23"], ["172.31.69.25"]),
    ("DoS-Hulk", 2018, 2, 16, 13, 45, 14, 19, ["18.219.193.20", "172.31.70.16"], ["172.31.69.25"]),
    ("DDoS attacks-LOIC-HTTP", 2018, 2, 20, 10, 12, 11, 17, _DDoS_ATTACKERS, ["172.31.69.25"]),
    ("DDoS-LOIC-UDP", 2018, 2, 20, 13, 13, 13, 32, _DDoS_ATTACKERS, ["172.31.69.25"]),
    ("DDoS-LOIC-UDP", 2018, 2, 21, 10, 9, 10, 43, _DDoS_ATTACKERS, ["172.31.69.28"]),
    ("DDOS-HOIC", 2018, 2, 21, 14, 5, 15, 5, _DDoS_ATTACKERS, ["172.31.69.28"]),
    ("Brute Force -Web", 2018, 2, 22, 10, 17, 11, 24, ["18.218.115.60"], ["172.31.69.28"]),
    ("Brute Force -XSS", 2018, 2, 22, 13, 50, 14, 29, ["18.218.115.60"], ["172.31.69.28"]),
    ("SQL Injection", 2018, 2, 22, 16, 15, 16, 29, ["18.218.115.60"], ["172.31.69.28"]),
    ("Brute Force -Web", 2018, 2, 23, 10, 3, 11, 3, ["18.218.115.60"], ["172.31.69.28"]),
    ("Brute Force -XSS", 2018, 2, 23, 13, 0, 14, 10, ["18.218.115.60"], ["172.31.69.28"]),
    ("SQL Injection", 2018, 2, 23, 15, 5, 15, 18, ["18.218.115.60"], ["172.31.69.28"]),
    ("Infiltration", 2018, 2, 28, 10, 50, 12, 5, ["13.58.225.34"], ["172.31.69.24"]),
    ("Infiltration", 2018, 2, 28, 13, 42, 14, 40, ["13.58.225.34"], ["172.31.69.24"]),
    ("Infiltration", 2018, 3, 1, 9, 57, 10, 55, ["13.58.225.34"], ["172.31.69.13"]),
    ("Infiltration", 2018, 3, 1, 14, 0, 15, 37, ["13.58.225.34"], ["172.31.69.13"]),
    ("Bot", 2018, 3, 2, 10, 11, 11, 34, ["18.219.211.138"], _BOT_VICTIMS),
    ("Bot", 2018, 3, 2, 14, 24, 15, 55, ["18.219.211.138"], _BOT_VICTIMS),
]

# ---------------------------------------------------------------------------
# CICIDS2017 — fast path-anchored labeling (weekday folder → date; bisect on UTC
# epoch intervals built from America/New_York wall times). Matches spec:
#   in_window AND (src in ATTACKERS or dst in VICTIMS or dst in FIREWALL_IPS)
# ---------------------------------------------------------------------------
CICIDS2017_EASTERN = ZoneInfo("America/New_York")

CICIDS2017_DAY_TO_DATE: Dict[str, str] = {
    "Monday": "2017-07-03",
    "Tuesday": "2017-07-04",
    "Wednesday": "2017-07-05",
    "Thursday": "2017-07-06",
    "Friday": "2017-07-07",
}

CICIDS2017_DAY_KEYS_LOWER = {k.lower(): k for k in CICIDS2017_DAY_TO_DATE}

CICIDS2017_ATTACKERS: frozenset[str] = frozenset(
    {"205.174.165.73", "205.174.165.69", "205.174.165.70", "205.174.165.71"}
)
CICIDS2017_FIREWALL_IPS: frozenset[str] = frozenset({"205.174.165.80", "172.16.0.1"})
CICIDS2017_VICTIMS: frozenset[str] = frozenset(
    {
        "192.168.10.50",
        "192.168.10.51",
        "192.168.10.8",
        "192.168.10.25",
        "192.168.10.5",
        "192.168.10.9",
        "192.168.10.14",
        "192.168.10.15",
    }
)
CICIDS2017_LATERAL_VISTA_SRC = "192.168.10.8"

# (start_hms, end_hms, attack_type, attack_subtype); end second inclusive via +1s exclusive bound.
CICIDS2017_ATTACK_WINDOWS: Dict[str, List[Tuple[str, str, str, str]]] = {
    "Tuesday": [
        ("09:20:00", "10:20:00", "BruteForce", "FTP-Patator"),
        ("14:00:00", "15:00:00", "BruteForce", "SSH-Patator"),
    ],
    "Wednesday": [
        ("09:47:00", "10:10:00", "DoS", "Slowloris"),
        ("10:14:00", "10:35:00", "DoS", "SlowHTTPTest"),
        ("10:43:00", "11:00:00", "DoS", "Hulk"),
        ("11:10:00", "11:23:00", "DoS", "GoldenEye"),
        ("15:12:00", "15:32:00", "Exploitation", "Heartbleed"),
    ],
    "Thursday": [
        ("09:20:00", "10:00:00", "WebAttack", "BruteForce"),
        ("10:15:00", "10:35:00", "WebAttack", "XSS"),
        ("10:40:00", "10:42:00", "WebAttack", "SQLi"),
        ("14:19:00", "14:21:00", "Infiltration", "Metasploit"),
        ("14:33:00", "14:35:00", "Infiltration", "Metasploit"),
        ("14:53:00", "15:00:00", "Infiltration", "Mac"),
        ("15:04:00", "15:45:00", "Infiltration", "Dropbox"),
    ],
    "Friday": [
        ("10:02:00", "11:02:00", "Botnet", "ARES"),
        ("13:55:00", "14:24:00", "Recon", "PortScan"),
        ("14:51:00", "15:29:00", "Recon", "PortScanVariants"),
        ("15:56:00", "16:16:00", "DDoS", "LOIT"),
    ],
}


@dataclass(frozen=True)
class Cicids2017IntervalIndex:
    starts: Tuple[float, ...]
    ends_excl: Tuple[float, ...]
    attack_types: Tuple[str, ...]
    attack_subtypes: Tuple[str, ...]


def _cicids2017_build_intervals_for_weekday(weekday: str) -> Optional[Cicids2017IntervalIndex]:
    windows = CICIDS2017_ATTACK_WINDOWS.get(weekday)
    date_str = CICIDS2017_DAY_TO_DATE.get(weekday)
    if not windows or not date_str:
        return None
    starts: List[float] = []
    ends_excl: List[float] = []
    attack_types: List[str] = []
    attack_subtypes: List[str] = []
    for hms0, hms1, atype, sub in windows:
        t0 = datetime.strptime(f"{date_str} {hms0}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=CICIDS2017_EASTERN)
        t1 = datetime.strptime(f"{date_str} {hms1}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=CICIDS2017_EASTERN)
        start_epoch = t0.timestamp()
        end_epoch_excl = (t1 + timedelta(seconds=1)).timestamp()
        if end_epoch_excl <= start_epoch:
            end_epoch_excl = start_epoch + 1.0
        starts.append(start_epoch)
        ends_excl.append(end_epoch_excl)
        attack_types.append(atype)
        attack_subtypes.append(sub)
    order = sorted(range(len(starts)), key=lambda i: (starts[i], ends_excl[i]))
    return Cicids2017IntervalIndex(
        starts=tuple(starts[i] for i in order),
        ends_excl=tuple(ends_excl[i] for i in order),
        attack_types=tuple(attack_types[i] for i in order),
        attack_subtypes=tuple(attack_subtypes[i] for i in order),
    )


def _build_cicids2017_interval_index() -> Dict[str, Cicids2017IntervalIndex]:
    out: Dict[str, Cicids2017IntervalIndex] = {}
    for day in CICIDS2017_DAY_TO_DATE:
        idx = _cicids2017_build_intervals_for_weekday(day)
        if idx is not None:
            out[day] = idx
    return out


CICIDS2017_INTERVAL_INDEX: Dict[str, Cicids2017IntervalIndex] = _build_cicids2017_interval_index()


def cicids2017_day_key_from_path(eve_path: Path) -> str:
    for part in eve_path.parts:
        key = CICIDS2017_DAY_KEYS_LOWER.get(part.lower())
        if key is not None:
            return key
    raise ValueError(
        "CICIDS2017: path must include a weekday folder "
        f"({', '.join(sorted(CICIDS2017_DAY_TO_DATE))}): {eve_path}"
    )


def cicids2017_lookup_interval(day_key: str, ts_epoch: float) -> Optional[Tuple[str, str]]:
    table = CICIDS2017_INTERVAL_INDEX.get(day_key)
    if not table or not table.starts:
        return None
    i = bisect.bisect_right(table.starts, ts_epoch) - 1
    if i < 0:
        return None
    if ts_epoch < table.ends_excl[i]:
        return table.attack_types[i], table.attack_subtypes[i]
    return None


def cicids2017_is_attack_ip(src_ip: str, dst_ip: str) -> bool:
    return (src_ip in CICIDS2017_ATTACKERS) or (dst_ip in CICIDS2017_VICTIMS) or (dst_ip in CICIDS2017_FIREWALL_IPS)


@dataclass
class AttackWindow:
    start_ts: float
    end_ts: float
    ips: Set[str] = field(default_factory=set)
    attackers: Set[str] = field(default_factory=set)
    victims: Set[str] = field(default_factory=set)
    attack_name: str = ""


@dataclass
class MawiWeakIndex:
    # High confidence (anomalous)
    high_ip_set: Set[str] = field(default_factory=set)
    high_ip_subnet_set: Set[str] = field(default_factory=set)
    high_ip_port_set: Set[Tuple[str, int]] = field(default_factory=set)
    high_freq_ip_set: Set[str] = field(default_factory=set)
    # Medium confidence (suspicious)
    medium_ip_set: Set[str] = field(default_factory=set)
    medium_ip_port_set: Set[Tuple[str, int]] = field(default_factory=set)
    medium_strong_ip_set: Set[str] = field(default_factory=set)
    medium_strong_ip_port_set: Set[Tuple[str, int]] = field(default_factory=set)
    # Low confidence (notice)
    low_notice_ip_set: Set[str] = field(default_factory=set)
    low_notice_ip_port_set: Set[Tuple[str, int]] = field(default_factory=set)
    low_notice_freq_ip_set: Set[str] = field(default_factory=set)
    # Stats
    anomaly_rows_total: int = 0
    anomaly_rows_bad: int = 0
    notice_rows_total: int = 0
    notice_rows_bad: int = 0


def _safe_int_any(val: Any) -> Optional[int]:
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def _safe_port(val: Any) -> Optional[int]:
    x = _safe_int_any(val)
    if x is None:
        return None
    if x < 0 or x > 65535:
        return None
    return x


def _norm_ip(val: Any) -> str:
    return str(val or "").strip()


def normalize_ip(ip: str) -> str:
    """
    Canonicalize IP strings across EVE and weak-label CSV sources.

    Suricata can emit IPv6-mapped IPv4 (e.g. ::ffff:1.2.3.4) while CSVs often
    store plain IPv4. Normalize both to plain IPv4 form when mapped.
    """
    if not ip:
        return ""
    s = str(ip).strip().lower()
    if s.startswith("::ffff:"):
        s = s[7:]
    return s


def ip_to_subnet(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) != 4:
        return ""
    return ".".join(parts[:3])


def _add_ip_port_keys(
    src_ip: str,
    src_port: Optional[int],
    dst_ip: str,
    dst_port: Optional[int],
) -> Tuple[List[str], List[Tuple[str, int]]]:
    ips = [x for x in (src_ip, dst_ip) if x]
    ip_ports: List[Tuple[str, int]] = []
    if src_ip and src_port is not None:
        ip_ports.append((src_ip, src_port))
    if dst_ip and dst_port is not None:
        ip_ports.append((dst_ip, dst_port))
    return ips, ip_ports


def load_mawi_weak_supervision(
    anomaly_csv: Path,
    notice_csv: Optional[Path],
    medium_nbdet_threshold: int,
    medium_repeat_threshold: int,
    high_ip_repeat_threshold: int,
    low_notice_repeat_threshold: int,
) -> MawiWeakIndex:
    idx = MawiWeakIndex()

    # Temporary frequency counters
    high_ip_counts: Dict[str, int] = {}
    med_ip_counts: Dict[str, int] = {}
    med_ip_port_counts: Dict[Tuple[str, int], int] = {}
    low_ip_counts: Dict[str, int] = {}

    # Suspicious rows with strong nbDetectors immediately become strong-medium
    med_nbdet_strong_ip: Set[str] = set()
    med_nbdet_strong_ip_port: Set[Tuple[str, int]] = set()

    with anomaly_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames:
            reader.fieldnames = [str(h).strip() for h in reader.fieldnames]
        for row in reader:
            row = {str(k).strip(): v for k, v in row.items()}
            idx.anomaly_rows_total += 1
            lab = str(row.get("label") or "").strip().lower()
            src_ip = normalize_ip(_norm_ip(row.get("srcIP")))
            dst_ip = normalize_ip(_norm_ip(row.get("dstIP")))
            src_port = _safe_port(row.get("srcPort"))
            dst_port = _safe_port(row.get("dstPort"))
            ips, ip_ports = _add_ip_port_keys(src_ip, src_port, dst_ip, dst_port)
            if not ips:
                idx.anomaly_rows_bad += 1
                continue

            if lab == "anomalous":
                for ip in ips:
                    idx.high_ip_set.add(ip)
                    sub = ip_to_subnet(ip)
                    if sub:
                        idx.high_ip_subnet_set.add(sub)
                    high_ip_counts[ip] = high_ip_counts.get(ip, 0) + 1
                for key in ip_ports:
                    idx.high_ip_port_set.add(key)
                continue

            if lab == "suspicious":
                nb_det = _safe_int_any(row.get("nbDetectors"))
                strong_nbdet = nb_det is not None and nb_det >= medium_nbdet_threshold
                for ip in ips:
                    idx.medium_ip_set.add(ip)
                    med_ip_counts[ip] = med_ip_counts.get(ip, 0) + 1
                    if strong_nbdet:
                        med_nbdet_strong_ip.add(ip)
                for key in ip_ports:
                    idx.medium_ip_port_set.add(key)
                    med_ip_port_counts[key] = med_ip_port_counts.get(key, 0) + 1
                    if strong_nbdet:
                        med_nbdet_strong_ip_port.add(key)
                continue

            idx.anomaly_rows_bad += 1

    idx.high_freq_ip_set = {ip for ip, c in high_ip_counts.items() if c >= high_ip_repeat_threshold}
    idx.medium_strong_ip_set = (
        {ip for ip, c in med_ip_counts.items() if c >= medium_repeat_threshold} | med_nbdet_strong_ip
    )
    idx.medium_strong_ip_port_set = (
        {k for k, c in med_ip_port_counts.items() if c >= medium_repeat_threshold} | med_nbdet_strong_ip_port
    )

    if notice_csv is not None:
        with notice_csv.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames:
                reader.fieldnames = [str(h).strip() for h in reader.fieldnames]
            for row in reader:
                row = {str(k).strip(): v for k, v in row.items()}
                idx.notice_rows_total += 1
                lab = str(row.get("label") or "").strip().lower()
                if lab != "notice":
                    idx.notice_rows_bad += 1
                    continue
                src_ip = normalize_ip(_norm_ip(row.get("srcIP")))
                dst_ip = normalize_ip(_norm_ip(row.get("dstIP")))
                src_port = _safe_port(row.get("srcPort"))
                dst_port = _safe_port(row.get("dstPort"))
                ips, ip_ports = _add_ip_port_keys(src_ip, src_port, dst_ip, dst_port)
                if not ips:
                    idx.notice_rows_bad += 1
                    continue
                for ip in ips:
                    idx.low_notice_ip_set.add(ip)
                    low_ip_counts[ip] = low_ip_counts.get(ip, 0) + 1
                for key in ip_ports:
                    idx.low_notice_ip_port_set.add(key)

        idx.low_notice_freq_ip_set = {
            ip for ip, c in low_ip_counts.items() if c >= low_notice_repeat_threshold
        }

    return idx


def mawi_flow_risk(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    idx: MawiWeakIndex,
) -> Tuple[str, str]:
    src_sub = ip_to_subnet(src_ip)
    dst_sub = ip_to_subnet(dst_ip)
    if (
        src_ip in idx.high_ip_set or
        dst_ip in idx.high_ip_set or
        src_sub in idx.high_ip_subnet_set or
        dst_sub in idx.high_ip_subnet_set
    ):
        print(f"[MATCH FOUND] src={src_ip} dst={dst_ip}", file=sys.stderr)
        return "high", "high_ip"
    # HIGH: anomalous IP+port or anomalous IP (exact) or frequent anomalous IP
    if (src_ip, src_port) in idx.high_ip_port_set or (dst_ip, dst_port) in idx.high_ip_port_set:
        return "high", "high_ip_port"
    if src_ip in idx.high_freq_ip_set or dst_ip in idx.high_freq_ip_set:
        return "high", "high_ip_freq"

    # MEDIUM: suspicious only if strong condition met
    if (src_ip, src_port) in idx.medium_strong_ip_port_set or (dst_ip, dst_port) in idx.medium_strong_ip_port_set:
        return "medium", "medium_ip_port_strong"
    if src_ip in idx.medium_strong_ip_set or dst_ip in idx.medium_strong_ip_set:
        return "medium", "medium_ip_strong"

    # LOW: notice only (never hard-remove by itself)
    if (src_ip, src_port) in idx.low_notice_ip_port_set or (dst_ip, dst_port) in idx.low_notice_ip_port_set:
        return "low", "low_notice_ip_port"
    if src_ip in idx.low_notice_freq_ip_set or dst_ip in idx.low_notice_freq_ip_set:
        return "low", "low_notice_ip_freq"

    return "normal", "none"


def _eastern_to_utc_epoch(year: int, month: int, day: int, hour: int, minute: int) -> float:
    dt_eastern = datetime(year, month, day, hour, minute, 0)
    dt_utc = dt_eastern + timedelta(hours=EASTERN_TO_UTC_HOURS)
    return dt_utc.replace(tzinfo=timezone.utc).timestamp()


def load_attack_windows_from_hardcoded_table(
    table: List[Tuple[str, int, int, int, int, int, int, int, List[str], List[str]]]
) -> List[AttackWindow]:
    windows: List[AttackWindow] = []
    for row in table:
        name, year, month, day, sh, sm, eh, em, atks, vics = row
        # Base UTC times from Eastern schedule
        start_ts = _eastern_to_utc_epoch(year, month, day, sh, sm)
        end_ts = _eastern_to_utc_epoch(year, month, day, eh, em)
        # Apply attack-type specific buffers
        start_buf, end_buf = ATTACK_BUFFERS.get(name, (60, 60))
        start_ts -= start_buf
        end_ts += end_buf
        attackers = set(atks)
        victims = set(vics)
        w = AttackWindow(
            start_ts=start_ts, end_ts=end_ts,
            ips=attackers | victims, attackers=attackers, victims=victims, attack_name=name,
        )
        windows.append(w)
    return windows


def _experiment_date_from_path(eve_path: Path) -> Optional[Tuple[date, str]]:
    path_str = str(eve_path)
    m = re.search(r"(\d{1,2})-(\d{1,2})-(\d{4})", path_str)
    if not m:
        return None
    day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
    try:
        d = date(year, month, day)
    except ValueError:
        return None
    label = eve_path.parent.name if eve_path.parent and eve_path.parent.name else f"{year:04d}-{month:02d}-{day:02d}"
    return d, label


def _filter_windows_for_experiment(
    windows: List[AttackWindow], eve_path: Path
) -> Tuple[List[AttackWindow], Optional[str]]:
    parsed = _experiment_date_from_path(eve_path)
    if parsed is None:
        return windows, None
    exp_date, label = parsed
    filtered = [w for w in windows if datetime.fromtimestamp(w.start_ts, tz=timezone.utc).date() == exp_date]
    return filtered, label


def _event_timestamp_epoch(ev: Dict[str, Any]) -> Optional[float]:
    """Get event time as UTC epoch. Uses flow.start for flow events, else timestamp."""
    if ev.get("event_type") == "flow":
        flow = ev.get("flow") or {}
        raw = flow.get("start")
        if raw is not None:
            try:
                if isinstance(raw, (int, float)):
                    return float(raw)
                s = str(raw).replace("Z", "+00:00")
                return datetime.fromisoformat(s).timestamp()
            except Exception:
                pass
    raw = ev.get("timestamp")
    if raw is None:
        return None
    try:
        if isinstance(raw, (int, float)):
            return float(raw)
        s = str(raw).replace("Z", "+00:00")
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def label_event(ev: Dict[str, Any], windows: List[AttackWindow]) -> Tuple[bool, str]:
    """
    Classify any event (flow or http) as attack or benign using time windows and IPs.
    DoS/Web: directional (attacker→victim). Bot/Infiltration: bidirectional.
    """
    ts = _event_timestamp_epoch(ev)
    if ts is None:
        return False, "benign"
    src = (ev.get("src_ip") or "").strip()
    dst = (ev.get("dest_ip") or "").strip()
    for w in windows:
        if not (w.start_ts <= ts <= w.end_ts):
            continue
        attack_name = (w.attack_name or "unknown").strip() or "unknown"
        if w.attackers and w.victims:
            if attack_name in DOS_TYPES or attack_name in WEB_TYPES:
                if src in w.attackers and dst in w.victims:
                    return True, attack_name
            elif attack_name in C2_TYPES:
                if (src in w.attackers and dst in w.victims) or (src in w.victims and dst in w.attackers):
                    return True, attack_name
            else:
                if src in w.attackers and dst in w.victims:
                    return True, attack_name
        elif w.attackers:
            if src in w.attackers:
                return True, attack_name
        elif w.ips:
            if src in w.ips or dst in w.ips:
                return True, attack_name
    return False, "benign"


def label_full_attack_dataset(_ev: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Fallback for datasets with no known attack time window (e.g. synthetic attack PCAPs).
    Labels every event as attack so the ground truth reflects a full-attack dataset.
    """
    return True, "synthetic"


def _canonical_proto_str(val: Any) -> str:
    """Canonicalize protocol to an upper-case string (e.g. TCP/UDP/ICMP/6/17)."""
    if val is None:
        return ""
    return str(val).strip().upper()


def _parse_toniot_timestamp(raw: Any) -> Optional[float]:
    """Parse TON_IoT ground-truth timestamp to epoch seconds."""
    if raw is None:
        return None
    # numeric epoch (seconds)
    try:
        if isinstance(raw, (int, float)):
            return float(raw)
        s = str(raw).strip()
        if not s:
            return None
        # Try numeric first
        if re.fullmatch(r"-?\d+(\.\d+)?", s):
            return float(s)
        # Fallback: ISO-ish string
        s_norm = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s_norm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def load_toniot_ground_truth_csv(path: Path, tolerance: float) -> Tuple[Dict[Tuple[str, str, int, int, str], List[float]], float]:
    """
    Load TON_IoT ground-truth CSV into an index for fast lookup.

    Expected columns (minimal):
      ts, src_ip, src_port, dst_ip, dst_port, proto, type

    Index key: (src_ip, dst_ip, src_port, dst_port, proto_str) -> sorted list of ts (epoch seconds).
    """
    index: Dict[Tuple[str, str, int, int, str], List[float]] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts_raw = row.get("ts") or row.get("timestamp")
            ts = _parse_toniot_timestamp(ts_raw)
            if ts is None:
                continue
            src_ip = (row.get("src_ip") or "").strip()
            dst_ip = (row.get("dst_ip") or "").strip()
            if not src_ip or not dst_ip:
                continue
            try:
                src_port = int(row.get("src_port") or 0)
                dst_port = int(row.get("dst_port") or 0)
            except ValueError:
                continue
            proto = _canonical_proto_str(row.get("proto"))
            key = (src_ip, dst_ip, src_port, dst_port, proto)
            index.setdefault(key, []).append(ts)
    # Sort timestamps per key for efficient time-window search
    for ts_list in index.values():
        ts_list.sort()
    return index, tolerance if tolerance > 0 else TONIOT_TIME_TOLERANCE_SEC


def _toniot_match_timestamp(ts: float, times: List[float], tolerance: float) -> bool:
    """Check if ts is within tolerance of any timestamp in the sorted list times."""
    if not times:
        return False
    i = bisect.bisect_left(times, ts)
    # Check nearest neighbors
    for j in (i, i - 1):
        if 0 <= j < len(times) and abs(times[j] - ts) <= tolerance:
            return True
    return False


def label_toniot_event(
    ev: Dict[str, Any],
    gt_index: Dict[Tuple[str, str, int, int, str], List[float]],
    tolerance: float,
) -> Tuple[bool, str]:
    """
    TON_IoT labeling: per-flow ground-truth CSV match, no attack windows.

    Match rule:
      abs(flow_ts - gt_ts) <= tolerance
      AND src_ip == gt.src_ip
      AND dst_ip == gt.dst_ip
      AND src_port == gt.src_port
      AND dst_port == gt.dst_port
      AND proto == gt.proto
    """
    ts = _event_timestamp_epoch(ev)
    if ts is None:
        return False, "benign"
    src_ip = (ev.get("src_ip") or "").strip()
    dst_ip = (ev.get("dest_ip") or "").strip()
    if not src_ip or not dst_ip:
        return False, "benign"
    try:
        src_port = int(ev.get("src_port") or 0)
        dst_port = int(ev.get("dest_port") or 0)
    except ValueError:
        return False, "benign"
    proto = _canonical_proto_str(ev.get("proto"))
    key = (src_ip, dst_ip, src_port, dst_port, proto)
    times = gt_index.get(key)
    if not times:
        return False, "benign"
    if _toniot_match_timestamp(ts, times, tolerance):
        return True, "backdoor"
    return False, "benign"


def _event_involves_attacker(src_ip: str, dst_ip: str, ts: Optional[float], windows: List[AttackWindow]) -> bool:
    if ts is None:
        return False
    for w in windows:
        if not w.attackers or not (w.start_ts <= ts <= w.end_ts):
            continue
        if src_ip in w.attackers or dst_ip in w.attackers:
            return True
    return False


def _event_involves_victim(src_ip: str, dst_ip: str, ts: Optional[float], windows: List[AttackWindow]) -> bool:
    if ts is None:
        return False
    for w in windows:
        if not w.victims or not (w.start_ts <= ts <= w.end_ts):
            continue
        if src_ip in w.victims or dst_ip in w.victims:
            return True
    return False


def _timestamp_str(ev: Dict[str, Any]) -> str:
    """Extract timestamp string for output (flow.start or timestamp)."""
    if ev.get("event_type") == "flow":
        flow = ev.get("flow") or {}
        start_val = flow.get("start") or ev.get("timestamp")
    else:
        start_val = ev.get("timestamp")
    if start_val is None:
        return ""
    if hasattr(start_val, "isoformat"):
        return start_val.isoformat()
    return str(start_val)


def process_flow(ev: Dict[str, Any]) -> Optional[Tuple[str, str, int, int, str, str, str, str, str, str]]:
    """Extract flow fields; HTTP fields are empty."""
    if ev.get("event_type") != "flow":
        return None
    src = str(ev.get("src_ip") or "").strip()
    dst = str(ev.get("dest_ip") or "").strip()
    if not src or not dst:
        return None
    src_port = int(ev.get("src_port") or 0)
    dst_port = int(ev.get("dest_port") or 0)
    proto = str(ev.get("proto") or "TCP").strip()
    ts_str = _timestamp_str(ev)
    return src, dst, src_port, dst_port, proto, ts_str, "flow", "", "", "", "", ""


def process_http(ev: Dict[str, Any]) -> Optional[Tuple[str, str, int, int, str, str, str, str, str, str, str, str]]:
    """Extract http row with HTTP fields."""
    if ev.get("event_type") != "http":
        return None
    src = str(ev.get("src_ip") or "").strip()
    dst = str(ev.get("dest_ip") or "").strip()
    if not src or not dst:
        return None
    src_port = int(ev.get("src_port") or 0)
    dst_port = int(ev.get("dest_port") or 0)
    proto = str(ev.get("proto") or "TCP").strip()
    ts_str = _timestamp_str(ev)
    http = ev.get("http") or {}
    http_method = str(http.get("http_method") or http.get("method") or "").strip()
    http_host = str(http.get("hostname") or http.get("http_host") or "").strip()
    http_url = str(http.get("url") or "").strip()
     # user agent may appear as http_user_agent or user_agent
    http_user_agent = str(http.get("http_user_agent") or http.get("user_agent") or "").strip()
    http_status = str(http.get("status") or http.get("status_code") or "").strip()
    return src, dst, src_port, dst_port, proto, ts_str, "http", http_method, http_host, http_url, http_user_agent, http_status


def _detect_json_format(path: Path) -> str:
    with open(path, "rb") as f:
        for i, line in enumerate(f):
            if i >= DETECT_PEEK_LINES:
                break
            line_dec = line.decode("utf-8", errors="replace").strip()
            if not line_dec:
                continue
            if line_dec.startswith("["):
                return "pretty"
            if line_dec.startswith("{") and line_dec.endswith("}"):
                return "ndjson"
            if line_dec.startswith("{"):
                return "pretty"
            return "ndjson"
    return "ndjson"


def _stream_ndjson(path: Path) -> Iterator[Dict[str, Any]]:
    decode_errors = 0
    if orjson is not None:
        with open(path, "rb") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield orjson.loads(line)
                except Exception as e:
                    decode_errors += 1
                    if decode_errors <= 10:
                        print(f"JSON decode error line {line_num}: {e}", file=sys.stderr)
                    continue
    else:
        import json
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    decode_errors += 1
                    if decode_errors <= 10:
                        print(f"JSON decode error line {line_num}: {e}", file=sys.stderr)
                    continue
    if decode_errors > 10:
        print(f"Total JSON decode errors: {decode_errors}", file=sys.stderr)


def _stream_pretty(path: Path) -> Iterator[Dict[str, Any]]:
    buffer: List[bytes] = []
    use_orjson = orjson is not None
    if not use_orjson:
        import json as _json
    parse_errors = 0
    with open(path, "rb") as f:
        for line in f:
            buffer.append(line)
            if line.strip().rstrip(b",") != b"}":
                continue
            try:
                raw = b"".join(buffer).rstrip()
                if raw.endswith(b","):
                    raw = raw[:-1].rstrip()
                if raw:
                    if use_orjson:
                        obj = orjson.loads(raw)
                    else:
                        obj = _json.loads(raw.decode("utf-8", errors="replace"))
                    if obj is not None:
                        yield obj
            except Exception as e:
                parse_errors += 1
                if parse_errors <= 10:
                    print(f"JSON parse error: {e}", file=sys.stderr)
            finally:
                buffer.clear()
    if parse_errors > 10:
        print(f"Total JSON parse errors: {parse_errors}", file=sys.stderr)


def stream_events(path: Path) -> Iterator[Dict[str, Any]]:
    if _detect_json_format(path) == "ndjson":
        yield from _stream_ndjson(path)
    else:
        yield from _stream_pretty(path)


def _csv_label_is_attack(lab: str) -> bool:
    s = lab.strip()
    if s == "1":
        return True
    return s.lower() == "attack"


def _csv_label_is_benign(lab: str) -> bool:
    s = lab.strip()
    if s == "0":
        return True
    return s.lower() == "benign"


def _verify_output_csvs(
    attack_path: Path,
    benign_path: Path,
    use_full_attack_fallback: bool,
) -> None:
    """Read output CSVs and print row counts; in fallback mode verify attack labels."""
    header = OUTPUT_HEADER
    idx_label = header.index("label")
    idx_attack_type = header.index("attack_type")
    idx_labeling_mode = header.index("labeling_mode")

    def count_and_validate(path: Path, expect_attack: bool) -> Tuple[int, bool]:
        count = 0
        had_bad = False
        benign_in_attack = 0
        bad_rows: List[Tuple[int, List[str]]] = []
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            first = next(reader, None)
            if first is None:
                return 0, False
            for row in reader:
                if not row or (len(row) > 0 and str(row[0]).strip().startswith("#")):
                    continue
                count += 1
                if len(row) > idx_label:
                    lab = row[idx_label].strip() if idx_label < len(row) else ""
                    if expect_attack and _csv_label_is_benign(lab):
                        benign_in_attack += 1
                if use_full_attack_fallback and expect_attack and len(row) > idx_labeling_mode:
                    lab = row[idx_label].strip() if idx_label < len(row) else ""
                    atype = row[idx_attack_type].strip() if idx_attack_type < len(row) else ""
                    lmode = row[idx_labeling_mode].strip() if idx_labeling_mode < len(row) else ""
                    if not _csv_label_is_attack(lab) or lmode != LABELING_MODE_FULL_ATTACK:
                        had_bad = True
                        bad_rows.append((count, row))
        if benign_in_attack > 0:
            print(
                f"[WARNING] Found {benign_in_attack} row(s) with benign label (0) in attack CSV",
                file=sys.stderr,
            )
        if bad_rows:
            print("[WARNING] Some attack rows have unexpected label/attack_type/labeling_mode:", file=sys.stderr)
            for row_num, r in bad_rows[:10]:
                lab = r[idx_label] if idx_label < len(r) else ""
                atype = r[idx_attack_type] if idx_attack_type < len(r) else ""
                lmode = r[idx_labeling_mode] if idx_labeling_mode < len(r) else ""
                print(f"  row {row_num}: label={lab!r} attack_type={atype!r} labeling_mode={lmode!r}", file=sys.stderr)
            if len(bad_rows) > 10:
                print(f"  ... and {len(bad_rows) - 10} more", file=sys.stderr)
        return count, had_bad

    attack_rows, attack_had_bad = count_and_validate(attack_path, expect_attack=True)
    benign_rows, _ = count_and_validate(benign_path, expect_attack=False)

    print("Verification:", file=sys.stderr)
    print(f"attack rows: {attack_rows}", file=sys.stderr)
    print(f"benign rows: {benign_rows}", file=sys.stderr)

    if use_full_attack_fallback and benign_rows > 0:
        print(f"[WARNING] FULL_ATTACK_DATASET mode but benign CSV has {benign_rows} rows (expected 0)", file=sys.stderr)
    if use_full_attack_fallback and attack_rows > 0 and not attack_had_bad:
        print("All labels verified", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build unified ground-truth CSV from Suricata eve.json for CICIDS2018, synthetic, or TON_IoT datasets.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=("mawi_weak_supervision",),
        default=None,
        help="Alias mode selector. If set to mawi_weak_supervision, overrides --dataset.",
    )
    parser.add_argument(
        "--dataset",
        required=False,
        default="cicids2018",
        choices=("cicids2018", "cicids2017", "synthetic", "toniot", "mawi_weak_supervision"),
        help="Dataset type: CICIDS2018 (UTC windows+IPs); CICIDS2017 (weekday-folder + bisect intervals + IP rule); synthetic; TON_IoT; MAWI weak supervision.",
    )
    parser.add_argument(
        "--day",
        type=str,
        default=None,
        help="Optional dataset_day label (used in output filenames); defaults to experiment label or parent directory name.",
    )
    parser.add_argument(
        "--ton-gt",
        type=Path,
        default=None,
        help="TON_IoT ground-truth CSV with columns ts,src_ip,src_port,dst_ip,dst_port,proto,type (required when --dataset toniot).",
    )
    parser.add_argument(
        "--ton-tolerance-sec",
        type=float,
        default=TONIOT_TIME_TOLERANCE_SEC,
        help="Time tolerance (seconds) for matching TON_IoT flows to ground-truth CSV.",
    )
    parser.add_argument(
        "--mawi-anomaly-csv",
        type=Path,
        default=None,
        help="MAWI anomaly+suspicious CSV (label column uses anomalous/suspicious). Required in mawi_weak_supervision mode.",
    )
    parser.add_argument(
        "--mawi-notice-csv",
        type=Path,
        default=None,
        help="MAWI notice CSV (label=notice). Optional low-confidence signal in mawi_weak_supervision mode.",
    )
    parser.add_argument(
        "--mawi-clean-mode",
        choices=("strict_clean", "balanced_clean", "no_clean"),
        default="balanced_clean",
        help="strict: remove high+medium; balanced: remove high only; none: keep all.",
    )
    parser.add_argument(
        "--mawi-medium-nbdet-threshold",
        type=int,
        default=4,
        help="Suspicious match is medium-risk only if nbDetectors >= threshold or repeated occurrences.",
    )
    parser.add_argument(
        "--mawi-medium-repeat-threshold",
        type=int,
        default=2,
        help="Suspicious indicators repeated at least this many times become medium-risk.",
    )
    parser.add_argument(
        "--mawi-high-ip-repeat-threshold",
        type=int,
        default=2,
        help="Anomalous IP appearing this often is treated as strong high-risk IP match.",
    )
    parser.add_argument(
        "--mawi-low-notice-repeat-threshold",
        type=int,
        default=3,
        help="Notice IP appearing this often is tracked as low-risk frequent notice IP.",
    )
    parser.add_argument(
        "--use-weights",
        action="store_true",
        help="Output weak-supervision sample weights (high=0.0, medium=0.4, low=0.7, normal=1.0).",
    )
    parser.add_argument(
        "--weights-out",
        type=Path,
        default=None,
        help="Path for optional weights CSV (flow_key,sample_weight,risk,rule).",
    )
    parser.add_argument(
        "eve",
        type=Path,
        help="Path to Suricata master_eve.json (NDJSON or pretty-printed JSON).",
    )
    parser.add_argument(
        "total_est",
        nargs="?",
        type=int,
        default=None,
        help="Optional estimated total number of events (for progress reporting only).",
    )
    args = parser.parse_args()

    eve_path: Path = args.eve
    total_est: Optional[int] = args.total_est
    dataset_kind: str = args.mode or args.dataset

    if not eve_path.exists():
        print(f"Error: eve file not found: {eve_path}", file=sys.stderr)
        return 1
    if dataset_kind == "toniot" and args.ton_gt is None:
        print("Error: --ton-gt is required when --dataset toniot", file=sys.stderr)
        return 1
    if dataset_kind == "mawi_weak_supervision" and args.mawi_anomaly_csv is None:
        print("Error: --mawi-anomaly-csv is required for mawi_weak_supervision mode", file=sys.stderr)
        return 1

    # Dataset-specific initialization
    all_windows: List[AttackWindow] = []
    windows: List[AttackWindow] = []
    experiment_label: Optional[str] = None
    use_full_attack_fallback = False
    synthetic_attack_type_label = ""
    toniot_index: Dict[Tuple[str, str, int, int, str], List[float]] = {}
    toniot_tolerance = args.ton_tolerance_sec
    mawi_idx = MawiWeakIndex()
    cicids2017_day_key: Optional[str] = None

    if dataset_kind == "cicids2018":
        # CICIDS2018: hard-coded schedule + directional IP labeling in label_event()
        all_windows = load_attack_windows_from_hardcoded_table(CICIDS2018_HARDCODED_TABLE)
        windows, experiment_label = _filter_windows_for_experiment(all_windows, eve_path)
        use_full_attack_fallback = (len(windows) == 0) or (experiment_label is None)
        if use_full_attack_fallback:
            print(
                "[WARNING] No attack window found for this dataset.\n"
                "Falling back to FULL_ATTACK_DATASET mode.\n"
                "All flows will be labeled as attacks.",
                file=sys.stderr,
            )
            print("[INFO] FULL_ATTACK_DATASET mode active — all flows will be labeled as attack", file=sys.stderr)
    elif dataset_kind == "cicids2017":
        try:
            cicids2017_day_key = cicids2017_day_key_from_path(eve_path.resolve())
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        experiment_label = cicids2017_day_key
        use_full_attack_fallback = False
    elif dataset_kind == "synthetic":
        # Synthetic datasets: all traffic is attack traffic by design.
        use_full_attack_fallback = True
        synthetic_attack_type_label = str(eve_path.parent.name).strip() or "synthetic"
        print(
            "[INFO] Synthetic dataset selected (FULL_ATTACK_DATASET). "
            f"All flows labeled attack; attack_type from folder name: {synthetic_attack_type_label!r}.",
            file=sys.stderr,
        )
    elif dataset_kind == "toniot":
        # TON_IoT: per-flow ground-truth CSV matching, no windows.
        assert args.ton_gt is not None
        toniot_index, toniot_tolerance = load_toniot_ground_truth_csv(args.ton_gt, toniot_tolerance)
        total_gt = sum(len(v) for v in toniot_index.values())
        print(f"Loaded TON_IoT ground truth entries: {total_gt}", file=sys.stderr)
    elif dataset_kind == "mawi_weak_supervision":
        assert args.mawi_anomaly_csv is not None
        mawi_idx = load_mawi_weak_supervision(
            anomaly_csv=args.mawi_anomaly_csv,
            notice_csv=args.mawi_notice_csv,
            medium_nbdet_threshold=args.mawi_medium_nbdet_threshold,
            medium_repeat_threshold=args.mawi_medium_repeat_threshold,
            high_ip_repeat_threshold=args.mawi_high_ip_repeat_threshold,
            low_notice_repeat_threshold=args.mawi_low_notice_repeat_threshold,
        )
        print(
            f"Loaded MAWI weak labels: anomaly_rows={mawi_idx.anomaly_rows_total:,} "
            f"anomaly_bad={mawi_idx.anomaly_rows_bad:,} notice_rows={mawi_idx.notice_rows_total:,} "
            f"notice_bad={mawi_idx.notice_rows_bad:,}",
            file=sys.stderr,
        )
        print(f"[DEBUG] Sample MAWI high IPs: {list(mawi_idx.high_ip_set)[:10]}", file=sys.stderr)

    day_override: Optional[str] = args.day
    dataset_day = day_override or experiment_label or eve_path.parent.name or dataset_kind

    # Concise startup summary + buffer info (windows only meaningful for CICIDS2018)
    print(f"Dataset kind: {dataset_kind}", file=sys.stderr)
    print(f"Dataset day: {dataset_day}", file=sys.stderr)
    if dataset_kind == "cicids2017" and cicids2017_day_key:
        tab = CICIDS2017_INTERVAL_INDEX.get(cicids2017_day_key)
        niv = len(tab.starts) if tab else 0
        print(
            f"CICIDS2017: weekday={cicids2017_day_key} calendar={CICIDS2017_DAY_TO_DATE[cicids2017_day_key]} "
            f"intervals={niv} (bisect lookup; labeling_mode={LABELING_MODE_CICIDS2017_FAST})",
            file=sys.stderr,
        )
        if tab:
            for j in range(len(tab.starts)):
                t0 = datetime.fromtimestamp(tab.starts[j], tz=timezone.utc).strftime("%H:%M:%S")
                t1 = datetime.fromtimestamp(tab.ends_excl[j] - 0.001, tz=timezone.utc).strftime("%H:%M:%S")
                print(
                    f"  [interval] {tab.attack_types[j]}/{tab.attack_subtypes[j]} ~UTC {t0}–{t1}",
                    file=sys.stderr,
                )
    else:
        print(f"Loaded {len(all_windows)} attack windows", file=sys.stderr)
        print(f"Active windows: {len(windows)}", file=sys.stderr)
        for w in windows:
            start_utc = datetime.fromtimestamp(w.start_ts, tz=timezone.utc).strftime("%H:%M")
            end_utc = datetime.fromtimestamp(w.end_ts, tz=timezone.utc).strftime("%H:%M")
            start_buf, end_buf = ATTACK_BUFFERS.get(w.attack_name, (60, 60))
            print(f"  [window] {w.attack_name} {start_utc}–{end_utc} UTC", file=sys.stderr)
            print(f"    buffer: start -{start_buf}s, end +{end_buf}s", file=sys.stderr)

    attack_path = Path(f"attack_{dataset_day}.csv")
    benign_path = Path(f"benign_{dataset_day}.csv")
    attack_file = attack_path.open("w", newline="", encoding="utf-8")
    benign_file = benign_path.open("w", newline="", encoding="utf-8")
    attack_writer = csv.writer(attack_file)
    benign_writer = csv.writer(benign_file)
    attack_writer.writerow(OUTPUT_HEADER)
    benign_writer.writerow(OUTPUT_HEADER)
    if use_full_attack_fallback:
        comment = "# No attack window detected. Labeled using FULL_ATTACK_DATASET fallback mode."
        attack_file.write(comment + "\n")
        benign_file.write(comment + "\n")
    weights_writer = None
    weights_file = None
    if dataset_kind == "mawi_weak_supervision" and args.use_weights:
        weights_path = args.weights_out or Path(f"weights_{dataset_day}.csv")
        weights_file = weights_path.open("w", newline="", encoding="utf-8")
        weights_writer = csv.writer(weights_file)
        weights_writer.writerow(["flow_key", "sample_weight", "risk", "rule"])

    total_events_parsed = 0
    processed = 0
    missing_flow_id = 0
    attack_count = 0
    benign_count = 0
    attack_with_attacker_ip = 0
    attack_with_victim_ip = 0
    attack_type_counts: Dict[str, int] = {}
    start_time = time.perf_counter()
    next_progress = PROGRESS_EVERY
    next_attack_stats = ATTACK_STATS_EVERY
    next_breakdown = ATTACK_BREAKDOWN_EVERY
    removed_total = 0
    removed_by_rule: Dict[str, int] = {}
    matched_risk_counts: Dict[str, int] = {"high": 0, "medium": 0, "low": 0, "normal": 0}
    matched_indicator_counts: Dict[str, int] = {}
    # Track matched weak-indicator keys for unmatched reporting.
    matched_high_ips: Set[str] = set()
    matched_high_ip_ports: Set[Tuple[str, int]] = set()
    matched_medium_ips: Set[str] = set()
    matched_medium_ip_ports: Set[Tuple[str, int]] = set()
    matched_low_ips: Set[str] = set()
    matched_low_ip_ports: Set[Tuple[str, int]] = set()
    high_zero_warned = False
    mawi_seen_ips: Set[str] = set()

    # -------------------------------------------------------------------------
    # Why attacks often appear only after ~5–6M events ("6M mark"):
    # CICIDS PCAPs are ordered with benign traffic first; attack windows occur
    # later in the day. We process events sequentially, so we only see attack
    # flows/HTTP when the parser reaches that time range in the file.
    # -------------------------------------------------------------------------

    try:
        for ev in stream_events(eve_path):
            total_events_parsed += 1
            event_type = ev.get("event_type")

            if dataset_kind == "mawi_weak_supervision" and event_type != "flow":
                # MAWI weak supervision currently uses flow events only.
                continue
            if event_type == "flow":
                row_data = process_flow(ev)
            elif event_type == "http":
                row_data = process_http(ev)
            else:
                continue

            if row_data is None:
                continue

            src_ip, dst_ip, src_port, dst_port, proto, timestamp_str, etype, hm, hh, hu, h_ua, hs = row_data
            src_ip = normalize_ip(src_ip)
            dst_ip = normalize_ip(dst_ip)
            if dataset_kind == "mawi_weak_supervision":
                if src_ip:
                    mawi_seen_ips.add(src_ip)
                if dst_ip:
                    mawi_seen_ips.add(dst_ip)
            if src_ip == "60.130.105.85" or dst_ip == "60.130.105.85":
                print(f"[FLOW HIT] src={src_ip} dst={dst_ip}", file=sys.stderr)

            if dataset_kind == "synthetic" or (dataset_kind == "cicids2018" and use_full_attack_fallback):
                # Synthetic datasets and CICIDS fallback: treat all events as attacks.
                is_attack, attack_type = label_full_attack_dataset(ev)
                labeling_mode = LABELING_MODE_FULL_ATTACK
                if synthetic_attack_type_label:
                    attack_type = synthetic_attack_type_label
            elif dataset_kind == "toniot":
                # TON_IoT: per-flow ground-truth CSV matching.
                is_attack, attack_type = label_toniot_event(ev, toniot_index, toniot_tolerance)
                labeling_mode = LABELING_MODE_GROUND_TRUTH
            elif dataset_kind == "cicids2017":
                ts_ev = _event_timestamp_epoch(ev)
                win = None
                if ts_ev is not None and cicids2017_day_key is not None:
                    win = cicids2017_lookup_interval(cicids2017_day_key, ts_ev)
                is_attack = win is not None and cicids2017_is_attack_ip(src_ip, dst_ip)
                if is_attack and win is not None:
                    atype0, sub0 = win
                    if atype0 == "Infiltration" and src_ip == CICIDS2017_LATERAL_VISTA_SRC:
                        atype0 = "LateralMovement"
                    attack_type = f"{atype0}/{sub0}"
                else:
                    attack_type = "benign"
                labeling_mode = LABELING_MODE_CICIDS2017_FAST
            elif dataset_kind == "mawi_weak_supervision":
                risk, rule = mawi_flow_risk(src_ip, dst_ip, src_port, dst_port, mawi_idx)
                matched_risk_counts[risk] = matched_risk_counts.get(risk, 0) + 1
                matched_indicator_counts[rule] = matched_indicator_counts.get(rule, 0) + 1
                if rule == "high_ip":
                    if src_ip in mawi_idx.high_ip_set:
                        matched_high_ips.add(src_ip)
                    if dst_ip in mawi_idx.high_ip_set:
                        matched_high_ips.add(dst_ip)
                elif rule == "high_ip_port":
                    if (src_ip, src_port) in mawi_idx.high_ip_port_set:
                        matched_high_ip_ports.add((src_ip, src_port))
                    if (dst_ip, dst_port) in mawi_idx.high_ip_port_set:
                        matched_high_ip_ports.add((dst_ip, dst_port))
                elif rule == "high_ip_freq":
                    if src_ip in mawi_idx.high_freq_ip_set:
                        matched_high_ips.add(src_ip)
                    if dst_ip in mawi_idx.high_freq_ip_set:
                        matched_high_ips.add(dst_ip)
                elif rule == "medium_ip_strong":
                    if src_ip in mawi_idx.medium_strong_ip_set:
                        matched_medium_ips.add(src_ip)
                    if dst_ip in mawi_idx.medium_strong_ip_set:
                        matched_medium_ips.add(dst_ip)
                elif rule == "medium_ip_port_strong":
                    if (src_ip, src_port) in mawi_idx.medium_strong_ip_port_set:
                        matched_medium_ip_ports.add((src_ip, src_port))
                    if (dst_ip, dst_port) in mawi_idx.medium_strong_ip_port_set:
                        matched_medium_ip_ports.add((dst_ip, dst_port))
                elif rule == "low_notice_ip_freq":
                    if src_ip in mawi_idx.low_notice_freq_ip_set:
                        matched_low_ips.add(src_ip)
                    if dst_ip in mawi_idx.low_notice_freq_ip_set:
                        matched_low_ips.add(dst_ip)
                elif rule == "low_notice_ip_port":
                    if (src_ip, src_port) in mawi_idx.low_notice_ip_port_set:
                        matched_low_ip_ports.add((src_ip, src_port))
                    if (dst_ip, dst_port) in mawi_idx.low_notice_ip_port_set:
                        matched_low_ip_ports.add((dst_ip, dst_port))
                is_attack = risk in {"high", "medium"}
                attack_type = f"mawi_{risk}" if risk != "normal" else "benign"
                labeling_mode = LABELING_MODE_MAWI_WEAK
                if rule != "none":
                    print(f"[MATCH] {rule} src={src_ip} dst={dst_ip}", file=sys.stderr)
            else:
                # CICIDS2018 normal window-based labeling
                is_attack, attack_type = label_event(ev, windows)
                labeling_mode = LABELING_MODE_WINDOW_BASED

            label = 1 if is_attack else 0
            if dataset_kind == "mawi_weak_supervision":
                atype = attack_type
            else:
                atype = attack_type if is_attack else "benign"
            flow_id = ev.get("flow_id")
            flow_id_str = str(flow_id) if flow_id is not None else ""
            if flow_id is None:
                missing_flow_id += 1
            ts_key = _event_timestamp_epoch(ev) or 0.0
            if flow_id is not None:
                flow_key = f"{dataset_day}-{flow_id}"
            else:
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}-{int(ts_key)}"
            row = [
                dataset_day,
                timestamp_str,
                etype,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto,
                flow_id_str,
                flow_key,
                hm,
                hh,
                hu,
                h_ua,
                hs,
                label,
                atype,
                labeling_mode,
            ]
            keep_row = True
            if dataset_kind == "mawi_weak_supervision":
                # strict_clean: remove high + medium
                # balanced_clean: remove high only
                # no_clean: remove nothing
                if args.mawi_clean_mode == "strict_clean":
                    keep_row = not (atype in ("mawi_high", "mawi_medium"))
                elif args.mawi_clean_mode == "balanced_clean":
                    keep_row = atype != "mawi_high"
                elif args.mawi_clean_mode == "no_clean":
                    keep_row = True
                if not keep_row:
                    removed_total += 1
                    removed_by_rule[atype] = removed_by_rule.get(atype, 0) + 1
                if weights_writer is not None:
                    if atype == "mawi_high":
                        w = 0.0
                    elif atype == "mawi_medium":
                        w = 0.4
                    elif atype == "mawi_low":
                        w = 0.7
                    else:
                        w = 1.0
                    weights_writer.writerow([flow_key, f"{w:.3f}", atype, rule])

            if dataset_kind == "mawi_weak_supervision":
                if keep_row:
                    benign_writer.writerow(row)
                    benign_count += 1
                else:
                    attack_writer.writerow(row)
                    attack_count += 1
            elif is_attack:
                attack_writer.writerow(row)
                attack_count += 1
                attack_type_counts[atype] = attack_type_counts.get(atype, 0) + 1
                if dataset_kind == "cicids2018":
                    ts = _event_timestamp_epoch(ev)
                    if _event_involves_attacker(src_ip, dst_ip, ts, windows):
                        attack_with_attacker_ip += 1
                    if _event_involves_victim(src_ip, dst_ip, ts, windows):
                        attack_with_victim_ip += 1
            else:
                benign_writer.writerow(row)
                benign_count += 1
            processed += 1
            if dataset_kind == "mawi_weak_supervision" and processed % 5_000_000 == 0:
                print(f"[DEBUG] src={src_ip} dst={dst_ip}", file=sys.stderr)
            if (
                dataset_kind == "mawi_weak_supervision"
                and not high_zero_warned
                and processed > 1_000_000
                and matched_risk_counts.get("high", 0) == 0
            ):
                print("[ERROR] No HIGH matches detected — likely normalization or logic bug", file=sys.stderr)
                high_zero_warned = True

            if processed >= next_progress:
                gc.collect()
                attack_file.flush()
                benign_file.flush()
                elapsed = time.perf_counter() - start_time
                speed = processed / elapsed if elapsed > 0 else 0
                rate_str = f"{speed / 1000:.0f}k/s" if speed >= 1000 else f"{speed:.0f}/s"
                print(
                    f"[{processed // 1_000_000}M events] attack={attack_count:,} benign={benign_count:,} rate={rate_str}",
                    file=sys.stderr,
                )
                if processed >= next_attack_stats:
                    print(
                        f"  attack_with_attacker_ip={attack_with_attacker_ip:,} attack_with_victim_ip={attack_with_victim_ip:,}",
                        file=sys.stderr,
                    )
                    next_attack_stats = (processed // ATTACK_STATS_EVERY + 1) * ATTACK_STATS_EVERY
                next_progress = (processed // PROGRESS_EVERY + 1) * PROGRESS_EVERY

            if processed >= next_breakdown and attack_type_counts:
                print("Attack breakdown:", file=sys.stderr)
                for name, count in sorted(attack_type_counts.items(), key=lambda x: -x[1]):
                    print(f"  {name}: {count:,}", file=sys.stderr)
                next_breakdown = (processed // ATTACK_BREAKDOWN_EVERY + 1) * ATTACK_BREAKDOWN_EVERY
    finally:
        attack_file.close()
        benign_file.close()
        if weights_file is not None:
            weights_file.close()

    elapsed = time.perf_counter() - start_time
    speed = processed / elapsed if elapsed > 0 else 0
    total_written = attack_count + benign_count

    print(f"Total events parsed: {total_events_parsed:,}", file=sys.stderr)
    print(
        f"Processed: {processed:,} | attack: {attack_count:,} | benign: {benign_count:,} | "
        f"{speed:,.0f}/s | {elapsed:.1f}s",
        file=sys.stderr,
    )
    if missing_flow_id:
        print(
            f"Events without flow_id (fallback flow_key): {missing_flow_id:,} / {processed:,}",
            file=sys.stderr,
        )
    expected_written = processed - removed_total if dataset_kind == "mawi_weak_supervision" else processed
    if total_written != expected_written:
        print(
            f"WARNING: attack+benign ({total_written:,}) != expected_written ({expected_written:,})",
            file=sys.stderr,
        )
    else:
        if dataset_kind == "mawi_weak_supervision":
            print(
                f"OK: attack+benign == expected_written ({expected_written:,}); removed={removed_total:,}",
                file=sys.stderr,
            )
        else:
            print(f"OK: attack+benign == processed ({processed:,})", file=sys.stderr)
    if total_est and processed > 0:
        print(f"Dataset: {processed:,} / ~{total_est:,} ({100.0 * processed / total_est:.1f}%)", file=sys.stderr)
    if attack_type_counts:
        print("Final attack distribution:", file=sys.stderr)
        for name, count in sorted(attack_type_counts.items(), key=lambda x: -x[1]):
            print(f"  {name}: {count:,}", file=sys.stderr)
    if dataset_kind == "mawi_weak_supervision":
        print("MAWI weak-supervision report:", file=sys.stderr)
        print(
            f"  clean_mode={args.mawi_clean_mode} total_flows={processed:,} "
            f"high={matched_risk_counts.get('high', 0):,} medium={matched_risk_counts.get('medium', 0):,} "
            f"low={matched_risk_counts.get('low', 0):,} normal={matched_risk_counts.get('normal', 0):,}",
            file=sys.stderr,
        )
        print(
            f"  removed={removed_total:,} ({(100.0 * removed_total / processed) if processed else 0.0:.2f}%)",
            file=sys.stderr,
        )
        if removed_by_rule:
            for k, v in sorted(removed_by_rule.items(), key=lambda x: -x[1]):
                print(f"    removed_by_{k}: {v:,}", file=sys.stderr)
        if matched_indicator_counts:
            print("  match_rule_breakdown:", file=sys.stderr)
            for k, v in sorted(matched_indicator_counts.items(), key=lambda x: -x[1]):
                print(f"    {k}: {v:,}", file=sys.stderr)
        if processed > 0 and (removed_total / processed) > 0.40:
            print(
                "[WARNING] Over-filtering: >40% flows removed. Prefer balanced_clean or no_clean.",
                file=sys.stderr,
            )
        unmatched_high_ip = len((mawi_idx.high_ip_set | mawi_idx.high_freq_ip_set) - matched_high_ips)
        unmatched_high_ip_port = len(mawi_idx.high_ip_port_set - matched_high_ip_ports)
        unmatched_medium_ip = len(mawi_idx.medium_strong_ip_set - matched_medium_ips)
        unmatched_medium_ip_port = len(mawi_idx.medium_strong_ip_port_set - matched_medium_ip_ports)
        unmatched_low_ip = len(mawi_idx.low_notice_freq_ip_set - matched_low_ips)
        unmatched_low_ip_port = len(mawi_idx.low_notice_ip_port_set - matched_low_ip_ports)
        print(
            f"  unmatched_indicators: high_ip={unmatched_high_ip:,} high_ip_port={unmatched_high_ip_port:,} "
            f"medium_ip={unmatched_medium_ip:,} medium_ip_port={unmatched_medium_ip_port:,} "
            f"low_notice_ip={unmatched_low_ip:,} low_notice_ip_port={unmatched_low_ip_port:,}",
            file=sys.stderr,
        )
        overlap_high_ip = len(mawi_idx.high_ip_set & mawi_seen_ips)
        overlap_medium_ip = len(mawi_idx.medium_strong_ip_set & mawi_seen_ips)
        overlap_low_ip = len(mawi_idx.low_notice_freq_ip_set & mawi_seen_ips)
        print(
            f"  seen_flow_ip_overlap: high_ip={overlap_high_ip:,}/{len(mawi_idx.high_ip_set):,} "
            f"medium_ip={overlap_medium_ip:,}/{len(mawi_idx.medium_strong_ip_set):,} "
            f"low_notice_ip={overlap_low_ip:,}/{len(mawi_idx.low_notice_freq_ip_set):,}",
            file=sys.stderr,
        )
    print(f"Attack rows written: {attack_count}", file=sys.stderr)
    print(f"Benign rows written: {benign_count}", file=sys.stderr)
    print(f"Wrote datasets: {attack_path} and {benign_path}", file=sys.stderr)

    _verify_output_csvs(attack_path, benign_path, use_full_attack_fallback)
    return 0


if __name__ == "__main__":
    sys.exit(main())
