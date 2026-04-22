#!/usr/bin/env bash
# Generate synthetic recon EVE JSONL with hex flow_id on every flow record.
#
# Usage:
#   ./generate_recon_jsonl.sh [OUT_PATH] [TARGET_FLOW_EVENTS] [DURATION_SEC] [SEED]
#
# Example (100,500 flow rows + optional dns/http/tls/anomaly noise):
#   ./generate_recon_jsonl.sh scripts/recon.jsonl 100500 600 42
set -euo pipefail

OUT_PATH="${1:-recon.jsonl}"
TARGET_FLOW_EVENTS="${2:-100500}"
DURATION_SEC="${3:-600}"
SEED="${4:-42}"

python3 - "$OUT_PATH" "$TARGET_FLOW_EVENTS" "$DURATION_SEC" "$SEED" <<'PY'
import json, random, sys
from datetime import datetime, timedelta, timezone

out_path, target_flow_events, duration_sec, seed = (
    sys.argv[1],
    int(sys.argv[2]),
    int(sys.argv[3]),
    int(sys.argv[4]),
)
rng = random.Random(seed)
# Spread timestamps if the window is tight vs flow count
duration_sec = max(int(duration_sec), min(86_400, target_flow_events // 200))

# Synthetic Suricata-style flow_id: unique 16-digit lowercase hex (stable per generated flow order).
_FLOW_SEQ = 0
_FLOW_ID_BASE = 0xDEC0DE0000000000

def next_synthetic_flow_id() -> str:
    global _FLOW_SEQ
    _FLOW_SEQ += 1
    return f"{_FLOW_ID_BASE + _FLOW_SEQ:016x}"

start_dt = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=duration_sec)
def ts(x): return (start_dt + timedelta(seconds=float(x))).isoformat().replace("+00:00","Z")

# --- IP Pools ---
src_pool = [f"192.168.200.{i}" for i in range(10,80)] + [f"10.0.2.{i}" for i in range(2,40)]
dst_pool = ["172.31.65.6","172.31.69.8","172.31.70.12","172.31.71.44",
            "18.221.219.4","18.219.211.138","142.250.192.194","8.8.8.8","1.1.1.1"]

infra_ips = ["172.31.70.12","8.8.8.8","1.1.1.1"]

# --- Attacker Profiles (ASYMMETRY) ---
heavy_scanner = rng.choice(src_pool)
medium_scanners = rng.sample(src_pool, 5)

def pick_src():
    r = rng.random()
    if r < 0.5:
        return heavy_scanner
    elif r < 0.8:
        return rng.choice(medium_scanners)
    else:
        return rng.choice(src_pool)

# Sticky TTL per src
ttl_map = {ip: rng.choice([44,52,56,58,60,64,128]) for ip in src_pool}

def syn_outcome():
    r = rng.random()
    if r < 0.6: return "closed"
    if r < 0.85: return "open"
    return "filtered"

def build_flow(src_ip, dst_ip, src_port, dst_port, scan, t0):
    ttl = ttl_map.get(src_ip, 64)

    if scan == "syn":
        outcome = syn_outcome()
        pkts = rng.randint(1,3)
        age = rng.uniform(0.05,1.2)

        if outcome == "open":
            return pkts, rng.randint(1,2), age, "established", "syn_ack"
        elif outcome == "closed":
            return pkts, 1, age, "closed", "rst"
        else:
            return pkts, 0, age, "new", "timeout"

    if scan in ("fin","null","xmas"):
        pkts = 1
        age = rng.uniform(0.03,0.8)
        if rng.random() < 0.7:
            return pkts, 0, age, "new", "no_response"
        else:
            return pkts, 1, age, "closed", "rst"

    if scan == "svc":
        pkts = rng.randint(5,20)
        dst_pkts = rng.randint(3,25)
        age = rng.uniform(0.5,6.0)
        return pkts, dst_pkts, age, "established", "banner"

    return 1,0,0.1,"new","unknown"

def flow_event(src_ip, dst_ip, src_port, dst_port, scan, proto, t0, app=None):
    pkts_s, pkts_c, age, state, reason = build_flow(src_ip,dst_ip,src_port,dst_port,scan,t0)

    # jitter
    if rng.random() < 0.1:
        pkts_s = max(1, pkts_s - 1)

    bytes_s = pkts_s * rng.randint(40,1200)
    bytes_c = pkts_c * rng.randint(40,1200)

    return {
        "timestamp": ts(t0+age),
        "event_type":"flow",
        "flow_id": next_synthetic_flow_id(),
        "src_ip":src_ip,
        "dest_ip":dst_ip,
        "src_port":src_port,
        "dest_port":dst_port,
        "proto":proto,
        "app_proto":app,
        "flow":{
            "pkts_toserver":pkts_s,
            "pkts_toclient":pkts_c,
            "bytes_toserver":bytes_s,
            "bytes_toclient":bytes_c,
            "start":ts(t0),
            "end":ts(t0+age),
            "age":age,
            "state":state,
            "reason":reason,
            "ttl":ttl_map.get(src_ip,64)
        },
        "tcp":{
            "syn": scan in ("syn","svc"),
            "ack": scan=="svc",
            "fin": scan=="fin",
            "psh": scan=="xmas",
            "urg": scan=="xmas",
            "rst": reason=="rst",
            "window": rng.choice([0,1,2,4,8,16,32,64,128,256])
        } if proto=="TCP" else {},
        "ip":{
            "ttl":ttl_map.get(src_ip,64),
            "fragments": 1 if scan in ("fin","null","xmas") and rng.random()<0.15 else 0
        },
        "attack_type":"Recon",
        "label":"attack",
        "binary_label":1
    }

# --- FIXED anomaly ---
def anomaly_event(src_ip,t0):
    return {
        "timestamp":ts(t0),
        "event_type":"anomaly",
        "src_ip":src_ip,
        "dest_ip":rng.choice(infra_ips),
        "src_port":rng.randint(1024,65535),
        "dest_port":rng.randint(1,65535),
        "proto":"TCP",
        "anomaly":{
            "event":rng.choice(["TCP_REASSEMBLY_FAILED","UNABLE_TO_MATCH_RESPONSE"]),
            "severity":rng.choice([1,2,3])
        }
    }

# --- App-layer events ---
def http_event(src_ip,t0):
    return {
        "timestamp":ts(t0),
        "event_type":"http",
        "src_ip":src_ip,
        "dest_ip":"172.31.70.12",
        "src_port":rng.randint(1024,65535),
        "dest_port":rng.choice([80,8080,8443]),
        "proto":"TCP",
        "http":{
            "method":rng.choice(["GET","POST","HEAD"]),
            "url":rng.choice(["/","/admin","/login","/api"]),
            "status":rng.choice([200,301,403,404,500])
        }
    }

def dns_event(src_ip,t0):
    return {
        "timestamp":ts(t0),
        "event_type":"dns",
        "src_ip":src_ip,
        "dest_ip":"8.8.8.8",
        "src_port":rng.randint(1024,65535),
        "dest_port":53,
        "proto":"UDP"
    }

def tls_event(src_ip,t0):
    return {
        "timestamp":ts(t0),
        "event_type":"tls",
        "src_ip":src_ip,
        "dest_ip":"172.31.70.12",
        "src_port":rng.randint(1024,65535),
        "dest_port":443,
        "proto":"TCP"
    }

behaviors = ["horizontal_syn","vertical_syn","svc","fin","null","xmas","distributed","slow"]
weights = [18,18,15,10,10,10,5,4]

lines = []
n_flow = 0

while n_flow < target_flow_events:
    b = rng.choices(behaviors,weights)[0]

    # --- slow scan ---
    if b == "slow":
        t0 = rng.uniform(0,duration_sec) + rng.uniform(5,30)
    else:
        t0 = rng.uniform(0,duration_sec)

    src = pick_src()
    dst = rng.choice(dst_pool)
    sport = rng.choice([53,20,443,rng.randint(1024,65535)])
    proto = "TCP"

    if b=="horizontal_syn":
        dst = f"172.31.{rng.randint(64,79)}.{rng.randint(2,254)}"
        dport = rng.randint(20,1024)
        scan="syn"

    elif b=="vertical_syn":
        dport = rng.randint(1,2000)
        scan="syn"

    elif b=="svc":
        dport = rng.choice([80,443,22,21,25])
        scan="svc"

    elif b in ("fin","null","xmas"):
        dport = rng.randint(20,2000)
        scan=b

    elif b=="distributed":
        src = f"10.10.{rng.randint(0,20)}.{rng.randint(2,254)}"
        dport = rng.randint(20,1024)
        scan="syn"

    else:
        dport = rng.randint(20,1024)
        scan="syn"

    lines.append(flow_event(src,dst,sport,dport,scan,proto,t0))
    n_flow += 1

    # reduced anomaly rate
    if rng.random() < 0.05:
        lines.append(anomaly_event(src,t0+rng.uniform(0.01,0.2)))

    # app layer signals
    if rng.random() < 0.1:
        lines.append(http_event(src,t0))
    if rng.random() < 0.05:
        lines.append(dns_event(src,t0))
    if rng.random() < 0.05:
        lines.append(tls_event(src,t0))

lines.sort(key=lambda x: x["timestamp"])

n_flow_out = sum(1 for x in lines if x.get("event_type") == "flow")
last_fid = 0xDEC0DE0000000000 + n_flow_out
with open(out_path,"w") as f:
    for l in lines:
        f.write(json.dumps(l,separators=(",",":"))+"\n")

print(
    f"[+] wrote {len(lines)} events ({n_flow_out} flow rows; "
    f"flow_id range dec0de0000000001 … {last_fid:016x}) → {out_path}"
)
PY
