#!/usr/bin/env bash
#
# process_pcaps_experimental.sh
#
# Experimental Suricata → eve.json → NDJSON merger for large CICIDS PCAP dirs.
# - Runs Suricata on each PCAP in parallel.
# - Extracts only flow + HTTP events.
# - Produces a single NDJSON master_eve.json (one JSON object per line).
# - Fully streaming: no large files loaded into RAM, safe for 400+ PCAPs.
#

set -euo pipefail

# Allow many file descriptors to avoid “Too many open files” / “No more file handles”
ulimit -n 65535 || true

echo "==============================================="
echo " Suricata Parallel Feature Extractor (EXP)     "
echo " NDJSON master_eve.json builder for CICIDS     "
echo "==============================================="
echo

# --- 1. User input -------------------------------------------------------------

read -p "Enter Suricata config file path: " CONFIG
read -p "Enter PCAP directory: " PCAP_DIR
read -p "Enter destination directory for master_eve.json: " DEST_DIR

if [ ! -f "$CONFIG" ]; then
    echo "Error: Suricata config file not found: $CONFIG" >&2
    exit 1
fi

if [ ! -d "$PCAP_DIR" ]; then
    echo "Error: PCAP directory not found: $PCAP_DIR" >&2
    exit 1
fi

mkdir -p "$DEST_DIR"

MASTER="$DEST_DIR/master_eve.json"
ERROR_LOG="$DEST_DIR/failed_pcaps_experimental.log"

rm -f "$MASTER" "$ERROR_LOG"

# Temporary workspace lives inside DEST_DIR to avoid /tmp exhaustion
TMP_DIR="$(mktemp -d "$DEST_DIR/suri_tmp.XXXXXX")"

echo "[+] Temporary workspace: $TMP_DIR"
echo

# --- 2. Discover PCAP files (filter only real PCAP candidates) -----------------

# Include typical CICIDS patterns: *.pcap, cap*, UCAP*
mapfile -t FILES < <(
    find "$PCAP_DIR" -type f \( -name "*.pcap" -o -name "cap*" -o -name "UCAP*" \) | sort
)

TOTAL=${#FILES[@]}
if [ "$TOTAL" -eq 0 ]; then
    echo "Error: No PCAP files found in $PCAP_DIR (patterns: *.pcap, cap*, UCAP*)" >&2
    rm -rf "$TMP_DIR"
    exit 1
fi

echo "[+] Found $TOTAL PCAP files"
echo

# --- 3. Worker calculation -----------------------------------------------------

CORES="$(nproc || echo 4)"
WORKERS=$(( CORES - 1 ))
if [ "$WORKERS" -lt 2 ]; then
    WORKERS=2
fi

echo "[+] Using $WORKERS parallel workers"
echo "[+] Streaming NDJSON output (flow + http only)"
echo "[+] Processing started..."
echo

# --- 4. Worker function: run Suricata + jq NDJSON filter ----------------------

process_pcap() {
    local pcap="$1"
    local name
    name="$(basename "$pcap")"

    local outdir="$TMP_DIR/$name"
    mkdir -p "$outdir"

    # Run Suricata in offline mode on this PCAP, writing eve.json into $outdir
    TZ=UTC suricata \
        -c "$CONFIG" \
        -r "$pcap" \
        -l "$outdir" \
        --runmode=single \
        > /dev/null 2>&1

    # If eve.json is missing, record failure and skip
    if [ ! -f "$outdir/eve.json" ]; then
        echo "$pcap" >> "$ERROR_LOG"
        return
    fi

    # Stream eve.json line-by-line, parse NDJSON, and select only flow/http events.
    # -R: read raw lines
    # fromjson?: try to parse each line as JSON, null on failure
    # select(...): keep only events we care about
    # -c: compact output → one JSON object per line (NDJSON)
    jq -R -c 'fromjson? | select(.event_type=="flow" or .event_type=="http")' < "$outdir/eve.json" 2>/dev/null || true
}

export -f process_pcap
export CONFIG TMP_DIR ERROR_LOG

# --- 5. Run in parallel and merge stdout into MASTER --------------------------

# --keep-order: preserve PCAP order in merged output
# --compress : reduce GNU parallel overhead (good for many jobs)
# --tmpdir   : ensures parallel's own temp files live under DEST_DIR, not /tmp
parallel --bar \
    -j "$WORKERS" \
    --keep-order \
    --compress \
    --tmpdir "$DEST_DIR" \
    process_pcap ::: "${FILES[@]}" >> "$MASTER"

# Ensure final newline so that the last JSON object is properly terminated
if [ -s "$MASTER" ]; then
    # If last byte is not a newline, append one
    if [ "$(tail -c1 "$MASTER" | wc -l)" -eq 0 ]; then
        echo >> "$MASTER"
    fi
fi

# --- 6. Validation: count JSON lines and flow events --------------------------

echo
echo "==============================================="
echo " Processing complete (experimental pipeline)   "
echo "==============================================="

if [ -s "$MASTER" ]; then
    EVENT_TOTAL="$(wc -l < "$MASTER" | tr -d ' ')"
    FLOW_EVENTS="$(grep -c '"event_type":"flow"' "$MASTER" 2>/dev/null || echo 0)"

    echo "Total JSON lines (events): $EVENT_TOTAL"
    echo "Flow events:               $FLOW_EVENTS"
    echo "Output file:               $MASTER"
else
    echo "WARNING: master_eve.json is empty: $MASTER" >&2
fi

if [ -f "$ERROR_LOG" ]; then
    echo
    echo "Some PCAPs failed; see: $ERROR_LOG"
fi

# --- 7. Cleanup ----------------------------------------------------------------

rm -rf "$TMP_DIR"
echo
echo "[+] Temporary workspace removed: $TMP_DIR"
echo "[+] Done (experimental NDJSON builder)."