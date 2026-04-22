#!/bin/bash
#
# SURICATA RECURSIVE PROCESSOR (V8.2 - Behavioral Safe/Fast)
# Keeps all behavioral fields required by the 31-feature pipeline.
#

set -euo pipefail

CONFIG="/etc/suricata/suricata_test.yaml"
PCAP_DIR="${PCAP_DIR:-$(dirname "$0")/../Datasets/AttackHeavy/CICIDS2018+Synthetic/pcaps}"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}  Suricata Recursive Processor (V8.2)    ${NC}"
echo -e "${GREEN}==========================================${NC}"

read -p "Enter destination folder path: " DEST_DIR
mkdir -p "$DEST_DIR"

SURICATA_OUTPUT="$DEST_DIR/master_eve.json"
SCHEMA_FINAL="$DEST_DIR/schema_31_ready.jsonl"

sudo -v

echo -e "${GREEN}[+] Starting Suricata Analysis...${NC}"
echo "    PCAP dir:   $PCAP_DIR"
echo "    Output dir: $DEST_DIR"

sudo suricata -c "$CONFIG" -r "$PCAP_DIR" --pcap-file-recursive -l "$DEST_DIR" -k none

echo -e "\n${GREEN}[+] Filtering for 31-Feature Behavioral Schema (event types only)...${NC}"

if [ ! -f "$SURICATA_OUTPUT" ]; then
  echo -e "${RED}[ERROR] Suricata failed to generate $SURICATA_OUTPUT.${NC}"
  echo "Check $DEST_DIR/suricata.log for details."
  exit 1
fi

echo "    Keeping event types: flow, anomaly, http, dns, ssh, tls"

# If pv is installed, show a progress bar; otherwise just run jq.
if command -v pv >/dev/null 2>&1; then
  EVE_SIZE=$(stat -c%s "$SURICATA_OUTPUT")
  pv -s "$EVE_SIZE" "$SURICATA_OUTPUT" | jq -c '
    select(
      .event_type=="flow" or
      .event_type=="anomaly" or
      .event_type=="http" or
      .event_type=="dns" or
      .event_type=="ssh" or
      .event_type=="tls"
    )
  ' > "$SCHEMA_FINAL"
else
  jq -c '
    select(
      .event_type=="flow" or
      .event_type=="anomaly" or
      .event_type=="http" or
      .event_type=="dns" or
      .event_type=="ssh" or
      .event_type=="tls"
    )
  ' "$SURICATA_OUTPUT" > "$SCHEMA_FINAL"
fi

echo -e "${GREEN}[SUCCESS] Processing Complete!${NC}"
echo "  Raw Suricata EVE:   $SURICATA_OUTPUT"
echo "  Filtered JSONL:     $SCHEMA_FINAL"
