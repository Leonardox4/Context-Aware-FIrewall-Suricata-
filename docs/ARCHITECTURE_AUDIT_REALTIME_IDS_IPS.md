# Architecture Audit: Real-Time ML IDS/IPS

**Purpose:** Identify current pipeline architecture and missing components required for real-time IDS/IPS with blocking.  
**Status:** Audit complete; no implementation until approved.

---

## Current Architecture

**Data flow:**

```
Traffic → Suricata → eve.json (on disk)
                          ↓
              runtime_scoring.py --input <path>
                          ↓
              iter_eve_chunks (read full file in chunks)
                          ↓
              normalize_suricata_features → enforce_schema → score_chunk (IF + RF + RiskEngine)
                          ↓
              ContextEngine.update_and_escalate (optional)
                          ↓
              write_decisions() → decisions_log.jsonl
              write_context_events() → context_engine_log.jsonl
                          ↓
              (no firewall / blocking)
```

---

## Step 1 — Audit Answers

### 1. Is traffic ingestion **file-based or streaming**?

**File-based.**  
- `runtime_scoring.py` takes `--input <path>` to a CSV or eve.json file.  
- `iter_eve_chunks()` in `utils/streaming.py` opens the file and reads it in chunks (line-by-line, chunk_size events).  
- The entire input is consumed from disk; there is no continuous stream or tail of a live file.

### 2. Does the pipeline currently **consume events in real time**?

**No.**  
- The pipeline runs once over a given file and exits.  
- It does not wait for new data, tail a log, or connect to a socket/queue.  
- Latency is “after the file is written”; there is no real-time consumption.

### 3. Does the pipeline include any **packet blocking or firewall enforcement**?

**No.**  
- `inference/firewall_adapter_stub.py` defines `apply_decision(src_ip, decision, risk_score, reason)` which only prints to stderr (e.g. `[FIREWALL_STUB] BLOCK src=...`).  
- **The stub is never imported or called** from `runtime_scoring.py`.  
- No iptables, nftables, or other firewall/blocking API is invoked anywhere in the pipeline.

### 4. Are decisions currently **only written to logs**?

**Yes.**  
- Decisions and actions are written only to:  
  - `decisions_log.jsonl` (per-flow: timestamp, src_ip, dst_ip, dst_port, classification, risk_score, decision, action)  
  - `context_engine_log.jsonl` (escalation / DDoS / port-scan events).  
- No process reads these logs to apply blocks; no enforcement step exists.

### 5. Is there any integration with iptables, nftables, NFQUEUE, Suricata drop rules, or kernel firewall APIs?

**No.**  
- No references to iptables, nftables, NFQUEUE, or Suricata drop rules in the codebase (excluding `.venv`).  
- The firewall adapter is a stub only; no kernel or Suricata integration.

### 6. Is there any **real-time event ingestion mechanism** (socket, tail, message queue)?

**No.**  
- No socket listener, no `tail -f`-style reading of eve.json, no Kafka/Redis/other queue.  
- Ingestion is strictly: open file → read until EOF → exit.

### 7. Other missing components for production-style IDS/IPS

| Component | Status | Notes |
|-----------|--------|--------|
| **Real-time ingestion** | Missing | No tail/socket/queue; need continuous reading of eve.json or equivalent. |
| **Enforcement engine** | Stub only | Need real iptables/nftables (or NFQUEUE) integration; block/unblock API. |
| **Rule expiration / unblock logic** | Missing | No TTL or scheduler to remove blocks after e.g. 10–30 min. |
| **IP blocklist cache** | Missing | In-memory set of currently blocked IPs to avoid duplicate rules and to drive expiry. |
| **Rate-limited rule creation** | Missing | No limit on how many rules are added per second/minute. |
| **Async / event-loop** | Missing | Single-threaded, synchronous chunk processing. |
| **Queue backpressure** | N/A | No queue yet; would be needed if using a message queue. |
| **Max block rules / cap** | Missing | No upper bound on number of blocked IPs. |
| **Integration of ContextEngine → Enforcement** | Missing | BLOCK decisions are not passed to any enforcement layer. |

---

## Clear List of Missing Components

### For real-time IDS

1. **Real-time event ingestion**  
   - Continuously read new events (e.g. tail eve.json, or stream from socket/queue).  
   - Process events as they arrive instead of one batch over a static file.

2. **Long-running process**  
   - Replace “run once and exit” with a loop that runs until shutdown (signal or config).

3. **Optional: async/event-loop**  
   - To avoid blocking the read loop when doing ML or I/O; optional but useful at scale.

### For inline IPS blocking

4. **Enforcement engine (replace stub)**  
   - Module that applies BLOCK decisions (e.g. `iptables -A INPUT -s <ip> -j DROP` or nftables equivalent).  
   - Must avoid duplicate rules (idempotent block per IP).

5. **Blocklist state**  
   - In-memory set (or similar) of currently blocked IPs.  
   - Used to skip duplicate rule insertion and to know what to unblock.

6. **Rule expiration / unblock**  
   - TTL per block (e.g. 10–30 minutes) and a mechanism (scheduler or periodic task) to remove rules when TTL expires.

7. **Integration: ContextEngine → Enforcement**  
   - When ContextEngine (or final decision) outputs `action == BLOCK`, call the enforcement engine with the relevant IP (e.g. src_ip).  
   - Pipeline: Suricata → ML → ContextEngine → **Enforcement**.

8. **Safety limits**  
   - Rate-limit firewall rule insertion (max N new rules per minute).  
   - Maximum number of blocked IPs (cap size of blocklist).  
   - Optional: allowlist to never block certain IPs.

9. **Cleanup on shutdown**  
   - On graceful shutdown, optionally remove rules that were added by this process (or document that rules persist).

---

## Summary

| Question | Answer |
|----------|--------|
| Ingestion | File-based (path to eve.json/CSV). |
| Real time? | No; one-shot file read. |
| Blocking? | No; stub only, not called. |
| Decisions | Logged only (decisions_log.jsonl, context_engine_log.jsonl). |
| iptables/nftables/NFQUEUE/Suricata | None. |
| Real-time mechanism (tail/socket/queue) | None. |
| Missing for real-time IDS | Real-time ingestion, long-running loop. |
| Missing for IPS blocking | Enforcement engine, blocklist, rule expiry, ContextEngine→Enforcement, rate limit, max blocks. |

---

## Step 2 — Implemented

The following has been implemented:

1. **Real-time event streaming** — `--tail` mode in `runtime_scoring.py`; `iter_eve_tail()` in `utils/streaming.py` tails eve.json, handles rotation, yields micro-batches; process runs until Ctrl+C.
2. **Enforcement engine** — `inference/enforcement_engine.py`: backends stub / iptables / nftables; in-memory blocklist; rate limit (max blocks/min); max blocks cap; TTL expiry with `expire_blocks()`.
3. **Integration** — When ContextEngine (or RiskEngine) outputs action BLOCK, `apply_enforcement()` calls `enforcement_engine.add_block(src_ip)`. Wired in `stream_json_runtime`, `stream_csv_runtime`, and `stream_json_tail_runtime`.
4. **Safety** — Rate limit (`--max-blocks-per-min`), max blocks (`--max-blocks`), block TTL (`--block-ttl-sec`), periodic `expire_blocks()` in tail mode.

---

## Upgraded Architecture (after implementation)

```
                    ┌─────────────────────────────────────────────────────────────────┐
                    │                     REAL-TIME ML IDS/IPS                          │
                    └─────────────────────────────────────────────────────────────────┘

  Traffic ──► Suricata ──► eve.json (on disk or appended in real time)
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
              File mode (--input)              Tail mode (--tail)
              one-shot read                    iter_eve_tail(): seek end, read new lines
                    │                               │
                    └───────────────┬───────────────┘
                                    ▼
                    normalize_suricata_features → enforce_schema
                                    ▼
                    score_chunk (IF + RF + RiskEngine) → risk, decisions, actions
                                    ▼
                    ContextEngine.update_and_escalate (optional) → may escalate to HIGH/BLOCK
                                    ▼
                    write_decisions → decisions_log.jsonl
                    write_context_events → context_engine_log.jsonl
                                    ▼
                    apply_enforcement(actions, src_ips, enforcement_engine)
                                    │
                    For each action == BLOCK: enforcement_engine.add_block(src_ip)
                                    │
                    ┌───────────────┴───────────────┐
                    │  Backend: stub | iptables | nftables  │
                    │  Blocklist, rate limit, max blocks, TTL expiry  │
                    └───────────────────────────────────────┘
```

- **ML inference and ContextEngine** — Unchanged (same feature schema, same scoring and escalation logic).  
- **Real-time blocking** — In tail mode, new events are processed as they arrive; BLOCK decisions trigger firewall rules (when enforcement is enabled).  
- **Safety** — Rate limit, max blocks, and TTL prevent runaway rule growth; periodic expiry in tail mode.
