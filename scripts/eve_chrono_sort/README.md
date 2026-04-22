# EVE chronological sort (40GB+ JSONL)

Memory-efficient pipeline: **index → external sort → replay** so merged / unsorted Suricata EVE logs can be processed with correct sliding-window state (e.g. 60s / 120s features).

## Layout

| File | Description |
|------|-------------|
| `timestamp_index.bin` | Phase 1: big-endian `(ts_ns:int64, line_offset:int64)` per input line (16 bytes each) |
| `sorted_timestamp_index.bin` | Phase 2: same records, globally sorted by `(ts_ns, offset)` (stable tie-break) |
| `<output>.sorted.jsonl` | Phase 3: JSONL in chronological order |
| `<output>.partitions.json` | Optional: worker ranges over **sorted index pairs** (works even if sorted JSONL is deleted) |

## Run

From `Model2_development/scripts` (so `eve_chrono_sort` is importable):

```bash
cd Model2_development/scripts

python -m eve_chrono_sort \
  --input /data/eve_merged.jsonl \
  --output /data/eve_sorted.jsonl \
  --workers 16 \
  --warmup-pairs 500000 \
  --partition-manifest /data/eve_sorted.jsonl.partitions.json \
  --delete-sorted-output
```

### CLI flags

| Flag | Meaning |
|------|---------|
| `--input` | Source JSONL |
| `--output` | Sorted JSONL (default: `<input>.sorted.jsonl`) |
| `--index` / `--sorted-index` | Override index paths (defaults next to input) |
| `--timestamp-field` | Comma order, e.g. `timestamp,flow.start` |
| `--chunk-lines` | External-sort chunk size (lines per temp chunk) |
| `--buffer-mb` | Per-handle buffer size |
| `--temp-dir` | Chunk directory (default: system temp) |
| `--skip-sort-if-monotonic` | If file-order keys are already non-decreasing, skip sort (copy) |
| `--workers` | Emit partition manifest for N workers |
| `--warmup-pairs` | Extra **index pairs** each worker reads before its emit range |
| `--warmup-seconds` | With `--workers`, rough `warmup_pairs` from Phase 1 scan rate |
| `--delete-sorted-output` | Delete sorted JSONL after success (manifest omits `sorted_jsonl`) |

## Parallel workers (Phase 4)

Partitions are **ranges of rows in the sorted index** (each row = one global time-ordered line). Each worker entry has:

- `read_pair_start` … `read_pair_end` — lines to **read** (includes warmup)
- `emit_pair_start` … `emit_pair_end` — lines that **belong** to that shard for output / ML

Replay in Python:

```python
from eve_chrono_sort.index_stream import iter_lines_from_sorted_index

for line in iter_lines_from_sorted_index(
    original_path, sorted_index_path, read_pair_start, read_pair_end
):
    ...
    # only emit records for emit_pair_* range (track pair index)
```

This preserves temporal order without keeping the materialized `sorted.jsonl` on disk.

## Performance notes

1. **Phase 1** is sequential read of the input — optimal for HDD/SSD.
2. **Phase 2** is sequential read of the index + temp chunk writes + merge; RAM ~ `chunk_lines × 16` bytes plus merge heap (`#chunks` items). Lower `--chunk-lines` if RAM is tight (more chunks, slower merge).
3. **Phase 3** follows **sorted file offsets into the original file** → seeks are pseudo-random in the original. This is the usual cost of time-sorting a single shard; throughput depends on OS cache and device. Re-reading the **sorted JSONL** later is sequential.
4. **Timestamps** are extracted with regex / light parsing, not `json.loads`. Malformed lines still get an index row; missing time uses a large sentinel so they sort near the end (logged as `missing_ts` in Phase 1).
5. **`flow.start` regex** may match other `"start"` fields; prefer `timestamp` first or use only `--timestamp-field timestamp` if needed.

## Disk budget

Roughly: `index + sorted_index + sorted_jsonl` ≈ `2 × 16 × lines + input_size` (plus temp chunks during Phase 2).

## Are you missing anything?

Confirm: **timezone semantics** for bare ISO timestamps (no zone) are assumed **UTC**. If your EVE uses local time without offset, adjust extraction or pre-normalize logs.
