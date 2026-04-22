"""
Shared streaming utilities for Suricata eve.json (JSONL) across training and inference.

Design:
- eve.json is line-delimited JSON (one object per line). We never load the full file.
- Chunking is standardized: configurable chunk_size; progress uses byte position vs file size.
- Progress reporting is time-based (default ~5s) so huge JSONL runs are not slowed by
  per-line or per-chunk UI updates (O(time), not O(events)).
- Single place for JSONL parsing, malformed-line handling, and progress callback logic.
"""

from __future__ import annotations

import json
import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, TextIO

# Legacy name kept for API compatibility; byte throttling for logging is not used (time-based only).
DEFAULT_PROGRESS_MIN_BYTES = 1024 * 1024
# Log at most every this many seconds (monotonic clock); avoids tqdm/per-refresh overhead.
DEFAULT_PROGRESS_LOG_INTERVAL_SEC = 5.0
# Large read buffer reduces syscall overhead on multi-GB JSONL (binary layer; still text mode).
DEFAULT_EVE_READ_BUFFER_BYTES = 8 * 1024 * 1024


def _fmt_duration_sec(sec: float) -> str:
    """Human-readable duration for progress lines (monotonic/wall seconds)."""
    if not math.isfinite(sec) or sec < 0:
        return "?"
    if sec >= 3600:
        h = int(sec // 3600)
        m = int((sec % 3600) // 60)
        return f"{h}h{m}m"
    if sec >= 60:
        return f"{int(sec // 60)}m{int(sec % 60)}s"
    return f"{sec:.0f}s"

try:
    import orjson as _orjson

    def _json_loads(line: str) -> Any:
        # orjson accepts str/bytes and is typically much faster for JSONL parsing.
        return _orjson.loads(line)

except ImportError:

    def _json_loads(line: str) -> Any:
        return json.loads(line)


class TimeBasedByteProgress:
    """
    Low-overhead progress: records byte position and line/event counts, prints a line
    at most every ``interval_sec`` (monotonic). Safe to call ``update`` every iteration;
    only emits when the interval has elapsed.

    Each line reports **recent** MiB/s (since the previous log) and **avg** MiB/s (since start).
    Cumulative avg often drops after a fast cached start even when recent throughput is stable.
    """

    __slots__ = (
        "_desc",
        "_file_size",
        "_interval",
        "_get_extra",
        "_out",
        "_start",
        "_last_log",
        "_last_bytes",
        "_last_lines",
        "_bytes_at_last_emit",
        "_closed",
    )

    def __init__(
        self,
        file_size: int,
        desc: str = "PROGRESS",
        interval_sec: float = DEFAULT_PROGRESS_LOG_INTERVAL_SEC,
        get_extra: Optional[Callable[[], Dict[str, Any]]] = None,
        file: TextIO = sys.stderr,
    ) -> None:
        self._desc = desc
        self._file_size = max(int(file_size), 1)
        self._interval = float(interval_sec)
        self._get_extra = get_extra
        self._out = file
        self._start = time.monotonic()
        self._last_log = self._start
        self._last_bytes = 0
        self._last_lines = 0
        self._bytes_at_last_emit = 0
        self._closed = False

    def update(self, bytes_read: int, lines_or_events: int) -> None:
        """Record progress; print only when ``interval_sec`` has elapsed since last log."""
        self._last_bytes = int(bytes_read)
        self._last_lines = int(lines_or_events)
        now = time.monotonic()
        if now - self._last_log < self._interval:
            return
        self._emit(now)
        self._last_log = now

    def _emit(self, now: float) -> None:
        b = min(self._last_bytes, self._file_size)
        pct = 100.0 * b / self._file_size
        elapsed = max(now - self._start, 1e-9)
        avg_mib_s = (b / elapsed) / (1024 * 1024)
        win_dt = max(now - self._last_log, 1e-9)
        win_bytes = max(0, b - self._bytes_at_last_emit)
        recent_mib_s = (win_bytes / win_dt) / (1024 * 1024)
        self._bytes_at_last_emit = b
        extra = ""
        if self._get_extra is not None:
            try:
                d = self._get_extra()
                if d:
                    parts = [f"{k}={v}" for k, v in d.items()]
                    extra = " | " + " ".join(parts)
            except Exception:
                pass
        eta_part = ""
        if 0.05 < pct < 99.99 and b > 0:
            rate = b / elapsed
            if rate > 0:
                rem = max(0, self._file_size - b)
                eta_part = f" | eta≈{_fmt_duration_sec(rem / rate)}"
        print(
            f"[{self._desc}] {pct:.2f}% | elapsed={_fmt_duration_sec(elapsed)} | "
            f"{recent_mib_s:.2f} MiB/s recent | {avg_mib_s:.2f} MiB/s avg | "
            f"lines={self._last_lines}{eta_part}{extra}",
            file=self._out,
            flush=True,
        )

    def close(self) -> None:
        """Emit a final progress line (if any bytes were read) and mark closed."""
        if self._closed:
            return
        self._closed = True
        if self._last_bytes > 0:
            self._emit(time.monotonic())


def iter_eve_chunks(
    filepath: Path,
    chunk_size: int,
    event_type_filter: Optional[str] = "flow",
    max_events: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Iterator[List[Dict[str, Any]]]:
    """
    Stream eve.json line-by-line and yield chunks of events. Memory-safe for multi-GB files.

    Args:
        filepath: Path to eve.json (JSONL).
        chunk_size: Max events per chunk (unified standard across training/inference).
        event_type_filter: If "flow", only include events with event_type == "flow";
            if None, include all parsed events.
        max_events: Optional cap on total events yielded (stops after that many).
        progress_callback: Optional callback(bytes_read, events_processed) after each line.

    Yields:
        Lists of event dicts (raw eve records). Chunk may be smaller than chunk_size
        at end of file or when max_events is hit.

    Malformed lines are skipped; encoding errors are replaced (errors="replace").
    """
    chunk: List[Dict[str, Any]] = []
    total_processed = 0
    bytes_read = 0

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace",
        buffering=DEFAULT_EVE_READ_BUFFER_BYTES,
    ) as f:
        for line in f:
            bytes_read += len(line) + 1
            if progress_callback is not None:
                progress_callback(bytes_read, total_processed)

            line = line.strip()
            if not line:
                continue

            try:
                event = _json_loads(line)
            except json.JSONDecodeError:
                continue
            except ValueError:
                # orjson raises ValueError for invalid JSON
                continue

            if not isinstance(event, dict):
                continue
            if event_type_filter is not None and event.get("event_type") != event_type_filter:
                continue

            chunk.append(event)
            total_processed += 1

            if max_events is not None and total_processed >= max_events:
                if chunk:
                    yield chunk
                return

            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []

    if chunk:
        yield chunk


def iter_eve_lines_with_progress(
    filepath: Path,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    min_callback_bytes: int = DEFAULT_PROGRESS_MIN_BYTES,
    progress_log_interval_sec: float = DEFAULT_PROGRESS_LOG_INTERVAL_SEC,
) -> Iterator[str]:
    """
    Stream raw JSONL lines (stripped) for Rust-side parsing. Same byte accounting pattern
    as iter_eve_chunks (len(line)+1 per line for progress).

    Yields every non-empty line; caller filters. Does not parse JSON in Python.

    When ``progress_callback`` is set, it is invoked on a **time** basis only (default
    every ``progress_log_interval_sec`` seconds), not every line — reduces Python
    call overhead on multi-GB files. A final callback runs in ``finally``.

    ``min_callback_bytes`` is ignored (kept for backward-compatible call signatures).
    """
    _ = min_callback_bytes
    bytes_read = 0
    lines_seen = 0
    last_log = time.monotonic()
    interval = float(progress_log_interval_sec)
    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace",
        buffering=DEFAULT_EVE_READ_BUFFER_BYTES,
    ) as f:
        try:
            for line in f:
                bytes_read += len(line) + 1
                if progress_callback is not None:
                    now = time.monotonic()
                    if now - last_log >= interval:
                        progress_callback(bytes_read, lines_seen)
                        last_log = now
                s = line.strip()
                if not s:
                    continue
                lines_seen += 1
                yield s
        finally:
            if progress_callback is not None and bytes_read > 0:
                progress_callback(bytes_read, lines_seen)


def iter_eve_tail(
    filepath: Path,
    chunk_size: int = 50,
    event_type_filter: Optional[str] = "flow",
    sleep_empty: float = 0.1,
    flush_interval_sec: float = 1.0,
) -> Iterator[List[Dict[str, Any]]]:
    """
    Tail eve.json in real time: seek to end, then yield chunks of new events as they arrive.
    Handles log rotation by reopening when file inode changes. Does not load the full file.

    Args:
        filepath: Path to eve.json (JSONL).
        chunk_size: Max events per chunk; smaller for lower latency.
        event_type_filter: If "flow", only include event_type == "flow"; if None, all.
        sleep_empty: Seconds to sleep when no new line is available.
        flush_interval_sec: If we have buffered events and no new data for this long, yield partial chunk.

    Yields:
        Lists of event dicts (new lines only). Use for real-time IDS/IPS pipelines.
    """
    path = Path(filepath).resolve()
    if not path.exists():
        return
    buffer: List[Dict[str, Any]] = []
    last_event_time = time.time()

    def open_at_end():
        f = open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
            buffering=DEFAULT_EVE_READ_BUFFER_BYTES,
        )
        f.seek(0, 2)  # seek to end
        return f

    f = open_at_end()
    try:
        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    try:
                        event = _json_loads(line)
                    except json.JSONDecodeError:
                        continue
                    except ValueError:
                        continue
                    if not isinstance(event, dict):
                        continue
                    if event_type_filter is not None and event.get("event_type") != event_type_filter:
                        continue
                    buffer.append(event)
                    last_event_time = time.time()
                if len(buffer) >= chunk_size:
                    yield buffer
                    buffer = []
            else:
                # EOF: sleep, then check for rotation
                time.sleep(sleep_empty)
                try:
                    stat_path = path.stat()
                    stat_fd = os.fstat(f.fileno())
                    if stat_path.st_ino != stat_fd.st_ino:
                        f.close()
                        f = open_at_end()
                except (OSError, FileNotFoundError):
                    f.close()
                    f = open_at_end()
                if buffer and (time.time() - last_event_time) >= flush_interval_sec:
                    yield buffer
                    buffer = []
    finally:
        f.close()


def create_eve_progress_bar(
    filepath: Path,
    desc: str = "eve.json",
    chunk_size: int = 50_000,
    use_tqdm: bool = True,
    min_interval_bytes: int = DEFAULT_PROGRESS_MIN_BYTES,
    get_postfix: Optional[Callable[[], Dict[str, Any]]] = None,
    log_interval_sec: float = DEFAULT_PROGRESS_LOG_INTERVAL_SEC,
) -> tuple[Optional[TimeBasedByteProgress], Optional[Callable[[int, int], None]]]:
    """
    Create a time-based progress logger and callback for streaming eve.json by file size.
    Use with ``iter_eve_chunks(..., progress_callback=callback)``.

    ``use_tqdm``: historical name — when True, enables progress logging (no tqdm).
    ``min_interval_bytes``: ignored (kept for backward-compatible call sites).
    ``get_postfix``: optional callable returning extra key=value fields for log lines.

    Returns:
        (progress, progress_callback). If ``use_tqdm`` is False, returns (None, None).
        Caller should ``progress.close()`` when the stream finishes.
    """
    _ = chunk_size
    _ = min_interval_bytes
    if not use_tqdm:
        return (None, None)

    file_size = filepath.stat().st_size
    prog = TimeBasedByteProgress(
        file_size=file_size,
        desc=desc,
        interval_sec=log_interval_sec,
        get_extra=get_postfix,
    )
    return (prog, prog.update)


def iter_eve_chunks_from_dir(
    dirpath: Path,
    chunk_size: int,
    event_type_filter: Optional[str] = "flow",
    max_events: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    glob_pattern: str = "**/*.json",
) -> Iterator[tuple[List[Dict[str, Any]], Path]]:
    """
    Stream eve.json from a directory: each file is streamed in chunks (no full load).
    Yields (chunk, filepath) so caller knows which file the chunk came from.

    Total bytes / progress across files is not aggregated; progress_callback receives
    (bytes_read_this_file, events_processed_this_file). For whole-dir progress, caller
    can aggregate or use a separate counter.
    """
    files = sorted(Path(dirpath).glob(glob_pattern))
    for fp in files:
        if not fp.is_file():
            continue
        try:
            for chunk in iter_eve_chunks(
                fp,
                chunk_size=chunk_size,
                event_type_filter=event_type_filter,
                max_events=max_events,
                progress_callback=progress_callback,
            ):
                yield chunk, fp
                if max_events is not None:
                    # iter_eve_chunks handles max_events internally; we don't track across files
                    pass
        except Exception:
            raise
