"""
Stable join key for labels ↔ flow features: Suricata ``flow_id`` when valid, else time-bucketed ``flow_key``.

Must stay aligned with ``rust/eve_extractor`` (same string rules for ``flow_id``).
"""

from __future__ import annotations

import json
import math
from typing import Any, Callable, Dict, Mapping, Optional

import numpy as np
import pandas as pd

IDENTITY_KEY_COL = "identity_key"

_INVALID_FLOW_ID_STRINGS = frozenset({"nan", "none", ""})


def coerce_parquet_utf8(value: Any) -> str:
    """
    Values for PyArrow ``pa.string()`` / Parquet UTF-8 columns.

    PyArrow raises ``ArrowTypeError: Expected bytes, got a 'float'`` if e.g. ``float('nan')``
    or numeric ``flow_id`` leaks into a string column buffer.
    """
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, float) and math.isnan(value):
        return ""
    if isinstance(value, np.floating):
        xf = float(value)
        if math.isnan(xf):
            return ""
    s = str(value).strip()
    sl = s.lower()
    if sl in ("nan", "none", "<na>", "nat"):
        return ""
    return s


def parse_flow_line_for_join_debug(line: str) -> Dict[str, str]:
    """Best-effort parse of one EVE JSONL line for unmatched join diagnostics (Python join paths)."""
    out: Dict[str, str] = {
        "ts": "",
        "src_ip": "",
        "dest_ip": "",
        "src_port": "",
        "dest_port": "",
    }
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return out
    if not isinstance(ev, dict):
        return out
    out["src_ip"] = str(ev.get("src_ip", "") or "")[:160]
    out["dest_ip"] = str(ev.get("dest_ip", "") or "")[:160]
    out["src_port"] = str(ev.get("src_port", "") or "")
    out["dest_port"] = str(ev.get("dest_port", "") or "")
    ts_val = None
    fo = ev.get("flow")
    if isinstance(fo, dict):
        ts_val = fo.get("start") or fo.get("end")
    if ts_val is None:
        ts_val = ev.get("timestamp")
    out["ts"] = str(ts_val)[:120] if ts_val is not None else ""
    return out


def identity_key_from_strings(flow_id: str, flow_key: str) -> str:
    """
    Unified join key from Rust-emitted strings: use ``flow_id`` when valid, else ``flow_key``.

    Treats None/empty/``nan``/``none`` (case-insensitive) as missing ``flow_id``.
    """
    fid = (flow_id or "").strip()
    if fid and fid.lower() not in ("nan", "none"):
        return fid
    return (flow_key or "").strip()


def eve_flow_id_string(ev: Mapping[str, Any]) -> Optional[str]:
    """Top-level EVE ``flow_id`` as join string, or ``None`` if missing/invalid."""
    if not isinstance(ev, Mapping):
        return None
    raw = ev.get("flow_id")
    if raw is None:
        return None
    if isinstance(raw, (bool, np.bool_)):
        return None
    if isinstance(raw, float) and math.isnan(raw):
        return None
    if isinstance(raw, (int, np.integer)):
        return str(int(raw))
    if isinstance(raw, float):
        return str(int(raw)) if raw.is_integer() else str(raw)
    s = str(raw).strip()
    if not s:
        return None
    sl = s.lower()
    if sl in _INVALID_FLOW_ID_STRINGS:
        return None
    return s


def identity_key_from_label_csv_row(
    row: Mapping[str, Any],
    flow_key_col: str = "flow_key",
    flow_id_col: str = "flow_id",
) -> str:
    """Join key for a ground-truth CSV row (same rules as ``add_identity_key_to_labels_df``)."""
    if IDENTITY_KEY_COL in row:
        pre = str(row.get(IDENTITY_KEY_COL) or "").strip()
        if pre and pre.lower() not in _INVALID_FLOW_ID_STRINGS:
            return pre
    fk = str(row.get(flow_key_col) or "").strip()
    if flow_id_col in row:
        sk = _flow_id_cell_to_join_str(row.get(flow_id_col))
        if sk is not None:
            return sk
    return fk


def identity_key_for_eve_flow(ev: Mapping[str, Any], flow_key: str) -> str:
    """Primary join key for one Python-parsed EVE row (same rule as ``identity_key_from_strings``)."""
    fid = eve_flow_id_string(ev)
    return identity_key_from_strings(fid or "", flow_key)


def assign_identity_key_with_flow_id_first(
    df: pd.DataFrame,
    flow_key_col: str = "flow_key",
    flow_id_col: str = "flow_id",
) -> tuple[pd.DataFrame, int, int]:
    """
    Set ``identity_key`` strictly: normalized valid ``flow_id`` when present, else ``flow_key``.

    Returns ``(df_out, n_rows_using_flow_id, n_rows_using_flow_key_fallback)``.
    """
    if flow_key_col not in df.columns:
        raise ValueError(f"labels DataFrame missing {flow_key_col!r}")
    out = df.copy()
    fk = out[flow_key_col].astype(str)
    n = len(out)
    if flow_id_col not in out.columns:
        out[IDENTITY_KEY_COL] = fk
        return out, 0, n

    parsed = [_flow_id_cell_to_join_str(v) for v in out[flow_id_col]]
    out[IDENTITY_KEY_COL] = [p if p is not None else f for p, f in zip(parsed, fk)]
    n_fid = sum(1 for p in parsed if p is not None)
    return out, n_fid, n - n_fid


def add_identity_key_to_labels_df(
    df: pd.DataFrame,
    flow_key_col: str = "flow_key",
    flow_id_col: str = "flow_id",
) -> pd.DataFrame:
    """
    Add ``identity_key``: valid string ``flow_id`` when present, else ``flow_key``.
    ``flow_key`` must already exist (see ``_prepare_labels_csv``).
    """
    out, _, _ = assign_identity_key_with_flow_id_first(df, flow_key_col, flow_id_col)
    return out


def _flow_id_cell_to_join_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (bool, np.bool_)):
        return None
    if isinstance(v, float) and math.isnan(v):
        return None
    if isinstance(v, (np.floating, float)):
        x = float(v)
        if math.isnan(x):
            return None
        return str(int(x)) if x.is_integer() else str(x)
    if isinstance(v, (int, np.integer)):
        return str(int(v))
    if pd.isna(v):
        return None
    s = str(v).strip()
    if not s:
        return None
    sl = s.lower()
    if sl in _INVALID_FLOW_ID_STRINGS:
        return None
    if sl.endswith(".0") and sl[:-2].replace("-", "").isdigit():
        return sl[:-2]
    return s


def log_identity_key_label_conflicts(
    labels_df: pd.DataFrame,
    log_fn: Callable[[str], None],
    label_col: str = "binary_label",
) -> int:
    """Return count of ``identity_key`` values with more than one distinct label."""
    if IDENTITY_KEY_COL not in labels_df.columns or label_col not in labels_df.columns:
        return 0
    dup = labels_df.groupby(IDENTITY_KEY_COL, sort=False)[label_col].nunique()
    conflicts = dup[dup > 1]
    n = int(conflicts.shape[0])
    log_fn(f"Conflicting identity_keys: {n}")
    return n


def build_label_maps_from_identity_key(
    labels_df: pd.DataFrame,
    use_subclass: bool,
) -> tuple[dict[str, int], dict[str, str]]:
    """``label_map`` / ``subclass_map`` keyed by ``identity_key`` (last row wins on duplicates)."""
    if IDENTITY_KEY_COL not in labels_df.columns:
        raise RuntimeError("labels DataFrame must contain 'identity_key' (run add_identity_key_to_labels_df).")
    label_map = labels_df.set_index(IDENTITY_KEY_COL)["binary_label"].astype(int).to_dict()
    subclass_map: dict[str, str] = {}
    if use_subclass:
        sub = labels_df.set_index(IDENTITY_KEY_COL)["attack_subclass"]
        subclass_map = {str(k): coerce_parquet_utf8(v) for k, v in sub.items()}
    return label_map, subclass_map
