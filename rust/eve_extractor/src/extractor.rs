//! Unified behavioral extraction — **keep in sync with Python**:
//! - Feature **count** and **column order**: `ingestion/unified_behavioral_schema.py` (`UNIFIED_BEHAVIORAL_FEATURE_NAMES` / `N_UNIFIED_BEHAVIORAL_FEATURES`).
//! - Join key time bucket: `ingestion/flow_identity.py` (`FLOW_KEY_BUCKET_SEC`); exported as `eve_extractor.FLOW_KEY_BUCKET_SEC`.
//!
//! Legacy sliding-window trackers in this file are unused on the `flow_tcp_behavioral_engine` hot path
//! but kept for optional incremental/validation presets.
#![allow(dead_code)]

use indexmap::IndexMap;
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

pub const N_FEATURES: usize = 45;
pub const W60: f64 = 60.0;
pub const W120: f64 = 120.0;
pub const W300: f64 = 300.0;
/// Reads `FLOW_KEY_BUCKET_SEC` once at first use (must match Python `ingestion.flow_identity`).
pub fn flow_key_bucket_sec() -> f64 {
    static BUCKET: OnceLock<f64> = OnceLock::new();
    *BUCKET.get_or_init(|| {
        std::env::var("FLOW_KEY_BUCKET_SEC")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|x| x.is_finite() && *x > 0.0)
            .unwrap_or(5.0)
    })
}
const GLOBAL_EVERY: u64 = 4096;
const MAX_SRC: usize = 100_000;
const MAX_DST: usize = 100_000;

/// JSON key `"event_type"` as it appears in Suricata EVE (quoted).
const EVE_EVENT_TYPE_KEY: &[u8] = b"\"event_type\"";

#[inline]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[inline]
fn skip_ascii_ws_bytes(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Returns `true` when we can skip `serde_json::from_str` and still match the outcome of
/// `process_line_detailed` for non-flow / invalid lines: `(false, None)`.
///
/// Conservative: unknown structure → `false` (must parse). Suricata places `"event_type"`
/// as a normal JSON string key; first occurrence on the line is used.
#[inline]
fn suricata_eve_skip_full_json_parse(bytes: &[u8]) -> bool {
    let Some(pos) = find_subslice(bytes, EVE_EVENT_TYPE_KEY) else {
        // No `event_type` key — not a normal EVE record we would turn into a flow row.
        return true;
    };
    let mut i = pos + EVE_EVENT_TYPE_KEY.len();
    i = skip_ascii_ws_bytes(bytes, i);
    if i >= bytes.len() || bytes[i] != b':' {
        return false;
    }
    i += 1;
    i = skip_ascii_ws_bytes(bytes, i);
    if i >= bytes.len() || bytes[i] != b'"' {
        // null, number, object, etc.
        return false;
    }
    i += 1;
    let val_start = i;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let val = &bytes[val_start..i];
                // We fully parse both `flow` and `tcp` lines because the
                // Rust engine performs a streaming join on `tcp(flow_id)` -> `flow`.
                return val != b"flow" && val != b"tcp";
            }
            b'\\' => return false,
            _ => i += 1,
        }
    }
    false
}

#[derive(Clone, Copy)]
pub struct FlowRec {
    pub ts: f64,
    pub src_port: i64,
    pub dst_port: i64,
    pub dst_ip_key: u64,
    pub svc: u8, // 0 http 1 dns 2 ssh 3 other
    pub failed: f64,
}

#[inline]
fn fnv1a64(s: &str) -> u64 {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;
    let mut h = FNV_OFFSET;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[inline]
fn service_class(dst_port: i64, proto_upper: &str) -> u8 {
    if dst_port == 53 {
        return 1;
    }
    if dst_port == 22 {
        return 2;
    }
    if proto_upper == "TCP" && matches!(dst_port, 80 | 443 | 8080 | 8000 | 8443) {
        return 0;
    }
    3
}

#[inline]
pub(crate) fn safe_int(v: &Value) -> i64 {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|x| x as i64)).unwrap_or(0),
        Value::String(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

#[inline]
fn safe_float(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Suricata often emits offsets as `+0530` / `-0330` without a colon. Chrono's strict
/// [`chrono::DateTime::parse_from_rfc3339`] expects `+05:30`. Returns `None` if the last five
/// characters are not exactly `[+-]HHMM` with ASCII digits.
fn colonize_offset_hhmm(s: &str) -> Option<String> {
    if s.len() < 5 {
        return None;
    }
    let tail = &s[s.len() - 5..];
    let b = tail.as_bytes();
    if b[0] != b'+' && b[0] != b'-' {
        return None;
    }
    if !tail[1..].bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let prefix = &s[..s.len() - 5];
    Some(format!("{}{}:{}", prefix, &tail[0..3], &tail[3..5]))
}

#[inline]
fn parse_rfc3339_epoch_seconds(s: &str) -> Option<f64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| {
        dt.timestamp() as f64 + dt.timestamp_subsec_nanos() as f64 * 1e-9
    })
}

/// Parse Suricata-style timestamp strings (strict RFC3339, optional `Z`, optional `+HHMM` offset).
fn parse_ts_string(s: &str) -> Option<f64> {
    if let Ok(x) = s.parse::<f64>() {
        return Some(x);
    }
    let normalized = if let Some(rest) = s.strip_suffix('Z') {
        format!("{}+00:00", rest)
    } else {
        s.to_string()
    };
    let try_one = |u: &str| {
        parse_rfc3339_epoch_seconds(u).or_else(|| colonize_offset_hhmm(u).and_then(|c| parse_rfc3339_epoch_seconds(&c)))
    };
    try_one(&normalized).or_else(|| {
        let alt = normalized.replace(' ', "T");
        try_one(&alt)
    })
}

pub(crate) fn ts_from_ev(ev: &Value) -> f64 {
    let flow = ev.get("flow").and_then(|x| x.as_object());
    let raw = flow
        .and_then(|f| f.get("start").or_else(|| f.get("end")))
        .or_else(|| ev.get("timestamp"));
    match raw {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => parse_ts_string(s).unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Suricata EVE top-level `flow_id` as join string (`None` if absent/invalid).
/// Keep aligned with `ingestion.identity_key.eve_flow_id_string` (Python).
fn flow_id_string_from_ev(ev: &Value) -> Option<String> {
    let id = ev.get("flow_id")?;
    if id.is_null() {
        return None;
    }
    let s = match id {
        Value::String(x) => {
            let t = x.trim();
            if t.is_empty() {
                return None;
            }
            t.to_string()
        }
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                u.to_string()
            } else if let Some(i) = n.as_i64() {
                i.to_string()
            } else {
                n.to_string()
            }
        }
        _ => return None,
    };
    let sl = s.to_lowercase();
    if sl == "nan" || sl == "none" {
        return None;
    }
    Some(s)
}

fn shannon_entropy_discrete_values(vals: &[i64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let mut m: HashMap<i64, u32> = HashMap::new();
    for &v in vals {
        *m.entry(v).or_insert(0) += 1;
    }
    let n = vals.len() as f64;
    let mut h = 0.0;
    for c in m.values() {
        let p = *c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// Same distribution as `shannon_entropy_discrete_values` over an expanded multiset (`n` = sample count).
fn shannon_entropy_from_port_counts(counts: &HashMap<i64, i32>, n: f64) -> f64 {
    if n <= 0.0 {
        return 0.0;
    }
    let mut h = 0.0;
    for &c in counts.values() {
        let p = c as f64 / n;
        if p > 0.0 {
            h -= p * p.log2();
        }
    }
    h
}

static INCREMENTAL_CTX_MISMATCH_LOGS: AtomicUsize = AtomicUsize::new(0);
static INCREMENTAL_ENT_MISMATCH_LOGS: AtomicUsize = AtomicUsize::new(0);
static INCREMENTAL_FALLBACK_LOGS: AtomicUsize = AtomicUsize::new(0);

fn log_incremental_ctx_mismatch(legacy: &[f64; 11], incr: &[f64; 11]) {
    let i = INCREMENTAL_CTX_MISMATCH_LOGS.fetch_add(1, Ordering::Relaxed);
    if i < 32 {
        eprintln!(
            "eve_extractor USE_INCREMENTAL_WINDOWS: get_context mismatch legacy={legacy:?} incr={incr:?}"
        );
    }
}

fn log_incremental_ent_mismatch(legacy: f64, incr: f64) {
    let i = INCREMENTAL_ENT_MISMATCH_LOGS.fetch_add(1, Ordering::Relaxed);
    if i < 32 {
        eprintln!(
            "eve_extractor USE_INCREMENTAL_WINDOWS: dst_port_entropy mismatch legacy={legacy} incr={incr}"
        );
    }
}

fn log_incremental_fallback(reason: &'static str) {
    let i = INCREMENTAL_FALLBACK_LOGS.fetch_add(1, Ordering::Relaxed);
    if i < 32 {
        eprintln!("eve_extractor: incremental output fallback ({reason})");
    }
}

#[inline]
fn ctx_float_match(a: f64, b: f64) -> bool {
    (a - b).abs() <= 1e-12
}

fn context_arrays_match(legacy: &[f64; 11], incr: &[f64; 11]) -> bool {
    legacy
        .iter()
        .zip(incr.iter())
        .all(|(a, b)| ctx_float_match(*a, *b))
}

#[inline]
fn context_array_finite(ctx: &[f64; 11]) -> bool {
    ctx.iter().all(|x| x.is_finite())
}

/// Legacy O(window) context (must match Python `get_context_60s_and_120s`).
fn legacy_context_from_deques(
    dq60_src: Option<&VecDeque<FlowRec>>,
    n60_src: usize,
    n60_dst: usize,
    n120_src: usize,
) -> [f64; 11] {
    let mut out = [0f64; 11];
    out[0] = n60_src as f64;
    out[1] = n60_dst as f64;
    out[8] = n120_src as f64;
    if let Some(dq) = dq60_src {
        if !dq.is_empty() {
            use std::collections::HashSet;
            let mut sp = HashSet::new();
            let mut dp = HashSet::new();
            let mut di = HashSet::new();
            let mut fh = 0u32;
            let mut fd = 0u32;
            let mut fs = 0u32;
            let mut fo = 0u32;
            let mut failed_n = 0u32;
            for r in dq.iter() {
                sp.insert(r.src_port);
                dp.insert(r.dst_port);
                di.insert(r.dst_ip_key);
                match r.svc {
                    0 => fh += 1,
                    1 => fd += 1,
                    2 => fs += 1,
                    _ => fo += 1,
                }
                if r.failed >= 0.5 {
                    failed_n += 1;
                }
            }
            out[2] = sp.len() as f64;
            out[3] = dp.len() as f64;
            out[4] = fh as f64;
            out[5] = fd as f64;
            out[6] = fs as f64;
            out[7] = fo as f64;
            out[9] = failed_n as f64 / n60_src as f64;
            out[10] = di.len() as f64;
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn process_rss_kb() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if line.starts_with("VmRSS:") {
            let mut it = line.split_whitespace();
            it.next();
            return it.next()?.parse().ok();
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn process_rss_kb() -> Option<u64> {
    None
}

fn append_benchmark_line(line: &str) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/benchmarks/optimization_results.txt");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

#[inline]
fn dec_count_i64(m: &mut HashMap<i64, i32>, k: i64) {
    if let Some(c) = m.get_mut(&k) {
        *c -= 1;
        if *c <= 0 {
            m.remove(&k);
        }
    }
}

#[inline]
fn dec_count_u64(m: &mut HashMap<u64, i32>, k: u64) {
    if let Some(c) = m.get_mut(&k) {
        *c -= 1;
        if *c <= 0 {
            m.remove(&k);
        }
    }
}

/// Sliding-window multiset for 60s **src** deque (distinct counts + dst-port histogram for entropy).
#[derive(Default, Clone)]
struct Src60Agg {
    n: usize,
    failed_n: u32,
    svc: [u32; 4],
    src_port_counts: HashMap<i64, i32>,
    dst_port_counts: HashMap<i64, i32>,
    dst_ipkey_counts: HashMap<u64, i32>,
}

impl Src60Agg {
    fn push(&mut self, r: &FlowRec) {
        self.n += 1;
        if r.failed >= 0.5 {
            self.failed_n += 1;
        }
        match r.svc {
            0 => self.svc[0] += 1,
            1 => self.svc[1] += 1,
            2 => self.svc[2] += 1,
            _ => self.svc[3] += 1,
        }
        *self.src_port_counts.entry(r.src_port).or_insert(0) += 1;
        *self.dst_port_counts.entry(r.dst_port).or_insert(0) += 1;
        *self.dst_ipkey_counts.entry(r.dst_ip_key).or_insert(0) += 1;
    }

    fn pop(&mut self, r: &FlowRec) {
        if self.n == 0 {
            return;
        }
        self.n -= 1;
        if r.failed >= 0.5 {
            self.failed_n = self.failed_n.saturating_sub(1);
        }
        match r.svc {
            0 => self.svc[0] = self.svc[0].saturating_sub(1),
            1 => self.svc[1] = self.svc[1].saturating_sub(1),
            2 => self.svc[2] = self.svc[2].saturating_sub(1),
            _ => self.svc[3] = self.svc[3].saturating_sub(1),
        }
        dec_count_i64(&mut self.src_port_counts, r.src_port);
        dec_count_i64(&mut self.dst_port_counts, r.dst_port);
        dec_count_u64(&mut self.dst_ipkey_counts, r.dst_ip_key);
    }
}

fn context_from_agg(
    agg: Option<&Src60Agg>,
    n60_src: usize,
    n60_dst: usize,
    n120_src: usize,
) -> [f64; 11] {
    let mut out = [0f64; 11];
    out[0] = n60_src as f64;
    out[1] = n60_dst as f64;
    out[8] = n120_src as f64;
    if n60_src == 0 {
        return out;
    }
    if let Some(a) = agg {
        if a.n == n60_src {
            out[2] = a.src_port_counts.len() as f64;
            out[3] = a.dst_port_counts.len() as f64;
            out[4] = a.svc[0] as f64;
            out[5] = a.svc[1] as f64;
            out[6] = a.svc[2] as f64;
            out[7] = a.svc[3] as f64;
            out[9] = a.failed_n as f64 / n60_src as f64;
            out[10] = a.dst_ipkey_counts.len() as f64;
        }
    }
    out
}

fn np_var_population(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let mut s = 0.0;
    for x in xs {
        let d = x - mean;
        s += d * d;
    }
    s / n
}

#[inline]
fn welford_add_delta(n: i64, mean: f64, m2: f64, x: f64) -> (i64, f64, f64) {
    let n_new = n + 1;
    let delta = x - mean;
    let mean_new = mean + delta / n_new as f64;
    let delta2 = x - mean_new;
    let m2_new = m2 + delta * delta2;
    (n_new, mean_new, m2_new)
}

#[inline]
fn welford_remove_delta(n: i64, mean: f64, m2: f64, x: f64) -> (i64, f64, f64) {
    if n <= 1 {
        return (0, 0.0, 0.0);
    }
    let n_new = n - 1;
    let mean_new = (n as f64 * mean - x) / n_new as f64;
    let m2_new = m2 - (x - mean) * (x - mean_new);
    (n_new, mean_new, m2_new.max(0.0))
}

fn tcp_parse_hex(s: &str) -> u32 {
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        return 0;
    }
    u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or_else(|_| {
        u32::from_str_radix(&s, 16).unwrap_or(0)
    })
}

fn tcp_mask_from_ev(ev: &Value) -> u32 {
    let tcp = match ev.get("tcp").and_then(|t| t.as_object()) {
        Some(t) => t,
        None => return 0,
    };
    let mut mask = 0u32;
    if tcp.get("syn").and_then(|v| v.as_bool()) == Some(true) {
        mask |= 0x02;
    }
    if tcp.get("ack").and_then(|v| v.as_bool()) == Some(true) {
        mask |= 0x10;
    }
    if tcp.get("fin").and_then(|v| v.as_bool()) == Some(true) {
        mask |= 0x01;
    }
    if tcp.get("rst").and_then(|v| v.as_bool()) == Some(true) {
        mask |= 0x04;
    }
    if tcp.get("psh").and_then(|v| v.as_bool()) == Some(true) {
        mask |= 0x08;
    }
    if tcp.get("urg").and_then(|v| v.as_bool()) == Some(true) {
        mask |= 0x20;
    }
    if mask != 0 {
        return mask;
    }
    let m_ts = tcp
        .get("tcp_flags_ts")
        .map(|v| match v {
            Value::String(s) => tcp_parse_hex(s),
            Value::Number(n) => n.as_u64().unwrap_or(0) as u32,
            _ => 0,
        })
        .unwrap_or(0);
    let m_tc = tcp
        .get("tcp_flags_tc")
        .map(|v| match v {
            Value::String(s) => tcp_parse_hex(s),
            Value::Number(n) => n.as_u64().unwrap_or(0) as u32,
            _ => 0,
        })
        .unwrap_or(0);
    if m_ts != 0 || m_tc != 0 {
        return m_ts | m_tc;
    }
    if let Some(v) = tcp.get("tcp_flags") {
        let s = match v {
            Value::String(s) => s.as_str(),
            _ => "",
        };
        return tcp_parse_hex(s);
    }
    0
}

pub struct BehavioralUnified {
    src_60: HashMap<String, VecDeque<FlowRec>>,
    src_120: HashMap<String, VecDeque<FlowRec>>,
    src_fifo: IndexMap<String, ()>,
    dst_60: HashMap<String, VecDeque<FlowRec>>,
    dst_fifo: IndexMap<String, ()>,
    add_calls: u64,
    /// Maintained when `config::maintain_src60_agg()` (must mirror `src_60` 60s window).
    src_60_agg: HashMap<String, Src60Agg>,
}

impl BehavioralUnified {
    pub fn new() -> Self {
        Self {
            src_60: HashMap::new(),
            src_120: HashMap::new(),
            src_fifo: IndexMap::new(),
            dst_60: HashMap::new(),
            dst_fifo: IndexMap::new(),
            add_calls: 0,
            src_60_agg: HashMap::new(),
        }
    }

    fn src_60_agg_push(&mut self, src_ip: &str, rec: &FlowRec) {
        if !crate::config::maintain_src60_agg() {
            return;
        }
        self.src_60_agg
            .entry(src_ip.to_string())
            .or_default()
            .push(rec);
    }

    fn src_60_agg_pop(&mut self, src_ip: &str, rec: &FlowRec) {
        if !crate::config::maintain_src60_agg() {
            return;
        }
        if let Some(agg) = self.src_60_agg.get_mut(src_ip) {
            agg.pop(rec);
            if agg.n == 0 {
                self.src_60_agg.remove(src_ip);
            }
        }
    }

    fn cleanup_global(&mut self, now: f64) {
        let c60 = now - W60;
        let c120 = now - W120;
        for key in self.src_60.keys().cloned().collect::<Vec<_>>() {
            let track_agg = crate::config::maintain_src60_agg();
            let popped: Vec<FlowRec> = match self.src_60.get_mut(&key) {
                None => continue,
                Some(dq) => {
                    let mut v = Vec::new();
                    while let Some(front) = dq.front() {
                        if front.ts < c60 {
                            v.push(dq.pop_front().unwrap());
                        } else {
                            break;
                        }
                    }
                    v
                }
            };
            if track_agg {
                for r in &popped {
                    self.src_60_agg_pop(&key, r);
                }
            }
            if self.src_60.get(&key).is_some_and(|dq| dq.is_empty()) {
                self.src_60.remove(&key);
                self.src_fifo.shift_remove(&key);
                if track_agg {
                    self.src_60_agg.remove(&key);
                }
            }
        }
        for key in self.src_120.keys().cloned().collect::<Vec<_>>() {
            if let Some(dq) = self.src_120.get_mut(&key) {
                while let Some(front) = dq.front() {
                    if front.ts < c120 {
                        dq.pop_front();
                    } else {
                        break;
                    }
                }
                if dq.is_empty() {
                    self.src_120.remove(&key);
                }
            }
        }
        for key in self.dst_60.keys().cloned().collect::<Vec<_>>() {
            if let Some(dq) = self.dst_60.get_mut(&key) {
                while let Some(front) = dq.front() {
                    if front.ts < c60 {
                        dq.pop_front();
                    } else {
                        break;
                    }
                }
                if dq.is_empty() {
                    self.dst_60.remove(&key);
                    self.dst_fifo.shift_remove(&key);
                }
            }
        }
    }

    fn prune_src(&mut self, src_ip: &str, now: f64) {
        let c60 = now - W60;
        let c120 = now - W120;
        let track_agg = crate::config::maintain_src60_agg();
        let popped: Vec<FlowRec> = match self.src_60.get_mut(src_ip) {
            None => Vec::new(),
            Some(dq) => {
                let mut v = Vec::new();
                while let Some(front) = dq.front() {
                    if front.ts < c60 {
                        v.push(dq.pop_front().unwrap());
                    } else {
                        break;
                    }
                }
                v
            }
        };
        if track_agg {
            for r in &popped {
                self.src_60_agg_pop(src_ip, r);
            }
        }
        if self.src_60.get(src_ip).is_some_and(|dq| dq.is_empty()) {
            self.src_60.remove(src_ip);
            self.src_fifo.shift_remove(src_ip);
            if track_agg {
                self.src_60_agg.remove(src_ip);
            }
        }
        if let Some(dq) = self.src_120.get_mut(src_ip) {
            while let Some(front) = dq.front() {
                if front.ts < c120 {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            if dq.is_empty() {
                self.src_120.remove(src_ip);
            }
        }
    }

    fn prune_dst(&mut self, dst_ip: &str, now: f64) {
        let c60 = now - W60;
        if let Some(dq) = self.dst_60.get_mut(dst_ip) {
            while let Some(front) = dq.front() {
                if front.ts < c60 {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            if dq.is_empty() {
                self.dst_60.remove(dst_ip);
                self.dst_fifo.shift_remove(dst_ip);
            }
        }
    }

    fn ensure_src(&mut self, src_ip: &str) -> (&mut VecDeque<FlowRec>, &mut VecDeque<FlowRec>) {
        if !self.src_60.contains_key(src_ip) {
            while self.src_60.len() >= MAX_SRC && !self.src_fifo.is_empty() {
                let evict = self.src_fifo.keys().next().cloned().unwrap();
                self.src_fifo.shift_remove(&evict);
                self.src_60.remove(&evict);
                self.src_120.remove(&evict);
                if crate::config::maintain_src60_agg() {
                    self.src_60_agg.remove(&evict);
                }
            }
            self.src_60.insert(src_ip.to_string(), VecDeque::new());
            self.src_120.insert(src_ip.to_string(), VecDeque::new());
            self.src_fifo.insert(src_ip.to_string(), ());
        }
        // safe: both exist
        let dq60 = self.src_60.get_mut(src_ip).unwrap();
        let dq120 = self.src_120.get_mut(src_ip).unwrap();
        (dq60, dq120)
    }

    fn ensure_dst(&mut self, dst_ip: &str) -> &mut VecDeque<FlowRec> {
        if !self.dst_60.contains_key(dst_ip) {
            while self.dst_60.len() >= MAX_DST && !self.dst_fifo.is_empty() {
                let evict = self.dst_fifo.keys().next().cloned().unwrap();
                self.dst_fifo.shift_remove(&evict);
                self.dst_60.remove(&evict);
            }
            self.dst_60.insert(dst_ip.to_string(), VecDeque::new());
            self.dst_fifo.insert(dst_ip.to_string(), ());
        }
        self.dst_60.get_mut(dst_ip).unwrap()
    }

    /// Context features matching Python `get_context_60s_and_120s` (11 floats used downstream).
    pub fn get_context(&mut self, src_ip: &str, dst_ip: &str, now: f64) -> [f64; 11] {
        self.prune_src(src_ip, now);
        self.prune_dst(dst_ip, now);
        let dq60_src = self.src_60.get(src_ip);
        let dq120_src = self.src_120.get(src_ip);
        let dq60_dst = self.dst_60.get(dst_ip);
        let n60_src = dq60_src.map(|d| d.len()).unwrap_or(0);
        let n120_src = dq120_src.map(|d| d.len()).unwrap_or(0);
        let n60_dst = dq60_dst.map(|d| d.len()).unwrap_or(0);

        let legacy = || legacy_context_from_deques(dq60_src, n60_src, n60_dst, n120_src);

        if crate::config::USE_INCREMENTAL_OUTPUT {
            let ctx = context_from_agg(
                self.src_60_agg.get(src_ip),
                n60_src,
                n60_dst,
                n120_src,
            );
            let agg_ok = n60_src == 0
                || self
                    .src_60_agg
                    .get(src_ip)
                    .map(|a| a.n == n60_src)
                    .unwrap_or(false);
            if !agg_ok || !context_array_finite(&ctx) {
                log_incremental_fallback(if !agg_ok {
                    "context_agg_desync"
                } else {
                    "context_non_finite"
                });
                return legacy();
            }
            if crate::config::USE_INCREMENTAL_WINDOWS {
                let leg = legacy();
                if !context_arrays_match(&leg, &ctx) {
                    log_incremental_ctx_mismatch(&leg, &ctx);
                    if crate::config::INCREMENTAL_STRICT {
                        panic!("eve_extractor INCREMENTAL_STRICT: get_context mismatch");
                    }
                    return leg;
                }
            }
            return ctx;
        }

        let out = legacy();
        if crate::config::USE_INCREMENTAL_WINDOWS {
            let incr = context_from_agg(
                self.src_60_agg.get(src_ip),
                n60_src,
                n60_dst,
                n120_src,
            );
            if !context_arrays_match(&out, &incr) {
                log_incremental_ctx_mismatch(&out, &incr);
                if crate::config::INCREMENTAL_STRICT {
                    panic!("eve_extractor INCREMENTAL_STRICT: get_context mismatch");
                }
            }
        }
        out
    }

    #[inline]
    pub fn src_60_len(&self, src_ip: &str) -> usize {
        self.src_60.get(src_ip).map(|d| d.len()).unwrap_or(0)
    }

    pub fn dst_ports_for_entropy(&self, src_ip: &str) -> Vec<i64> {
        self.src_60
            .get(src_ip)
            .map(|dq| dq.iter().map(|r| r.dst_port).collect())
            .unwrap_or_default()
    }

    pub fn add(
        &mut self,
        ts: f64,
        src_ip: &str,
        dst_ip: &str,
        src_port: i64,
        dst_port: i64,
        _bytes_total: i64,
        _pkts_total: i64,
        svc: u8,
        failed: f64,
        dst_key: u64,
    ) {
        self.add_calls += 1;
        if self.add_calls % GLOBAL_EVERY == 0 {
            self.cleanup_global(ts);
        }
        self.prune_src(src_ip, ts);
        self.prune_dst(dst_ip, ts);
        let rec = FlowRec {
            ts,
            src_port,
            dst_port,
            dst_ip_key: dst_key,
            svc,
            failed,
        };
        {
            let (dq60, dq120) = self.ensure_src(src_ip);
            dq60.push_back(rec);
            dq120.push_back(rec);
        }
        self.src_60_agg_push(src_ip, &rec);
        self.ensure_dst(dst_ip).push_back(rec);
    }
}

/// Dst-port entropy over the current (already-pruned) 60s src window — respects OUTPUT / WINDOWS flags.
fn behavioral_dst_port_entropy(b: &BehavioralUnified, src_ip: &str) -> f64 {
    if !crate::config::USE_INCREMENTAL_OUTPUT {
        let dst_ports = b.dst_ports_for_entropy(src_ip);
        let leg = shannon_entropy_discrete_values(&dst_ports);
        if crate::config::USE_INCREMENTAL_WINDOWS {
            let n = dst_ports.len();
            if n > 0 {
                if let Some(agg) = b.src_60_agg.get(src_ip) {
                    if agg.n == n {
                        let inc =
                            shannon_entropy_from_port_counts(&agg.dst_port_counts, n as f64);
                        if !ctx_float_match(inc, leg) {
                            log_incremental_ent_mismatch(leg, inc);
                            if crate::config::INCREMENTAL_STRICT {
                                panic!(
                                    "eve_extractor INCREMENTAL_STRICT: dst_port_entropy mismatch"
                                );
                            }
                        }
                    }
                }
            }
        }
        return leg;
    }

    if crate::config::USE_INCREMENTAL_WINDOWS {
        let dst_ports = b.dst_ports_for_entropy(src_ip);
        let leg = shannon_entropy_discrete_values(&dst_ports);
        let n = dst_ports.len();
        if n == 0 {
            return 0.0;
        }
        let inc = b
            .src_60_agg
            .get(src_ip)
            .filter(|a| a.n == n)
            .map(|a| shannon_entropy_from_port_counts(&a.dst_port_counts, n as f64))
            .unwrap_or(leg);
        if !ctx_float_match(leg, inc) {
            log_incremental_ent_mismatch(leg, inc);
            if crate::config::INCREMENTAL_STRICT {
                panic!("eve_extractor INCREMENTAL_STRICT: dst_port_entropy mismatch");
            }
            return leg;
        }
        return if inc.is_finite() { inc } else { leg };
    }

    let n = b.src_60_len(src_ip);
    if n == 0 {
        return 0.0;
    }
    match b.src_60_agg.get(src_ip) {
        Some(agg) if agg.n == n => {
            let e = shannon_entropy_from_port_counts(&agg.dst_port_counts, n as f64);
            if e.is_finite() {
                e
            } else {
                log_incremental_fallback("entropy_non_finite");
                let v = b.dst_ports_for_entropy(src_ip);
                shannon_entropy_discrete_values(&v)
            }
        }
        _ => {
            log_incremental_fallback("entropy_agg_desync");
            let v = b.dst_ports_for_entropy(src_ip);
            shannon_entropy_discrete_values(&v)
        }
    }
}

const FLAG_BITS: [u32; 6] = [0x02, 0x10, 0x01, 0x04, 0x08, 0x20];

pub struct TcpFlagTracker {
    src: HashMap<String, VecDeque<(f64, u32)>>,
    counts: HashMap<String, [i32; 6]>,
    total: HashMap<String, i32>,
    fifo: IndexMap<String, ()>,
    op_count: u64,
}

impl TcpFlagTracker {
    pub fn new() -> Self {
        Self {
            src: HashMap::new(),
            counts: HashMap::new(),
            total: HashMap::new(),
            fifo: IndexMap::new(),
            op_count: 0,
        }
    }

    fn cleanup_global(&mut self, now: f64) {
        let c = now - W60;
        for k in self.src.keys().cloned().collect::<Vec<_>>() {
            if let Some(dq) = self.src.get_mut(&k) {
                while let Some((ts, mask)) = dq.front().copied() {
                    if ts < c {
                        dq.pop_front();
                        let ct = self.counts.get_mut(&k).unwrap();
                        let tot = self.total.get_mut(&k).unwrap();
                        for i in 0..6 {
                            if mask & FLAG_BITS[i] != 0 {
                                ct[i] -= 1;
                                *tot -= 1;
                            }
                        }
                    } else {
                        break;
                    }
                }
                if dq.is_empty() {
                    self.src.remove(&k);
                    self.counts.remove(&k);
                    self.total.remove(&k);
                    self.fifo.shift_remove(&k);
                }
            }
        }
    }

    fn prune_src(&mut self, src_ip: &str, now: f64) {
        let c = now - W60;
        if let Some(dq) = self.src.get_mut(src_ip) {
            while let Some((ts, mask)) = dq.front().copied() {
                if ts < c {
                    dq.pop_front();
                    if let Some(ct) = self.counts.get_mut(src_ip) {
                        let tot = self.total.get_mut(src_ip).unwrap();
                        for i in 0..6 {
                            if mask & FLAG_BITS[i] != 0 {
                                ct[i] -= 1;
                                *tot -= 1;
                            }
                        }
                    }
                } else {
                    break;
                }
            }
            if dq.is_empty() {
                self.src.remove(src_ip);
                self.counts.remove(src_ip);
                self.total.remove(src_ip);
                self.fifo.shift_remove(src_ip);
            }
        }
    }

    fn maybe_global(&mut self, now: f64) {
        self.op_count += 1;
        if self.op_count % GLOBAL_EVERY == 0 {
            self.cleanup_global(now);
        }
    }

    fn ensure_src(&mut self, src_ip: &str) {
        if self.src.contains_key(src_ip) {
            return;
        }
        while self.src.len() >= MAX_SRC && !self.fifo.is_empty() {
            let evict = self.fifo.keys().next().cloned().unwrap();
            self.fifo.shift_remove(&evict);
            self.src.remove(&evict);
            self.counts.remove(&evict);
            self.total.remove(&evict);
        }
        self.src.insert(src_ip.to_string(), VecDeque::new());
        self.counts.insert(src_ip.to_string(), [0; 6]);
        self.total.insert(src_ip.to_string(), 0);
        self.fifo.insert(src_ip.to_string(), ());
    }

    pub fn entropy(&mut self, src_ip: &str, now: f64) -> f64 {
        self.maybe_global(now);
        self.prune_src(src_ip, now);
        let tot = *self.total.get(src_ip).unwrap_or(&0);
        if tot <= 0 {
            return 0.0;
        }
        let ct = self.counts.get(src_ip).unwrap_or(&[0; 6]);
        let mut ent = 0.0;
        for i in 0..6 {
            let c = ct[i];
            if c <= 0 {
                continue;
            }
            let p = c as f64 / tot as f64;
            ent -= p * p.log2();
        }
        ent
    }

    pub fn add_flags(&mut self, src_ip: &str, ts: f64, mask: u32) {
        if mask == 0 {
            return;
        }
        self.maybe_global(ts);
        self.prune_src(src_ip, ts);
        self.ensure_src(src_ip);
        self.src.get_mut(src_ip).unwrap().push_back((ts, mask));
        let ct = self.counts.get_mut(src_ip).unwrap();
        let tot = self.total.get_mut(src_ip).unwrap();
        for i in 0..6 {
            if mask & FLAG_BITS[i] != 0 {
                ct[i] += 1;
                *tot += 1;
            }
        }
    }
}

// --- 300s dst_port variance (per src_ip) ---
pub struct DstPortWindow300 {
    src: HashMap<String, VecDeque<(f64, i64)>>,
    fifo: IndexMap<String, ()>,
    op: u64,
}

impl DstPortWindow300 {
    pub fn new() -> Self {
        Self {
            src: HashMap::new(),
            fifo: IndexMap::new(),
            op: 0,
        }
    }

    fn cleanup_global(&mut self, now: f64) {
        let c = now - W300;
        for k in self.src.keys().cloned().collect::<Vec<_>>() {
            if let Some(dq) = self.src.get_mut(&k) {
                while let Some(front) = dq.front() {
                    if front.0 < c {
                        dq.pop_front();
                    } else {
                        break;
                    }
                }
                if dq.is_empty() {
                    self.src.remove(&k);
                    self.fifo.shift_remove(&k);
                }
            }
        }
    }

    fn maybe_global(&mut self, now: f64) {
        self.op += 1;
        if self.op % GLOBAL_EVERY == 0 {
            self.cleanup_global(now);
        }
    }

    fn prune_src(&mut self, src_ip: &str, now: f64) {
        let c = now - W300;
        if let Some(dq) = self.src.get_mut(src_ip) {
            while let Some(front) = dq.front() {
                if front.0 < c {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            if dq.is_empty() {
                self.src.remove(src_ip);
                self.fifo.shift_remove(src_ip);
            }
        }
    }

    pub fn variance_ports(&mut self, src_ip: &str, now: f64) -> f64 {
        self.maybe_global(now);
        self.prune_src(src_ip, now);
        let dq = match self.src.get(src_ip) {
            Some(d) => d,
            None => return 0.0,
        };
        if dq.len() < 2 {
            return 0.0;
        }
        let ports: Vec<f64> = dq.iter().map(|(_, p)| *p as f64).collect();
        np_var_population(&ports)
    }

    pub fn add(&mut self, src_ip: &str, ts: f64, dst_port: i64) {
        self.maybe_global(ts);
        self.prune_src(src_ip, ts);
        if !self.src.contains_key(src_ip) {
            while self.src.len() >= MAX_SRC && !self.fifo.is_empty() {
                let evict = self.fifo.keys().next().cloned().unwrap();
                self.fifo.shift_remove(&evict);
                self.src.remove(&evict);
            }
            self.src.insert(src_ip.to_string(), VecDeque::new());
            self.fifo.insert(src_ip.to_string(), ());
        }
        self.src.get_mut(src_ip).unwrap().push_back((ts, dst_port));
    }
}

// --- 300s flow inter-arrival variance (per src_ip, Welford on deltas) ---
pub struct FlowInterarrivalVar300 {
    ts: HashMap<String, VecDeque<f64>>,
    deltas: HashMap<String, VecDeque<f64>>,
    wn: HashMap<String, i64>,
    wmean: HashMap<String, f64>,
    wm2: HashMap<String, f64>,
    fifo: IndexMap<String, ()>,
    op: u64,
}

impl FlowInterarrivalVar300 {
    pub fn new() -> Self {
        Self {
            ts: HashMap::new(),
            deltas: HashMap::new(),
            wn: HashMap::new(),
            wmean: HashMap::new(),
            wm2: HashMap::new(),
            fifo: IndexMap::new(),
            op: 0,
        }
    }

    fn cleanup_global(&mut self, now: f64) {
        for k in self.ts.keys().cloned().collect::<Vec<_>>() {
            self.prune_src(&k, now);
        }
    }

    fn maybe_global(&mut self, now: f64) {
        self.op += 1;
        if self.op % GLOBAL_EVERY == 0 {
            self.cleanup_global(now);
        }
    }

    fn prune_src(&mut self, src_ip: &str, now: f64) {
        let c = now - W300;
        loop {
            let should_pop = match self.ts.get(src_ip) {
                Some(dq) => dq.front().copied().map(|t| t < c).unwrap_or(false),
                None => return,
            };
            if !should_pop {
                return;
            }
            self.ts.get_mut(src_ip).unwrap().pop_front();
            if let Some(dd) = self.deltas.get_mut(src_ip) {
                if let Some(d0) = dd.pop_front() {
                    let n0 = *self.wn.get(src_ip).unwrap_or(&0);
                    let mn0 = *self.wmean.get(src_ip).unwrap_or(&0.0);
                    let m20 = *self.wm2.get(src_ip).unwrap_or(&0.0);
                    let (nn, mm, m2n) = welford_remove_delta(n0, mn0, m20, d0);
                    self.wn.insert(src_ip.to_string(), nn);
                    self.wmean.insert(src_ip.to_string(), mm);
                    self.wm2.insert(src_ip.to_string(), m2n);
                }
            }
            if self.ts.get(src_ip).map(|d| d.is_empty()).unwrap_or(true) {
                self.ts.remove(src_ip);
                self.deltas.remove(src_ip);
                self.wn.remove(src_ip);
                self.wmean.remove(src_ip);
                self.wm2.remove(src_ip);
                self.fifo.shift_remove(src_ip);
                return;
            }
        }
    }

    pub fn variance_before(&mut self, src_ip: &str, now: f64) -> f64 {
        self.maybe_global(now);
        self.prune_src(src_ip, now);
        let n = *self.wn.get(src_ip).unwrap_or(&0);
        if n < 2 {
            return 0.0;
        }
        self.wm2.get(src_ip).copied().unwrap_or(0.0) / n as f64
    }

    pub fn add(&mut self, src_ip: &str, ts: f64) {
        self.maybe_global(ts);
        self.prune_src(src_ip, ts);
        if !self.ts.contains_key(src_ip) {
            while self.ts.len() >= MAX_SRC && !self.fifo.is_empty() {
                let evict = self.fifo.keys().next().cloned().unwrap();
                self.fifo.shift_remove(&evict);
                self.ts.remove(&evict);
                self.deltas.remove(&evict);
                self.wn.remove(&evict);
                self.wmean.remove(&evict);
                self.wm2.remove(&evict);
            }
            self.ts.insert(src_ip.to_string(), VecDeque::new());
            self.deltas.insert(src_ip.to_string(), VecDeque::new());
            self.wn.insert(src_ip.to_string(), 0);
            self.wmean.insert(src_ip.to_string(), 0.0);
            self.wm2.insert(src_ip.to_string(), 0.0);
            self.fifo.insert(src_ip.to_string(), ());
        }
        let ts_dq = self.ts.get_mut(src_ip).unwrap();
        let delta_dq = self.deltas.get_mut(src_ip).unwrap();
        if let Some(&prev) = ts_dq.back() {
            let d = ts - prev;
            delta_dq.push_back(d);
            let n0 = *self.wn.get(src_ip).unwrap();
            let mn0 = *self.wmean.get(src_ip).unwrap();
            let m20 = *self.wm2.get(src_ip).unwrap();
            let (nn, mm, m2n) = welford_add_delta(n0, mn0, m20, d);
            *self.wn.get_mut(src_ip).unwrap() = nn;
            *self.wmean.get_mut(src_ip).unwrap() = mm;
            *self.wm2.get_mut(src_ip).unwrap() = m2n;
        }
        ts_dq.push_back(ts);
    }
}

// --- 60s unique src_ip per dst_ip (flow events) ---
pub struct DstUniqueSrc60 {
    dq: HashMap<String, VecDeque<(f64, String)>>,
    counts: HashMap<String, HashMap<String, i32>>,
    fifo: IndexMap<String, ()>,
    op: u64,
}

impl DstUniqueSrc60 {
    pub fn new() -> Self {
        Self {
            dq: HashMap::new(),
            counts: HashMap::new(),
            fifo: IndexMap::new(),
            op: 0,
        }
    }

    fn cleanup_global(&mut self, now: f64) {
        for k in self.dq.keys().cloned().collect::<Vec<_>>() {
            self.prune_dst(&k, now);
        }
    }

    fn maybe_global(&mut self, now: f64) {
        self.op += 1;
        if self.op % GLOBAL_EVERY == 0 {
            self.cleanup_global(now);
        }
    }

    fn prune_dst(&mut self, dst_ip: &str, now: f64) {
        let c = now - W60;
        loop {
            let (t, sip) = match self.dq.get(dst_ip) {
                None => return,
                Some(dq) => match dq.front() {
                    None => break,
                    Some(&(t, ref sip)) => (t, sip.clone()),
                },
            };
            if t >= c {
                break;
            }
            self.dq.get_mut(dst_ip).unwrap().pop_front();
            if let Some(m) = self.counts.get_mut(dst_ip) {
                if let Some(cnt) = m.get_mut(&sip) {
                    *cnt -= 1;
                    if *cnt <= 0 {
                        m.remove(&sip);
                    }
                }
            }
        }
        if self.dq.get(dst_ip).map(|d| d.is_empty()).unwrap_or(true) {
            self.dq.remove(dst_ip);
            self.counts.remove(dst_ip);
            self.fifo.shift_remove(dst_ip);
        }
    }

    pub fn unique_before(&mut self, dst_ip: &str, now: f64) -> f64 {
        self.maybe_global(now);
        self.prune_dst(dst_ip, now);
        self.counts
            .get(dst_ip)
            .map(|m| m.len() as f64)
            .unwrap_or(0.0)
    }

    pub fn add(&mut self, dst_ip: &str, ts: f64, src_ip: &str) {
        let sip = {
            let t = src_ip.trim();
            if t.is_empty() {
                "UNKNOWN".to_string()
            } else {
                t.to_string()
            }
        };
        self.maybe_global(ts);
        self.prune_dst(dst_ip, ts);
        if !self.dq.contains_key(dst_ip) {
            while self.dq.len() >= MAX_DST && !self.fifo.is_empty() {
                let evict = self.fifo.keys().next().cloned().unwrap();
                self.fifo.shift_remove(&evict);
                self.dq.remove(&evict);
                self.counts.remove(&evict);
            }
            self.dq.insert(dst_ip.to_string(), VecDeque::new());
            self.counts.insert(dst_ip.to_string(), HashMap::new());
            self.fifo.insert(dst_ip.to_string(), ());
        }
        self.dq.get_mut(dst_ip).unwrap().push_back((ts, sip.clone()));
        let cm = self.counts.get_mut(dst_ip).unwrap();
        *cm.entry(sip).or_insert(0) += 1;
    }
}

// --- 300s flow count per src_ip ---
pub struct SrcFlowCount300 {
    src: HashMap<String, VecDeque<f64>>,
    fifo: IndexMap<String, ()>,
    op: u64,
}

impl SrcFlowCount300 {
    pub fn new() -> Self {
        Self {
            src: HashMap::new(),
            fifo: IndexMap::new(),
            op: 0,
        }
    }

    fn cleanup_global(&mut self, now: f64) {
        let c = now - W300;
        for k in self.src.keys().cloned().collect::<Vec<_>>() {
            if let Some(dq) = self.src.get_mut(&k) {
                while let Some(&t) = dq.front() {
                    if t < c {
                        dq.pop_front();
                    } else {
                        break;
                    }
                }
                if dq.is_empty() {
                    self.src.remove(&k);
                    self.fifo.shift_remove(&k);
                }
            }
        }
    }

    fn maybe_global(&mut self, now: f64) {
        self.op += 1;
        if self.op % GLOBAL_EVERY == 0 {
            self.cleanup_global(now);
        }
    }

    fn prune_src(&mut self, src_ip: &str, now: f64) {
        let c = now - W300;
        if let Some(dq) = self.src.get_mut(src_ip) {
            while let Some(&t) = dq.front() {
                if t < c {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            if dq.is_empty() {
                self.src.remove(src_ip);
                self.fifo.shift_remove(src_ip);
            }
        }
    }

    pub fn count_before(&mut self, src_ip: &str, now: f64) -> f64 {
        self.maybe_global(now);
        self.prune_src(src_ip, now);
        self.src.get(src_ip).map(|d| d.len() as f64).unwrap_or(0.0)
    }

    pub fn add(&mut self, src_ip: &str, ts: f64) {
        self.maybe_global(ts);
        self.prune_src(src_ip, ts);
        if !self.src.contains_key(src_ip) {
            while self.src.len() >= MAX_SRC && !self.fifo.is_empty() {
                let evict = self.fifo.keys().next().cloned().unwrap();
                self.fifo.shift_remove(&evict);
                self.src.remove(&evict);
            }
            self.src.insert(src_ip.to_string(), VecDeque::new());
            self.fifo.insert(src_ip.to_string(), ());
        }
        self.src.get_mut(src_ip).unwrap().push_back(ts);
    }
}

fn str_or_empty(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn collect_ttls(ev: &Value) -> Vec<f64> {
    let mut out = Vec::with_capacity(4);
    for key in ["ip", "inner", "flow"] {
        if let Some(o) = ev.get(key).and_then(|x| x.as_object()) {
            if let Some(ttl) = o.get("ttl") {
                let x = safe_float(ttl);
                if x.is_finite() {
                    out.push(x);
                }
            }
        }
    }
    out
}

fn is_failed_connection(flow: &serde_json::Map<String, Value>, tcp: &serde_json::Map<String, Value>) -> f64 {
    let src_pkts = safe_int(flow.get("pkts_toserver").unwrap_or(&Value::Null));
    let dst_pkts = safe_int(flow.get("pkts_toclient").unwrap_or(&Value::Null));
    if src_pkts <= 0 {
        return 0.0;
    }
    let syn = tcp.get("syn").and_then(|v| v.as_bool()) == Some(true);
    let ack = tcp.get("ack").and_then(|v| v.as_bool()) == Some(true);
    if syn && !ack {
        return 1.0;
    }
    if dst_pkts == 0 {
        return 1.0;
    }
    let state = flow
        .get("state")
        .map(|v| str_or_empty(v).to_lowercase())
        .unwrap_or_default();
    let reason = flow
        .get("reason")
        .map(|v| str_or_empty(v).to_lowercase())
        .unwrap_or_default();
    let asym_ratio = dst_pkts as f64 / (src_pkts.max(1) as f64);
    if asym_ratio < 0.2 {
        return 1.0;
    }
    if !state.is_empty() && state != "established" {
        if matches!(
            reason.as_str(),
            "timeout" | "closed" | "unestablished" | "rejected" | "abort"
        ) {
            return 1.0;
        }
    }
    0.0
}

// --- Per-src 10s / 60s repetition features (aligned with Python `SrcIpTemporalTracker`) ---
const TEMP_W10: f64 = 10.0;
const MAX_SRC_TEMPORAL: usize = 100_000;

struct SrcTemporalState {
    q10: VecDeque<(f64, u64, i64)>,
    q60: VecDeque<(f64, u64, i64)>,
    c10: HashMap<(u64, i64), i32>,
    c60p: HashMap<(u64, i64), i32>,
    c60d: HashMap<u64, i32>,
}

impl SrcTemporalState {
    fn new() -> Self {
        Self {
            q10: VecDeque::new(),
            q60: VecDeque::new(),
            c10: HashMap::new(),
            c60p: HashMap::new(),
            c60d: HashMap::new(),
        }
    }

    #[inline]
    fn dec_pair(map: &mut HashMap<(u64, i64), i32>, k: (u64, i64)) {
        if let Some(c) = map.get_mut(&k) {
            *c -= 1;
            if *c <= 0 {
                map.remove(&k);
            }
        }
    }

    #[inline]
    fn dec_dst(map: &mut HashMap<u64, i32>, k: u64) {
        if let Some(c) = map.get_mut(&k) {
            *c -= 1;
            if *c <= 0 {
                map.remove(&k);
            }
        }
    }

    fn pop_60(&mut self, cutoff: f64) {
        while let Some((t, dk, dp)) = self.q60.front().copied() {
            if t < cutoff {
                self.q60.pop_front();
                Self::dec_pair(&mut self.c60p, (dk, dp));
                Self::dec_dst(&mut self.c60d, dk);
            } else {
                break;
            }
        }
    }

    fn pop_10(&mut self, cutoff: f64) {
        while let Some((t, dk, dp)) = self.q10.front().copied() {
            if t < cutoff {
                self.q10.pop_front();
                Self::dec_pair(&mut self.c10, (dk, dp));
            } else {
                break;
            }
        }
    }
}

pub struct SrcTemporalTracker {
    by_src: HashMap<String, SrcTemporalState>,
    fifo: IndexMap<String, ()>,
}

impl SrcTemporalTracker {
    pub fn new() -> Self {
        Self {
            by_src: HashMap::new(),
            fifo: IndexMap::new(),
        }
    }

    /// Updates windows and returns
    /// `[src_flow_count_10s, src_to_dst_port_count_10s, same_dst_port_ratio, burst_ratio, same_dst_ip_ratio]`.
    pub fn update(&mut self, src_ip: &str, ts: f64, dst_key: u64, dst_port: i64) -> [f64; 5] {
        if self.by_src.len() >= MAX_SRC_TEMPORAL && !self.by_src.contains_key(src_ip) {
            while self.by_src.len() >= MAX_SRC_TEMPORAL && !self.fifo.is_empty() {
                let evict = self.fifo.keys().next().cloned().unwrap();
                self.fifo.shift_remove(&evict);
                self.by_src.remove(&evict);
            }
        }
        if !self.by_src.contains_key(src_ip) {
            self.by_src.insert(src_ip.to_string(), SrcTemporalState::new());
        }
        self.fifo.shift_remove(src_ip);
        self.fifo.insert(src_ip.to_string(), ());

        let st = self.by_src.get_mut(src_ip).unwrap();
        if ts > 0.0 {
            st.pop_60(ts - W60);
            st.pop_10(ts - TEMP_W10);
        }
        let k = (dst_key, dst_port);
        st.q10.push_back((ts, dst_key, dst_port));
        st.q60.push_back((ts, dst_key, dst_port));
        *st.c10.entry(k).or_insert(0) += 1;
        *st.c60p.entry(k).or_insert(0) += 1;
        *st.c60d.entry(dst_key).or_insert(0) += 1;

        let n10 = st.q10.len() as f64;
        let n60 = st.q60.len() as f64;
        let to_pair_10 = *st.c10.get(&k).unwrap_or(&0) as f64;
        let same_dp = if n60 > 0.0 {
            *st.c60p.get(&k).unwrap_or(&0) as f64 / n60
        } else {
            0.0
        };
        let burst = if n60 > 0.0 { n10 / n60 } else { 0.0 };
        let same_di = if n60 > 0.0 {
            *st.c60d.get(&dst_key).unwrap_or(&0) as f64 / n60
        } else {
            0.0
        };

        [n10, to_pair_10, same_dp, burst, same_di]
    }
}

fn tls_version_num(tls: &serde_json::Map<String, Value>) -> f64 {
    let ver_raw = str_or_empty(tls.get("version").unwrap_or(&Value::Null))
        .to_uppercase();
    if ver_raw.ends_with("1.0") {
        1.0
    } else if ver_raw.ends_with("1.1") {
        1.1
    } else if ver_raw.ends_with("1.2") {
        1.2
    } else if ver_raw.ends_with("1.3") {
        1.3
    } else {
        0.0
    }
}

pub struct ExtractorCore {
    pub behavioral: BehavioralUnified,
    pub tcp: TcpFlagTracker,
    pub dst300: DstPortWindow300,
    pub iat300: FlowInterarrivalVar300,
    pub dst_unique60: DstUniqueSrc60,
    pub src_flow300: SrcFlowCount300,
    pub src_temporal: SrcTemporalTracker,
    pub flow_tcp_engine: crate::flow_tcp_behavioral_engine::FlowTcpBehavioralEngineRust,
    /// Reused across `process_line_batch` to avoid per-batch allocations.
    batch_is_flow: Vec<u8>,
    batch_feat_idx: Vec<i32>,
    batch_flow_ids: Vec<String>,
    batch_flow_keys: Vec<String>,
    batch_feat_blob: Vec<u8>,
    /// Last-window stats when `USE_BENCHMARK_LOGGING` (feature rows only).
    bench_window_rows: u64,
    bench_window_bytes: u64,
    bench_window_start: Option<Instant>,
    /// Rows emitted with a non-empty valid join `flow_id` (else `flow_key` fallback).
    join_key_emitted_flow_id: u64,
    join_key_emitted_flow_key: u64,
    /// When `Some`, only flows whose `identity_key` (valid `flow_id` else `flow_key`) is in this set
    /// run full N_FEATURES computation; all flows still update sliding-window state.
    /// `None` = compute features for every flow (default).
    label_identity_keys: Option<HashSet<String>>,
    /// First feature row wins per Suricata `flow_id` (matches former enhanced-EVE "one line per flow_id").
    /// Skips `build_row_from_flow` on repeats — large speedup on multi-update EVE streams.
    /// Disable: `EVE_DISABLE_FLOW_ID_EMIT_DEDUPE=1`.
    emit_once_flow_id: HashSet<String>,
}

impl ExtractorCore {
    pub fn new() -> Self {
        Self {
            behavioral: BehavioralUnified::new(),
            tcp: TcpFlagTracker::new(),
            dst300: DstPortWindow300::new(),
            iat300: FlowInterarrivalVar300::new(),
            dst_unique60: DstUniqueSrc60::new(),
            src_flow300: SrcFlowCount300::new(),
            src_temporal: SrcTemporalTracker::new(),
            flow_tcp_engine: crate::flow_tcp_behavioral_engine::FlowTcpBehavioralEngineRust::new(),
            batch_is_flow: Vec::new(),
            batch_feat_idx: Vec::new(),
            batch_flow_ids: Vec::new(),
            batch_flow_keys: Vec::new(),
            batch_feat_blob: Vec::new(),
            bench_window_rows: 0,
            bench_window_bytes: 0,
            bench_window_start: None,
            join_key_emitted_flow_id: 0,
            join_key_emitted_flow_key: 0,
            label_identity_keys: None,
            emit_once_flow_id: HashSet::new(),
        }
    }

    /// Install label `identity_key` strings (same rules as Python `identity_key_from_strings`).
    /// Pass `None` to disable gating and compute features for every flow.
    pub fn set_label_identity_keys(&mut self, keys: Option<HashSet<String>>) {
        self.label_identity_keys = keys;
    }

    fn flow_id_emit_dedupe_enabled() -> bool {
        match std::env::var("EVE_DISABLE_FLOW_ID_EMIT_DEDUPE") {
            Ok(v) => {
                let s = v.trim().to_ascii_lowercase();
                !matches!(s.as_str(), "1" | "true" | "yes" | "on")
            }
            Err(_) => true,
        }
    }

    pub fn join_key_usage_counts(&self) -> (u64, u64) {
        (self.join_key_emitted_flow_id, self.join_key_emitted_flow_key)
    }

    pub fn reset_join_key_usage_counts(&mut self) {
        self.join_key_emitted_flow_id = 0;
        self.join_key_emitted_flow_key = 0;
        self.emit_once_flow_id.clear();
        if let Ok(s) = std::env::var("EVE_FLOW_ID_DEDUPE_RESERVE") {
            if let Ok(n) = s.trim().parse::<usize>() {
                if n > 0 {
                    self.emit_once_flow_id.reserve(n.min(5_000_000));
                }
            }
        }
    }

    fn record_benchmark_after_feature_row(&mut self, line_byte_len: usize) {
        if !crate::config::USE_BENCHMARK_LOGGING {
            return;
        }
        self.bench_window_rows += 1;
        self.bench_window_bytes += line_byte_len as u64;
        if self.bench_window_start.is_none() {
            self.bench_window_start = Some(Instant::now());
        }
        if self.bench_window_rows < crate::config::BENCHMARK_EVERY_FLOW_ROWS {
            return;
        }
        let Some(t0) = self.bench_window_start.take() else {
            return;
        };
        let dt = t0.elapsed().as_secs_f64();
        let mib = self.bench_window_bytes as f64 / (1024.0 * 1024.0);
        let mib_s = if dt > 0.0 { mib / dt } else { 0.0 };
        let rss = process_rss_kb().map_or_else(|| "n/a".to_string(), |k| k.to_string());
        append_benchmark_line(&format!(
            "bench last_n_flows={} dt_s={dt:.6} recent_line_bytes_MiB={mib:.6} recent_MiB_s={mib_s:.6} rss_kb={rss}",
            crate::config::BENCHMARK_EVERY_FLOW_ROWS
        ));
        self.bench_window_rows = 0;
        self.bench_window_bytes = 0;
        self.bench_window_start = Some(Instant::now());
    }

    /// Process one JSON line. Updates sliding state for **flow** events only (non-flow lines ignored).
    /// `(is_flow_event, row)` — `is_flow_event` is true only for `event_type == "flow"` (matches
    /// Python flow counting for `--max-events`). `row` is `Some` only when features were produced.
    pub fn process_line_detailed(
        &mut self,
        line: &str,
        if_benign_only: bool,
    ) -> (bool, Option<(String /* flow_id */, String /* flow_key */, f64, [f64; N_FEATURES])>) {
        let line_trim = line.trim();
        if line_trim.is_empty() {
            return (false, None);
        }
        if suricata_eve_skip_full_json_parse(line_trim.as_bytes()) {
            return (false, None);
        }
        if Self::flow_id_emit_dedupe_enabled()
            && crate::fast_flow_dedupe::skip_duplicate_flow_before_parse(
                line_trim,
                &self.emit_once_flow_id,
            )
        {
            return (true, None);
        }
        let v = match crate::typed_flow::parse_line_with_fallback(
            line_trim,
            crate::config::USE_TYPED_PARSING,
        ) {
            Ok(v) => v,
            Err(_) => return (false, None),
        };
        let et = v
            .get("event_type")
            .map(|x| str_or_empty(x).to_lowercase())
            .unwrap_or_default();
        if et == "tcp" {
            return (false, None);
        }
        if et != "flow" {
            return (false, None);
        }
        let src_ip = v
            .get("src_ip")
            .map(|x| str_or_empty(x).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "UNKNOWN".to_string());
        let dst_ip = v
            .get("dest_ip")
            .map(|x| str_or_empty(x).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "UNKNOWN".to_string());
        let src_port = safe_int(v.get("src_port").unwrap_or(&Value::Null));
        let dst_port = safe_int(v.get("dest_port").unwrap_or(&Value::Null));
        let mut proto = str_or_empty(v.get("proto").unwrap_or(&Value::String("TCP".to_string())))
            .trim()
            .to_uppercase();
        if proto.is_empty() {
            proto = "TCP".to_string();
        }
        let flow = match v.get("flow").and_then(|f| f.as_object()) {
            Some(f) => f,
            None => return (true, None),
        };
        if if_benign_only && flow.get("alerted").and_then(|x| x.as_bool()) == Some(true) {
            return (true, None);
        }

        let flow_id_str = flow_id_string_from_ev(&v).unwrap_or_default();
        let fid_trim = flow_id_str.trim();
        if Self::flow_id_emit_dedupe_enabled() && !fid_trim.is_empty() {
            let sl = fid_trim.to_ascii_lowercase();
            if sl != "nan" && sl != "none" && !self.emit_once_flow_id.insert(fid_trim.to_string()) {
                return (true, None);
            }
        }

        // Parity port (flow-only): sliding-window state for every flow; full N_FEATURES only when
        // `label_identity_keys` is None or contains this row's `identity_key`.
        let Some(p) = self.flow_tcp_engine.parse_flow_event(&v) else {
            return (true, None);
        };
        let ts2 = p.ts;
        let bucket = flow_key_bucket_sec();
        let tb = (ts2 / bucket).floor() as i64;
        let flow_key = format!(
            "{}:{}-{}:{}-{}_{}",
            src_ip, src_port, dst_ip, dst_port, proto, tb
        );
        let use_flow_id = !fid_trim.is_empty() && {
            let sl = fid_trim.to_ascii_lowercase();
            sl != "nan" && sl != "none"
        };
        let compute_features = match &self.label_identity_keys {
            None => true,
            Some(keys) => {
                if use_flow_id {
                    keys.contains(fid_trim)
                } else {
                    keys.contains(flow_key.as_str())
                }
            }
        };
        let (_, feats) = self
            .flow_tcp_engine
            .apply_parsed_with_optional_features(p, compute_features);
        let Some(feats) = feats else {
            return (true, None);
        };
        if use_flow_id {
            self.join_key_emitted_flow_id += 1;
        } else {
            self.join_key_emitted_flow_key += 1;
        }
        self.record_benchmark_after_feature_row(line_trim.len());
        (true, Some((flow_id_str, flow_key, ts2, feats)))
    }

    pub fn process_line(
        &mut self,
        line: &str,
        if_benign_only: bool,
    ) -> Option<(String, String, f64, [f64; N_FEATURES])> {
        self.process_line_detailed(line, if_benign_only).1
    }

    /// Process many lines with **one** round-trip from Python. Returns:
    /// - `is_flow`: u8 0/1 per input line (flow event)
    /// - `feat_idx`: i32 per line, `-1` if no feature row; else dense row index into key vectors / `feat_blob`
    /// - `flow_ids`: raw EVE `flow_id` per dense row (`""` when missing); Python merges with `flow_key` → `identity_key`
    /// - `flow_keys`: parallel time-bucketed 5-tuple keys
    /// - `feat_blob`: little-endian f64, `flow_ids.len() * N_FEATURES * 8` bytes
    pub fn process_line_batch(
        &mut self,
        lines: &[String],
        if_benign_only: bool,
    ) -> (Vec<u8>, Vec<i32>, Vec<String>, Vec<String>, Vec<u8>) {
        let n = lines.len();
        // Do not borrow `batch_*` across `process_line_detailed` — that needs `&mut self` wholly.
        self.batch_is_flow.clear();
        self.batch_is_flow.reserve(n);
        self.batch_feat_idx.clear();
        self.batch_feat_idx.reserve(n);
        self.batch_flow_ids.clear();
        self.batch_flow_keys.clear();
        self.batch_feat_blob.clear();
        self.batch_feat_blob
            .reserve(n.saturating_mul(N_FEATURES * 8));
        let mut dense_i: i32 = 0;
        for line in lines {
            let (is_f, row) = self.process_line_detailed(line, if_benign_only);
            self.batch_is_flow.push(u8::from(is_f));
            match row {
                None => self.batch_feat_idx.push(-1),
                Some((fid, fk, _ts, arr)) => {
                    self.batch_feat_idx.push(dense_i);
                    dense_i += 1;
                    self.batch_flow_ids.push(fid);
                    self.batch_flow_keys.push(fk);
                    for v in arr.iter() {
                        self.batch_feat_blob.extend_from_slice(&v.to_le_bytes());
                    }
                }
            }
        }
        (
            std::mem::take(&mut self.batch_is_flow),
            std::mem::take(&mut self.batch_feat_idx),
            std::mem::take(&mut self.batch_flow_ids),
            std::mem::take(&mut self.batch_flow_keys),
            std::mem::take(&mut self.batch_feat_blob),
        )
    }

    /// Non-empty lines read, feature rows emitted (same as `process_line_detailed(...).1.is_some()`).
    pub fn process_jsonl_file(
        &mut self,
        path: &Path,
        if_benign_only: bool,
    ) -> std::io::Result<(u64, u64)> {
        let f = std::fs::File::open(path)?;
        let reader = BufReader::new(f);
        let mut lines: u64 = 0;
        let mut feature_rows: u64 = 0;
        for line_res in reader.lines() {
            let line = line_res?;
            if line.trim().is_empty() {
                continue;
            }
            lines += 1;
            if self.process_line_detailed(&line, if_benign_only).1.is_some() {
                feature_rows += 1;
            }
        }
        Ok((lines, feature_rows))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_flow() {
        let mut e = ExtractorCore::new();
        let line = r#"{"timestamp":"2020-01-01T00:00:01.000000+0000","event_type":"flow","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","src_port":1234,"dest_port":443,"proto":"TCP","flow":{"pkts_toserver":3,"pkts_toclient":3,"bytes_toserver":100,"bytes_toclient":200,"age":1.0},"tcp":{"syn":true,"ack":true}}"#;
        let (is_flow, r) = e.process_line_detailed(line, false);
        assert!(is_flow);
        assert!(r.is_some());
        let (fid, fk, _, feat) = r.unwrap();
        assert!(fid.is_empty());
        assert!(!fk.is_empty());
        assert_eq!(feat.len(), N_FEATURES);
        assert!(feat[0] >= 0.0);
    }

    #[test]
    fn flow_id_emit_dedupe_second_line_skips_features() {
        let mut e = ExtractorCore::new();
        let a = r#"{"flow_id":"dup","event_type":"flow","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","src_port":1,"dest_port":443,"proto":"TCP","flow":{"age":1.0,"bytes_toserver":10,"bytes_toclient":20},"tcp":{"syn":true}}"#;
        let b = r#"{"flow_id":"dup","event_type":"flow","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","src_port":1,"dest_port":443,"proto":"TCP","flow":{"age":5.0,"bytes_toserver":999,"bytes_toclient":1},"tcp":{"syn":true,"ack":true}}"#;
        let (_, r1) = e.process_line_detailed(a, false);
        let (_, r2) = e.process_line_detailed(b, false);
        assert!(r1.is_some(), "first flow line should emit");
        assert!(r2.is_none(), "duplicate flow_id should not emit feature row");
    }

    #[test]
    fn flow_id_emitted_when_present() {
        let mut e = ExtractorCore::new();
        let line = r#"{"flow_id":12345,"timestamp":"2020-01-01T00:00:01.000000+0000","event_type":"flow","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","src_port":1234,"dest_port":443,"proto":"TCP","flow":{"pkts_toserver":3,"pkts_toclient":3,"bytes_toserver":100,"bytes_toclient":200,"age":1.0},"tcp":{"syn":true,"ack":true}}"#;
        let (is_flow, r) = e.process_line_detailed(line, false);
        assert!(is_flow);
        let (fid, fk, _, _) = r.unwrap();
        assert_eq!(fid, "12345");
        assert!(fk.contains("1.1.1.1"));
    }

    #[test]
    fn precheck_skips_dns_http_spacing() {
        assert!(suricata_eve_skip_full_json_parse(
            br#"{"timestamp":"x","event_type":"dns"}"#
        ));
        assert!(suricata_eve_skip_full_json_parse(
            br#"{"event_type": "http","x":1}"#
        ));
        assert!(suricata_eve_skip_full_json_parse(
            br#"{"event_type" : "alert"}"#
        ));
    }

    #[test]
    fn precheck_does_not_skip_flow_variants() {
        assert!(!suricata_eve_skip_full_json_parse(
            br#"{"event_type":"flow","x":1}"#
        ));
        assert!(!suricata_eve_skip_full_json_parse(
            br#"{"event_type": "flow"}"#
        ));
    }

    #[test]
    fn precheck_dns_matches_full_parse_semantics() {
        let mut e = ExtractorCore::new();
        let dns = r#"{"timestamp":"2020-01-01T00:00:01.000000+0000","event_type":"dns"}"#;
        assert!(suricata_eve_skip_full_json_parse(dns.as_bytes()));
        let (a, b) = e.process_line_detailed(dns, false);
        assert!(!a);
        assert!(b.is_none());
    }

    /// CICIDS-style `flow.start` uses `+0530` without a colon; must not collapse to ts=0 (breaks IAT variance).
    #[test]
    fn flow_start_plus0530_parses_nonzero_epoch() {
        let mut e = ExtractorCore::new();
        let line = r#"{"event_type":"flow","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","src_port":1234,"dest_port":443,"proto":"TCP","flow":{"start":"2017-07-07T17:29:50.639970+0530","pkts_toserver":3,"pkts_toclient":3,"bytes_toserver":100,"bytes_toclient":200,"age":1.0},"tcp":{"syn":true,"ack":true}}"#;
        let (is_flow, r) = e.process_line_detailed(line, false);
        assert!(is_flow);
        let (_, _, ts, _) = r.unwrap();
        assert!(
            ts > 1_000_000_000.0,
            "expected parsed epoch, got {}",
            ts
        );
    }

    /// Fourth flow from same src: two inter-arrival deltas in window → variance_before can be > 0.
    #[test]
    fn flow_interarrival_variance_positive_on_fourth_flow() {
        let mut e = ExtractorCore::new();
        let base = r#"{"event_type":"flow","src_ip":"10.0.0.1","dest_ip":"2.2.2.2","src_port":1234,"dest_port":443,"proto":"TCP","flow":{"pkts_toserver":3,"pkts_toclient":3,"bytes_toserver":100,"bytes_toclient":200,"age":1.0},"tcp":{"syn":true,"ack":true},"timestamp":"TIME"}"#;
        for (i, sec) in [0u32, 1, 3, 6].iter().enumerate() {
            let ts = format!("2020-01-01T00:00:{:02}.000000+00:00", sec);
            let line = base.replace("TIME", &ts);
            let (_, r) = e.process_line_detailed(&line, false);
            let feat = r.unwrap().3;
            if i == 3 {
                assert!(
                    feat[17] > 0.0,
                    "iat_cv_srcdst_300s should be > 0 on 4th flow, got {}",
                    feat[17]
                );
            }
        }
    }

    #[test]
    fn parity_python_rust_flow_tcp_engine() {
        use crate::flow_tcp_behavioral_engine::FlowTcpBehavioralEngineRust;
        use serde_json::Value as JsonValue;
        use std::io::Write;
        use std::path::PathBuf;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let t0 = "2020-01-01T00:00:00+00:00";
        let t5 = "2020-01-01T00:00:05+00:00";
        let t15 = "2020-01-01T00:00:15+00:00";

        // Flow-only JSONL: embedded `tcp` on some rows; standalone tcp events are ignored by both engines.
        let jsonl = vec![
            format!(
                r#"{{"event_type":"flow","flow_id":"f1","src_ip":"10.0.0.1","dest_ip":"2.2.2.2","src_port":1234,"dest_port":80,"proto":"TCP","flow":{{"start":"{t0}","age":200.0,"bytes_toserver":60,"bytes_toclient":40}},"tcp":{{"syn":true,"ack":false,"rst":false,"fin":false}}}}"#
            ),
            format!(
                r#"{{"event_type":"flow","flow_id":"f2","src_ip":"10.0.0.1","dest_ip":"2.2.2.2","src_port":1234,"dest_port":80,"proto":"TCP","flow":{{"start":"{t5}","age":0.5,"bytes_toserver":25,"bytes_toclient":25}}}}"#
            ),
            format!(
                r#"{{"event_type":"tcp","flow_id":"ignored","tcp":{{"syn":true}}}}"#
            ),
            format!(
                r#"{{"event_type":"flow","flow_id":"f3","src_ip":"10.0.0.1","dest_ip":"2.2.2.2","src_port":1234,"dest_port":80,"proto":"TCP","flow":{{"start":"{t15}","age":0.5,"bytes_toserver":120,"bytes_toclient":80}},"tcp":{{"syn":true,"ack":true,"rst":false,"fin":true}}}}"#
            ),
        ];

        let py_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .expect("crate must live at <project>/rust/eve_extractor")
            .to_path_buf();

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp_path = std::env::temp_dir().join(format!("eve_parity_{unique}.jsonl"));

        {
            let mut f = std::fs::File::create(&tmp_path).expect("create tmp jsonl");
            for line in &jsonl {
                writeln!(f, "{line}").expect("write jsonl");
            }
            f.flush().unwrap();
        }

        let py_script = r#"
import json, math, sys
from pathlib import Path

sys.path.insert(0, sys.argv[2])
from ingestion.flow_tcp_behavioral_engine import FlowTcpBehavioralEngine
from ingestion.unified_behavioral_schema import UNIFIED_BEHAVIORAL_FEATURE_NAMES

raw = Path(sys.argv[1])
eng = FlowTcpBehavioralEngine()
rows = []

def clean(x):
    if x is None:
        return 0.0
    try:
        xf = float(x)
    except Exception:
        return 0.0
    return xf if math.isfinite(xf) else 0.0

with open(raw, "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        ev = json.loads(line)
        if str(ev.get("event_type","")).strip().lower() != "flow":
            continue
        row = eng.build_row_from_flow(ev)
        feats = [clean(row.get(k, 0.0)) for k in UNIFIED_BEHAVIORAL_FEATURE_NAMES]
        rows.append(feats)

print(json.dumps({"names": UNIFIED_BEHAVIORAL_FEATURE_NAMES, "rows": rows}))
"#;

        let py_out = Command::new("python3")
            .arg("-c")
            .arg(py_script)
            .arg(tmp_path.to_string_lossy().to_string())
            .arg(py_root.to_string_lossy().to_string())
            .output()
            .expect("run python");
        assert!(
            py_out.status.success(),
            "python failed: stdout={} stderr={}",
            String::from_utf8_lossy(&py_out.stdout),
            String::from_utf8_lossy(&py_out.stderr)
        );

        let py_json: JsonValue = serde_json::from_slice(&py_out.stdout).expect("parse python json");
        let feat_names: Vec<String> = serde_json::from_value(py_json["names"].clone()).unwrap();
        let py_rows: Vec<Vec<f64>> = serde_json::from_value(py_json["rows"].clone()).unwrap();

        let mut rust_engine = FlowTcpBehavioralEngineRust::new();
        let mut rust_rows: Vec<Vec<f64>> = Vec::new();

        let contents = std::fs::read_to_string(&tmp_path).unwrap();
        for line in contents.lines() {
            let ev: JsonValue = serde_json::from_str(line).unwrap();
            let et = ev
                .get("event_type")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if et == "flow" {
                let (_ts, f) = rust_engine.build_row_from_flow(&ev);
                rust_rows.push(f.to_vec());
            }
        }

        let _ = std::fs::remove_file(&tmp_path);

        assert_eq!(py_rows.len(), rust_rows.len(), "row count mismatch");
        assert_eq!(
            feat_names.len(),
            crate::flow_tcp_behavioral_engine::DEV_FEATURE_COUNT,
            "feature name count mismatch"
        );

        for (row_idx, (py_row, rust_row)) in py_rows.iter().zip(rust_rows.iter()).enumerate() {
            assert_eq!(py_row.len(), rust_row.len(), "row feature length mismatch at {row_idx}");
            for (feat_idx, (py_v, rust_v)) in py_row.iter().zip(rust_row.iter()).enumerate() {
                let diff = (py_v - rust_v).abs();
                if diff > 1e-6 {
                    panic!(
                        "feature mismatch row={row_idx} feature={name} python={py_v} rust={rust_v} abs_diff={diff}",
                        name = feat_names[feat_idx]
                    );
                }
            }
        }
    }
}
