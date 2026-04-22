//! Flow-centric behavioral feature engine.
//!
//! TCP flags come only from the optional `tcp` object on **flow** events (no `event_type == "tcp"`).
//! When `tcp` is missing, counters are zero and `has_tcp` (last feature) is 0.
//!
//! Numerical parity target (same formulas / window semantics):
//! `Model2_development/ingestion/flow_tcp_behavioral_engine.py`
//! Feature **order** and **count**: `ingestion/unified_behavioral_schema.py`.
//!
//! **Performance:** `Rec` stores interned `u32` endpoint ids (no `String` in deques); window maps use
//! `FxHashMap` / `FxHashSet` for faster lookups. Semantics match string equality on `src_ip` / `dest_ip`.
//!
//! **IAT features (`iat_cv_*`, `iat_autocorr_srcdst_300s`):** inter-arrival gaps are maintained
//! **online** in **append order** (consecutive flow start times per window key). When the sliding
//! window **pops** old `Rec`s at the front, accumulated IAT stats for that key are **reset** (we do
//! not reverse Welford updates). This is an intentional approximation vs. the legacy time-sorted
//! gap sequence; it preserves jitter / instability signal for tree models while avoiding `O(n log n)`
//! sorts and scratch `Vec` allocations on the hot path.

use std::collections::VecDeque;

use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::Value;

pub const DEV_FEATURE_COUNT: usize = 45;

const EPS: f64 = 1e-6;

const W10: f64 = 10.0;
const W60: f64 = 60.0;
const W300: f64 = 300.0;
const W24H: f64 = 86400.0;

const THETA_SMALL: f64 = 128.0;
const THETA_REQ: f64 = 256.0;
const THETA_SHORT: f64 = 1.0;
const THETA_INCOMPLETE: f64 = 1.0;
const THETA_RATE: f64 = 64.0;
const THETA_LONG: f64 = 120.0;
const THETA_LOW: f64 = 512.0;

#[derive(Clone, Copy, Debug, Default)]
struct TcpStats {
    syn_count: f64,
    ack_count: f64,
    rst_count: f64,
    fin_count: f64,
    total_packets: f64,
}

/// One sliding-window record: **Copy** (no heap) — IPs are `StringInterner` ids (`0` = empty only).
#[derive(Clone, Copy, Debug, Default)]
struct Rec {
    ts: f64,
    src_id: u32,
    dst_id: u32,
    dst_port: i64,
    dur: f64,
    fwd: f64,
    rev: f64,
    total: f64,
    syn_count: f64,
    ack_count: f64,
    rst_count: f64,
    fin_count: f64,
    total_packets: f64,
}

/// Stable `u32` per distinct string; `intern("") == 0` reserved.
#[derive(Default)]
struct StringInterner {
    by_string: FxHashMap<String, u32>,
    next_id: u32,
}

impl StringInterner {
    fn new() -> Self {
        Self {
            by_string: FxHashMap::default(),
            next_id: 1,
        }
    }

    fn intern(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        if let Some(&id) = self.by_string.get(s) {
            return id;
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("string interner exhausted (u32::MAX distinct strings)");
        self.by_string.insert(s.to_string(), id);
        id
    }
}

fn safe_int(v: &Value) -> i64 {
    match v {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|x| x as i64))
            .unwrap_or(0),
        Value::String(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn safe_float(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn flow_id_py(ev: &Value) -> String {
    // Python `_flow_id`: if v is None -> "", else str(v).strip()
    match ev.get("flow_id") {
        None | Some(Value::Null) => "".to_string(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(other) => other.to_string().trim().to_string(),
    }
}

/// Match Python `bool(tcp.get(key))` for JSON values.
fn tcp_flag_truthy(v: Option<&Value>) -> f64 {
    match v {
        None | Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(*b as i32),
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                f64::from(i != 0)
            } else if let Some(f) = n.as_f64() {
                f64::from(f != 0.0)
            } else {
                0.0
            }
        }
        Some(Value::String(s)) => f64::from(!s.is_empty()),
        Some(Value::Array(a)) => f64::from(!a.is_empty()),
        Some(Value::Object(o)) => f64::from(!o.is_empty()),
    }
}

fn tcp_stats_from_flow_embedded(ev: &Value) -> (TcpStats, f64) {
    let Some(tcp) = ev.get("tcp").and_then(|x| x.as_object()) else {
        return (TcpStats::default(), 0.0);
    };
    let syn = tcp_flag_truthy(tcp.get("syn"));
    let ack = tcp_flag_truthy(tcp.get("ack"));
    let rst = tcp_flag_truthy(tcp.get("rst"));
    let fin = tcp_flag_truthy(tcp.get("fin"));
    let flag_sum = syn + ack + rst + fin;
    let total = if flag_sum > 0.0 { flag_sum } else { 1.0 };
    (
        TcpStats {
            syn_count: syn,
            ack_count: ack,
            rst_count: rst,
            fin_count: fin,
            total_packets: total,
        },
        1.0,
    )
}

/// Suggested setting for `EVE_MAX_WINDOW_EVENTS` when deliberately trading strict parity for speed
/// on extremely deep deques (only applies when the env var is set).
#[allow(dead_code)]
pub const MAX_WINDOW_EVENTS_TUNING_HINT: usize = 1000;

/// When set via `EVE_MAX_WINDOW_EVENTS` to a positive value, **after** time-based pruning,
/// drop oldest `Rec` entries so deque length ≤ cap. Default: unset = unbounded (strict parity).
fn max_rec_deque_cap() -> Option<usize> {
    std::env::var("EVE_MAX_WINDOW_EVENTS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
}

fn truncate_rec_deque_cap(q: &mut VecDeque<Rec>) {
    let Some(cap) = max_rec_deque_cap() else {
        return;
    };
    while q.len() > cap {
        q.pop_front();
    }
}

fn prune_q_capped(q: &mut VecDeque<Rec>, now: f64, w: f64) {
    prune_q(q, now, w);
    truncate_rec_deque_cap(q);
}

/// Returns how many `Rec`s were removed (time prune + optional length cap).
fn prune_q_capped_pop_count(q: &mut VecDeque<Rec>, now: f64, w: f64) -> usize {
    let before = q.len();
    prune_q_capped(q, now, w);
    before.saturating_sub(q.len())
}

/// Welford / online algorithm for mean and population variance (`ddof=0`).
#[derive(Clone, Copy, Debug, Default)]
struct Welford {
    n: usize,
    mean: f64,
    m2: f64,
}

impl Welford {
    fn push(&mut self, x: f64) {
        if !x.is_finite() {
            return;
        }
        self.n = self.n.saturating_add(1);
        let nf = self.n as f64;
        let delta = x - self.mean;
        self.mean += delta / nf;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    fn variance_pop(&self) -> f64 {
        if self.n == 0 {
            return 0.0;
        }
        (self.m2 / self.n as f64).max(0.0)
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Lag-1 Pearson correlation on consecutive IAT values (append order), population moments / n.
#[derive(Clone, Copy, Debug, Default)]
struct Lag1IatCorr {
    n_pairs: usize,
    mean_x: f64,
    mean_y: f64,
    cxx: f64,
    cyy: f64,
    cxy: f64,
    last_iat: Option<f64>,
}

impl Lag1IatCorr {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn observe_iat(&mut self, iat: f64) {
        if !iat.is_finite() || iat < 0.0 {
            return;
        }
        if let Some(x) = self.last_iat {
            let y = iat;
            self.n_pairs = self.n_pairs.saturating_add(1);
            let nf = self.n_pairs as f64;
            let dx = x - self.mean_x;
            self.mean_x += dx / nf;
            let dy = y - self.mean_y;
            self.mean_y += dy / nf;
            self.cxx += dx * (x - self.mean_x);
            self.cyy += dy * (y - self.mean_y);
            self.cxy += dx * (y - self.mean_y);
        }
        self.last_iat = Some(iat);
    }

    fn pearson_pop(&self) -> f64 {
        if self.n_pairs < 2 {
            return 0.0;
        }
        let nf = self.n_pairs as f64;
        let vx = self.cxx / nf;
        let vy = self.cyy / nf;
        if vx <= EPS * EPS || vy <= EPS * EPS {
            return 0.0;
        }
        let cov = self.cxy / nf;
        let d = (vx * vy).sqrt();
        let r = cov / d;
        if r.is_finite() { r } else { 0.0 }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct IatOnline {
    iat: Welford,
    lag1: Lag1IatCorr,
}

impl IatOnline {
    fn reset(&mut self) {
        self.iat.reset();
        self.lag1.reset();
    }

    /// Record one inter-arrival gap (current flow start minus previous flow start in this window).
    fn observe_gap_append_order(&mut self, dt: f64) {
        if !dt.is_finite() || dt < 0.0 {
            return;
        }
        self.iat.push(dt);
        self.lag1.observe_iat(dt);
    }

    fn cv(&self) -> f64 {
        let m = self.iat.mean;
        let s = self.iat.variance_pop().sqrt();
        s / (m.abs() + EPS)
    }

    fn autocorr_lag1(&self) -> f64 {
        self.lag1.pearson_pop()
    }
}

/// Shannon entropy from count map values; **order-invariant** (same multiset → same H).
fn entropy_from_dst_counts_map(map: &FxHashMap<u32, u32>) -> f64 {
    let n: f64 = map.values().map(|&c| c as f64).sum();
    if n <= 0.0 {
        return 0.0;
    }
    let mut e = 0.0;
    for &c in map.values() {
        if c == 0 {
            continue;
        }
        let p = (c as f64) / n;
        e -= p * (p + EPS).log2();
    }
    e
}

fn entropy_from_port_counts_map(map: &FxHashMap<i64, u32>) -> f64 {
    let n: f64 = map.values().map(|&c| c as f64).sum();
    if n <= 0.0 {
        return 0.0;
    }
    let mut e = 0.0;
    for &c in map.values() {
        if c == 0 {
            continue;
        }
        let p = (c as f64) / n;
        e -= p * (p + EPS).log2();
    }
    e
}

/// `flow_size_mode_src_300s`: bin of the **first** flow in deque order whose bin count equals the global max.
fn flow_size_mode_deque_tiebreak(q: &VecDeque<Rec>, size_bins: &FxHashMap<i64, u32>) -> f64 {
    let maxc = size_bins.values().cloned().max().unwrap_or(0);
    if maxc == 0 {
        return 0.0;
    }
    for r in q.iter() {
        let b = (r.total / 128.0).floor() as i64;
        if *size_bins.get(&b).unwrap_or(&0) == maxc {
            return b as f64;
        }
    }
    0.0
}

/// Incremental 300s window aggregates per **source** (`q_src300` key). Updated on append; reversed on prune.
#[derive(Default)]
struct Src300Agg {
    total: usize,
    dst_counts: FxHashMap<u32, u32>,
    port_counts: FxHashMap<i64, u32>,
    pair_counts: FxHashMap<(u32, i64), u32>,
    short_count: u32,
    ack_presence: u32,
    incomplete_count: u32,
    low_data_count: u32,
    sum_total: f64,
    size_bins: FxHashMap<i64, u32>,
    max_port_freq: u32,
}

impl Src300Agg {
    fn recompute_max_port_freq(&mut self) {
        self.max_port_freq = self.port_counts.values().cloned().max().unwrap_or(0);
    }

    fn add_rec(&mut self, r: &Rec) {
        self.total = self.total.saturating_add(1);
        *self.dst_counts.entry(r.dst_id).or_insert(0) += 1;
        let pc = self.port_counts.entry(r.dst_port).or_insert(0);
        *pc += 1;
        if *pc > self.max_port_freq {
            self.max_port_freq = *pc;
        }
        *self
            .pair_counts
            .entry((r.dst_id, r.dst_port))
            .or_insert(0) += 1;

        if r.dur < THETA_SHORT {
            self.short_count = self.short_count.saturating_add(1);
        }
        if r.ack_count > 0.0 {
            self.ack_presence = self.ack_presence.saturating_add(1);
        }
        if r.dur < THETA_INCOMPLETE {
            self.incomplete_count = self.incomplete_count.saturating_add(1);
        }
        if r.dur > THETA_LONG && (r.total / (r.dur + EPS)) < THETA_RATE {
            self.low_data_count = self.low_data_count.saturating_add(1);
        }
        self.sum_total += r.total;

        let bin = (r.total / 128.0).floor() as i64;
        *self.size_bins.entry(bin).or_insert(0) += 1;
    }

    fn dec_map_u32(m: &mut FxHashMap<u32, u32>, k: u32) {
        use std::collections::hash_map::Entry;
        if let Entry::Occupied(mut e) = m.entry(k) {
            let v = e.get_mut();
            *v = v.saturating_sub(1);
            if *v == 0 {
                e.remove();
            }
        }
    }

    fn dec_map_i64(m: &mut FxHashMap<i64, u32>, k: i64) {
        use std::collections::hash_map::Entry;
        if let Entry::Occupied(mut e) = m.entry(k) {
            let v = e.get_mut();
            *v = v.saturating_sub(1);
            if *v == 0 {
                e.remove();
            }
        }
    }

    fn dec_pair(m: &mut FxHashMap<(u32, i64), u32>, k: (u32, i64)) {
        use std::collections::hash_map::Entry;
        if let Entry::Occupied(mut e) = m.entry(k) {
            let v = e.get_mut();
            *v = v.saturating_sub(1);
            if *v == 0 {
                e.remove();
            }
        }
    }

    fn remove_rec(&mut self, r: &Rec) {
        if self.total == 0 {
            return;
        }
        self.total = self.total.saturating_sub(1);

        let old_pf = *self.port_counts.get(&r.dst_port).unwrap_or(&0);
        Self::dec_map_u32(&mut self.dst_counts, r.dst_id);
        Self::dec_map_i64(&mut self.port_counts, r.dst_port);
        Self::dec_pair(&mut self.pair_counts, (r.dst_id, r.dst_port));

        if old_pf == self.max_port_freq {
            self.recompute_max_port_freq();
        }

        if r.dur < THETA_SHORT {
            self.short_count = self.short_count.saturating_sub(1);
        }
        if r.ack_count > 0.0 {
            self.ack_presence = self.ack_presence.saturating_sub(1);
        }
        if r.dur < THETA_INCOMPLETE {
            self.incomplete_count = self.incomplete_count.saturating_sub(1);
        }
        if r.dur > THETA_LONG && (r.total / (r.dur + EPS)) < THETA_RATE {
            self.low_data_count = self.low_data_count.saturating_sub(1);
        }
        self.sum_total -= r.total;

        let bin = (r.total / 128.0).floor() as i64;
        Self::dec_map_i64(&mut self.size_bins, bin);
    }
}

fn prune_q(q: &mut VecDeque<Rec>, now: f64, w: f64) {
    let cutoff = now - w;
    while let Some(front) = q.front() {
        if front.ts < cutoff {
            q.pop_front();
        } else {
            break;
        }
    }
}

fn prune_active(q: &mut VecDeque<(f64, f64)>, now: f64, w: f64) {
    let c = now - w;
    while let Some(front) = q.front() {
        let (st, en) = *front;
        if en < now || st < c {
            q.pop_front();
        } else {
            break;
        }
    }
}

pub struct FlowTcpBehavioralEngineRust {
    interner: StringInterner,

    src_10: FxHashMap<u32, VecDeque<Rec>>,
    src_60: FxHashMap<u32, VecDeque<Rec>>,
    src_300: FxHashMap<u32, VecDeque<Rec>>,
    src_24h: FxHashMap<u32, VecDeque<Rec>>,

    dst_10: FxHashMap<u32, VecDeque<Rec>>,
    dst_60: FxHashMap<u32, VecDeque<Rec>>,

    srcdst_300: FxHashMap<(u32, u32), VecDeque<Rec>>,
    srcdst_24h: FxHashMap<(u32, u32), VecDeque<Rec>>,

    // Python defines these and prunes them, but never appends intervals.
    // We replicate by never inserting into them.
    src_active_10: FxHashMap<u32, VecDeque<(f64, f64)>>,
    dst_active_10: FxHashMap<u32, VecDeque<(f64, f64)>>,
    dst_port_active_10: FxHashMap<(u32, i64), VecDeque<(f64, f64)>>,

    // Debug instrumentation (mandatory audit): limit printing for emissions.
    dbg_emit_count: usize,

    /// Online IAT stats for `src_60` windows; reset when that deque pops at the front.
    iat_online_src60: FxHashMap<u32, IatOnline>,
    /// Online IAT stats for `srcdst_300` windows; reset when that deque pops at the front.
    iat_online_srcdst300: FxHashMap<(u32, u32), IatOnline>,

    /// Incremental aggregates for `q_src300` (per `src_id`); kept in sync with deque via append + prune.
    src300_agg: FxHashMap<u32, Src300Agg>,

    scratch_uniq_src: FxHashSet<u32>,
    /// Reused for `dst_src_ip_entropy_60s` (src_id counts in `q_dst60`); cleared each compute.
    scratch_dst60_src_counts: FxHashMap<u32, u32>,
    /// Reused for `single_dst_port_focus_src_60s` (`dst_port` counts in `q_src60`); cleared each compute.
    scratch_src60_port_counts: FxHashMap<i64, u32>,
}

/// Parsed flow row + per-event scalars. Windows are updated **after** feature computation
/// (see `apply_flow_with_optional_features`: prune → compute (optional) → append).
pub(crate) struct FlowTcpParsed {
    pub ts: f64,
    pub end: f64,
    pub flow_id: String,
    pub rec: Rec,
    pub has_tcp: f64,
    pub fwd: f64,
    pub rev: f64,
    pub src_id: u32,
    pub dst_id: u32,
    pub dst_port: i64,
}

impl FlowTcpBehavioralEngineRust {
    pub fn new() -> Self {
        Self {
            interner: StringInterner::new(),
            src_10: FxHashMap::default(),
            src_60: FxHashMap::default(),
            src_300: FxHashMap::default(),
            src_24h: FxHashMap::default(),
            dst_10: FxHashMap::default(),
            dst_60: FxHashMap::default(),
            srcdst_300: FxHashMap::default(),
            srcdst_24h: FxHashMap::default(),
            src_active_10: FxHashMap::default(),
            dst_active_10: FxHashMap::default(),
            dst_port_active_10: FxHashMap::default(),
            dbg_emit_count: 0,
            iat_online_src60: FxHashMap::default(),
            iat_online_srcdst300: FxHashMap::default(),
            src300_agg: FxHashMap::default(),
            scratch_uniq_src: FxHashSet::default(),
            scratch_dst60_src_counts: FxHashMap::default(),
            scratch_src60_port_counts: FxHashMap::default(),
        }
    }

    /// Time + length-cap prune for `src_300[src_id]`, reversing `src300_agg` per popped `Rec`.
    fn prune_src300_deque_and_agg(&mut self, src_id: u32, ts: f64) {
        let mut popped: Vec<Rec> = Vec::new();
        {
            let q = self.src_300.entry(src_id).or_insert_with(VecDeque::new);
            let cutoff = ts - W300;
            while let Some(front) = q.front() {
                if front.ts < cutoff {
                    popped.push(q.pop_front().unwrap());
                } else {
                    break;
                }
            }
            if let Some(cap) = max_rec_deque_cap() {
                while q.len() > cap {
                    popped.push(q.pop_front().unwrap());
                }
            }
        }
        if popped.is_empty() {
            return;
        }
        for r in popped {
            let remove_key = {
                let Some(agg) = self.src300_agg.get_mut(&src_id) else {
                    continue;
                };
                agg.remove_rec(&r);
                agg.total == 0
            };
            if remove_key {
                self.src300_agg.remove(&src_id);
            }
        }
    }

    pub(crate) fn parse_flow_event(&mut self, ev: &Value) -> Option<FlowTcpParsed> {
        let fid = flow_id_py(ev);
        let (tcp_stats, has_tcp) = tcp_stats_from_flow_embedded(ev);

        let ts = crate::extractor::ts_from_ev(ev);

        let src = ev
            .get("src_ip")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "UNKNOWN".to_string());
        let dst = ev
            .get("dest_ip")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "UNKNOWN".to_string());
        let dst_port = ev.get("dest_port").map(safe_int).unwrap_or(0);

        let flow_obj = ev.get("flow").and_then(|x| x.as_object())?;
        let dur = flow_obj
            .get("age")
            .map(|v| safe_float(v))
            .unwrap_or(0.0)
            .max(0.0);
        let end = ts + dur;

        let fwd = flow_obj
            .get("bytes_toserver")
            .map(|v| safe_int(v) as f64)
            .unwrap_or(0.0);
        let rev = flow_obj
            .get("bytes_toclient")
            .map(|v| safe_int(v) as f64)
            .unwrap_or(0.0);
        let total = fwd + rev;

        let src_id = self.interner.intern(src.as_str());
        let dst_id = self.interner.intern(dst.as_str());

        let rec = Rec {
            ts,
            src_id,
            dst_id,
            dst_port,
            dur,
            fwd,
            rev,
            total,
            syn_count: tcp_stats.syn_count as i64 as f64,
            ack_count: tcp_stats.ack_count as i64 as f64,
            rst_count: tcp_stats.rst_count as i64 as f64,
            fin_count: tcp_stats.fin_count as i64 as f64,
            total_packets: tcp_stats.total_packets,
        };
        Some(FlowTcpParsed {
            ts,
            end,
            flow_id: fid,
            rec,
            has_tcp,
            fwd,
            rev,
            src_id,
            dst_id,
            dst_port,
        })
    }

    pub(crate) fn prune_for_parsed(&mut self, p: &FlowTcpParsed) {
        let src_id = p.src_id;
        let dst_id = p.dst_id;
        let dst_port = p.dst_port;
        let ts = p.ts;
        // Must run before any `entry()` borrows — `prune_src300_deque_and_agg` needs `&mut self` wholly.
        self.prune_src300_deque_and_agg(src_id, ts);

        let q_src10 = self.src_10.entry(src_id).or_insert_with(VecDeque::new);
        let q_src60 = self.src_60.entry(src_id).or_insert_with(VecDeque::new);
        let q_src24h = self.src_24h.entry(src_id).or_insert_with(VecDeque::new);

        let q_dst10 = self.dst_10.entry(dst_id).or_insert_with(VecDeque::new);
        let q_dst60 = self.dst_60.entry(dst_id).or_insert_with(VecDeque::new);

        let q_sdp300 = self
            .srcdst_300
            .entry((src_id, dst_id))
            .or_insert_with(VecDeque::new);
        let q_sdp24h = self
            .srcdst_24h
            .entry((src_id, dst_id))
            .or_insert_with(VecDeque::new);

        let sact = self.src_active_10.entry(src_id).or_insert_with(VecDeque::new);
        let dact = self.dst_active_10.entry(dst_id).or_insert_with(VecDeque::new);
        let pact = self
            .dst_port_active_10
            .entry((dst_id, dst_port))
            .or_insert_with(VecDeque::new);

        prune_q_capped(q_src10, ts, W10);
        if prune_q_capped_pop_count(q_src60, ts, W60) > 0 {
            self.iat_online_src60.remove(&src_id);
        }
        prune_q_capped(q_src24h, ts, W24H);
        prune_q_capped(q_dst10, ts, W10);
        prune_q_capped(q_dst60, ts, W60);
        if prune_q_capped_pop_count(q_sdp300, ts, W300) > 0 {
            self.iat_online_srcdst300.remove(&(src_id, dst_id));
        }
        prune_q_capped(q_sdp24h, ts, W24H);
        prune_active(sact, ts, W10);
        prune_active(dact, ts, W10);
        prune_active(pact, ts, W10);
    }

    pub(crate) fn compute_features_for_parsed(&mut self, p: &FlowTcpParsed) -> [f64; DEV_FEATURE_COUNT] {
        let ts = p.ts;
        let src_id = p.src_id;
        let dst_id = p.dst_id;
        let dst_port = p.dst_port;
        let fwd = p.fwd;
        let rev = p.rev;
        let has_tcp = p.has_tcp;
        let q_src10 = self.src_10.entry(src_id).or_insert_with(VecDeque::new);
        let q_src60 = self.src_60.entry(src_id).or_insert_with(VecDeque::new);
        let q_src300 = self.src_300.get(&src_id);
        let q_src24h = self.src_24h.entry(src_id).or_insert_with(VecDeque::new);
        let q_dst10 = self.dst_10.entry(dst_id).or_insert_with(VecDeque::new);
        let q_dst60 = self.dst_60.entry(dst_id).or_insert_with(VecDeque::new);
        let q_sdp300 = self
            .srcdst_300
            .entry((src_id, dst_id))
            .or_insert_with(VecDeque::new);
        let q_sdp24h = self
            .srcdst_24h
            .entry((src_id, dst_id))
            .or_insert_with(VecDeque::new);
        let sact = self.src_active_10.entry(src_id).or_insert_with(VecDeque::new);
        let dact = self.dst_active_10.entry(dst_id).or_insert_with(VecDeque::new);
        let pact = self
            .dst_port_active_10
            .entry((dst_id, dst_port))
            .or_insert_with(VecDeque::new);
        let len_src10 = q_src10.len() as f64;
        let len_src60 = q_src60.len() as f64;
        let len_src300 = q_src300.map(|q| q.len()).unwrap_or(0) as f64;
        let len_src24h = q_src24h.len() as f64;
        let len_dst10 = q_dst10.len() as f64;
        let len_sdp24h = q_sdp24h.len() as f64;

        let flow_rate_src_10s = len_src10 / W10;
        let flow_rate_src_60s = len_src60 / W60;
        let flow_rate_dst_10s = len_dst10 / W10;
        let flow_rate_src_300 = len_src300 / W300;
        let rate_ratio_src_10s_60s = flow_rate_src_10s / (flow_rate_src_60s + EPS);
        let rate_ratio_src_60s_300s = flow_rate_src_60s / (flow_rate_src_300 + EPS);

        let concurrent_flows_src_10s = {
            let mut c = 0i64;
            for (st, en) in sact.iter() {
                if *st <= ts && ts <= *en {
                    c += 1;
                }
            }
            c as f64
        };
        let concurrent_flows_dst_10s = {
            let mut c = 0i64;
            for (st, en) in dact.iter() {
                if *st <= ts && ts <= *en {
                    c += 1;
                }
            }
            c as f64
        };
        let concurrent_flows_per_dst_port_10s = {
            let mut c = 0i64;
            for (st, en) in pact.iter() {
                if *st <= ts && ts <= *en {
                    c += 1;
                }
            }
            c as f64
        };

        self.scratch_uniq_src.clear();
        let mut src_contrib_dst60 = 0i64;
        for r in q_dst60.iter() {
            self.scratch_uniq_src.insert(r.src_id);
            if r.src_id == src_id {
                src_contrib_dst60 += 1;
            }
        }
        let unique_src_ips_by_dst_60s = self.scratch_uniq_src.len() as f64;

        self.scratch_uniq_src.clear();
        for r in q_dst10.iter() {
            self.scratch_uniq_src.insert(r.src_id);
        }
        let dst_ip_unique_src_ips_10s = self.scratch_uniq_src.len() as f64;

        let n300 = q_src300.map(|q| q.len()).unwrap_or(0);
        let n300_f = n300 as f64;
        let g300 = self.src300_agg.get(&src_id);
        debug_assert!(n300 == 0 || g300.map(|a| a.total) == Some(n300));

        let new_dst_ip_ratio_src_300s = if n300 > 1 {
            g300
                .map(|a| a.dst_counts.len() as f64 / n300_f)
                .unwrap_or(0.0)
        } else {
            0.0
        };
        let new_dst_ips_per_sec = if n300 > 1 {
            g300
                .map(|a| a.dst_counts.len() as f64 / W300)
                .unwrap_or(0.0)
        } else {
            0.0
        };
        let new_dst_port_ratio_src_300s = if n300 > 1 {
            g300
                .map(|a| a.port_counts.len() as f64 / n300_f)
                .unwrap_or(0.0)
        } else {
            0.0
        };
        let new_dst_ports_per_sec = if n300 > 1 {
            g300
                .map(|a| a.port_counts.len() as f64 / W300)
                .unwrap_or(0.0)
        } else {
            0.0
        };

        let dst_ip_entropy_src_300s = g300
            .map(|a| entropy_from_dst_counts_map(&a.dst_counts))
            .unwrap_or(0.0);
        let dst_port_entropy_src_300s = g300
            .map(|a| entropy_from_port_counts_map(&a.port_counts))
            .unwrap_or(0.0);

        // `iat_cv_src_60s`: online append-order IAT stats (see module doc).
        let mut syn60 = 0.0f64;
        let mut ack60 = 0.0f64;
        let mut rst60 = 0.0f64;
        let mut fin60 = 0.0f64;
        let mut tcp_pkts60 = 0.0f64;
        let mut small_resp_c = 0i64;
        for r in q_src60.iter() {
            syn60 += r.syn_count;
            ack60 += r.ack_count;
            rst60 += r.rst_count;
            fin60 += r.fin_count;
            tcp_pkts60 += r.total_packets;
            if r.rev < THETA_SMALL && r.fwd > THETA_REQ {
                small_resp_c += 1;
            }
        }
        let iat_cv_src_60s = self
            .iat_online_src60
            .get(&src_id)
            .map(|s| s.cv())
            .unwrap_or(0.0);
        let small_response_ratio_src_60s = if len_src60 > 0.0 {
            small_resp_c as f64 / len_src60
        } else {
            0.0
        };

        let iat_cv_srcdst_300s = self
            .iat_online_srcdst300
            .get(&(src_id, dst_id))
            .map(|s| s.cv())
            .unwrap_or(0.0);
        let iat_autocorr_srcdst_300s = self
            .iat_online_srcdst300
            .get(&(src_id, dst_id))
            .map(|s| s.autocorr_lag1())
            .unwrap_or(0.0);

        let bytes_ratio_fwd_rev = fwd / (rev + 1.0);

        let short_flow_ratio_src_300s = if n300 == 0 {
            0.0
        } else {
            g300
                .map(|a| a.short_count as f64 / (n300_f + EPS))
                .unwrap_or(0.0)
        };

        let avg_bytes_per_flow_src_300s = if n300 == 0 {
            0.0
        } else {
            g300
                .map(|a| a.sum_total / (n300_f + EPS))
                .unwrap_or(0.0)
        };

        let bytes_per_flow_srcdst = if q_sdp24h.is_empty() {
            0.0
        } else {
            let mut sum_b = 0.0f64;
            for r in q_sdp24h.iter() {
                sum_b += r.total;
            }
            sum_b / (len_sdp24h + EPS)
        };

        let connection_reuse_ratio_srcdst = len_sdp24h / (len_src24h + EPS);

        let flow_size_mode_src_300s = if n300 == 0 {
            0.0
        } else if let (Some(q), Some(a)) = (q_src300, g300) {
            flow_size_mode_deque_tiebreak(q, &a.size_bins)
        } else {
            0.0
        };

        let retry_rate_same_dstport_300s = if n300 == 0 {
            0.0
        } else {
            let rep_sum = g300
                .map(|a| {
                    a.pair_counts
                        .values()
                        .filter(|v| **v > 1)
                        .map(|v| (*v - 1) as f64)
                        .sum::<f64>()
                })
                .unwrap_or(0.0);
            rep_sum / (n300_f + EPS)
        };

        let retry_rate_same_dstip_300s = if n300 == 0 {
            0.0
        } else {
            let rep_sum = g300
                .map(|a| {
                    a.dst_counts
                        .values()
                        .filter(|v| **v > 1)
                        .map(|v| (*v - 1) as f64)
                        .sum::<f64>()
                })
                .unwrap_or(0.0);
            rep_sum / (n300_f + EPS)
        };

        let dst_port_reuse_ratio_src_300s = if n300 == 0 {
            0.0
        } else {
            g300
                .map(|a| a.max_port_freq as f64 / (n300_f + EPS))
                .unwrap_or(0.0)
        };

        let syn_heavy_ratio_src_60s = syn60 / (tcp_pkts60 + EPS);
        let syn_to_established_ratio = syn60 / (ack60 + EPS);
        let rst_ratio_src_60s = rst60 / (len_src60 + EPS);
        let rst_to_syn_ratio_src_60s = rst60 / (syn60 + EPS);

        let tcp_flag_entropy_src_60s = {
            let counts = [syn60 as i64, ack60 as i64, rst60 as i64, fin60 as i64];
            let n: f64 = counts.iter().map(|&c| c as f64).sum();
            if n <= 0.0 {
                0.0
            } else {
                let mut e = 0.0;
                for &c in &counts {
                    if c <= 0 {
                        continue;
                    }
                    let p = (c as f64) / n;
                    e -= p * (p + EPS).log2();
                }
                e
            }
        };

        let ack_presence_ratio = if n300 == 0 {
            0.0
        } else {
            g300
                .map(|a| a.ack_presence as f64 / (n300_f + EPS))
                .unwrap_or(0.0)
        };

        let incomplete_flow_duration_ratio_src_300s = if n300 == 0 {
            0.0
        } else {
            g300
                .map(|a| a.incomplete_count as f64 / (n300_f + EPS))
                .unwrap_or(0.0)
        };

        let low_data_rate_long_flow_ratio_src_300s = if n300 == 0 {
            0.0
        } else {
            g300
                .map(|a| a.low_data_count as f64 / (n300_f + EPS))
                .unwrap_or(0.0)
        };

        let src_contribution_to_dst_ratio_60s = if q_dst60.is_empty() {
            0.0
        } else {
            src_contrib_dst60 as f64 / (q_dst60.len() as f64 + EPS)
        };

        self.scratch_dst60_src_counts.clear();
        for r in q_dst60.iter() {
            *self.scratch_dst60_src_counts.entry(r.src_id).or_insert(0) += 1;
        }
        let dst_src_ip_entropy_60s = entropy_from_dst_counts_map(&self.scratch_dst60_src_counts);
        let avg_flow_per_src_to_dst_10s = len_dst10 / (dst_ip_unique_src_ips_10s + EPS);

        let n_src60_usize = q_src60.len();
        let rst_micro_flow_ratio_src_60s;
        let single_dst_port_focus_src_60s;
        let mut rst_after_ack_ratio_src_60s;
        let iat_regularity_src_60s;

        if n_src60_usize < 5 {
            rst_micro_flow_ratio_src_60s = 0.0;
            single_dst_port_focus_src_60s = 0.0;
            rst_after_ack_ratio_src_60s = 0.0;
            iat_regularity_src_60s = 0.0;
        } else {
            let n_sf = len_src60;
            let mut rst_micro_c = 0i64;
            let mut c_rst_ack = 0i64;
            for r in q_src60.iter() {
                if r.rst_count > 0.0
                    && r.dur <= 0.5
                    && r.total <= 150.0
                    && r.fwd <= 120.0
                    && r.rev <= 120.0
                {
                    rst_micro_c += 1;
                }
                if r.ack_count > 0.0 && r.rst_count > 0.0 {
                    c_rst_ack += 1;
                }
            }
            self.scratch_src60_port_counts.clear();
            for r in q_src60.iter() {
                *self
                    .scratch_src60_port_counts
                    .entry(r.dst_port)
                    .or_insert(0) += 1;
            }
            let max_port_count = self
                .scratch_src60_port_counts
                .values()
                .copied()
                .max()
                .unwrap_or(0);
            rst_micro_flow_ratio_src_60s = rst_micro_c as f64 / (n_sf + EPS);
            single_dst_port_focus_src_60s = max_port_count as f64 / (n_sf + EPS);
            rst_after_ack_ratio_src_60s = c_rst_ack as f64 / (n_sf + EPS);
            iat_regularity_src_60s = if iat_cv_src_60s > 0.0 {
                1.0 / (iat_cv_src_60s + EPS)
            } else {
                0.0
            };
        }

        if has_tcp == 0.0 {
            rst_after_ack_ratio_src_60s = 0.0;
        }

        let mut f = [0f64; DEV_FEATURE_COUNT];
        f[0] = flow_rate_src_10s;
        f[1] = flow_rate_src_60s;
        f[2] = flow_rate_dst_10s;
        f[3] = rate_ratio_src_10s_60s;
        f[4] = rate_ratio_src_60s_300s;
        f[5] = concurrent_flows_src_10s;
        f[6] = concurrent_flows_dst_10s;
        f[7] = concurrent_flows_per_dst_port_10s;
        f[8] = unique_src_ips_by_dst_60s;
        f[9] = dst_ip_unique_src_ips_10s;
        f[10] = new_dst_ip_ratio_src_300s;
        f[11] = new_dst_port_ratio_src_300s;
        f[12] = new_dst_ips_per_sec;
        f[13] = new_dst_ports_per_sec;
        f[14] = dst_ip_entropy_src_300s;
        f[15] = dst_port_entropy_src_300s;
        f[16] = iat_cv_src_60s;
        f[17] = iat_cv_srcdst_300s;
        f[18] = iat_autocorr_srcdst_300s;
        f[19] = bytes_ratio_fwd_rev;
        f[20] = short_flow_ratio_src_300s;
        f[21] = avg_bytes_per_flow_src_300s;
        f[22] = bytes_per_flow_srcdst;
        f[23] = connection_reuse_ratio_srcdst;
        f[24] = flow_size_mode_src_300s;
        f[25] = retry_rate_same_dstport_300s;
        f[26] = retry_rate_same_dstip_300s;
        f[27] = dst_port_reuse_ratio_src_300s;
        f[28] = syn_heavy_ratio_src_60s;
        f[29] = syn_to_established_ratio;
        f[30] = rst_ratio_src_60s;
        f[31] = rst_to_syn_ratio_src_60s;
        f[32] = tcp_flag_entropy_src_60s;
        f[33] = ack_presence_ratio;
        f[34] = small_response_ratio_src_60s;
        f[35] = incomplete_flow_duration_ratio_src_300s;
        f[36] = low_data_rate_long_flow_ratio_src_300s;
        f[37] = src_contribution_to_dst_ratio_60s;
        f[38] = rst_micro_flow_ratio_src_60s;
        f[39] = single_dst_port_focus_src_60s;
        f[40] = rst_after_ack_ratio_src_60s;
        f[41] = dst_src_ip_entropy_60s;
        f[42] = avg_flow_per_src_to_dst_10s;
        f[43] = iat_regularity_src_60s;
        f[44] = has_tcp;
        f
    }

    pub(crate) fn append_parsed_to_windows(&mut self, p: &FlowTcpParsed) {
        let src_id = p.src_id;
        let dst_id = p.dst_id;
        let dst_port = p.dst_port;
        let ts = p.ts;
        let end = p.end;
        let rec = p.rec;
        let q_src10 = self.src_10.entry(src_id).or_insert_with(VecDeque::new);
        let q_src60 = self.src_60.entry(src_id).or_insert_with(VecDeque::new);
        let q_src300 = self.src_300.entry(src_id).or_insert_with(VecDeque::new);
        let q_src24h = self.src_24h.entry(src_id).or_insert_with(VecDeque::new);
        let q_dst10 = self.dst_10.entry(dst_id).or_insert_with(VecDeque::new);
        let q_dst60 = self.dst_60.entry(dst_id).or_insert_with(VecDeque::new);
        let q_sdp300 = self
            .srcdst_300
            .entry((src_id, dst_id))
            .or_insert_with(VecDeque::new);
        let q_sdp24h = self
            .srcdst_24h
            .entry((src_id, dst_id))
            .or_insert_with(VecDeque::new);
        let sact = self.src_active_10.entry(src_id).or_insert_with(VecDeque::new);
        let dact = self.dst_active_10.entry(dst_id).or_insert_with(VecDeque::new);
        let pact = self
            .dst_port_active_10
            .entry((dst_id, dst_port))
            .or_insert_with(VecDeque::new);
        q_src10.push_back(rec);
        if let Some(prev) = q_src60.back() {
            let dt = ts - prev.ts;
            if dt.is_finite() {
                self.iat_online_src60
                    .entry(src_id)
                    .or_default()
                    .observe_gap_append_order(dt);
            }
        }
        q_src60.push_back(rec);
        q_src300.push_back(rec);
        self.src300_agg
            .entry(src_id)
            .or_insert_with(Src300Agg::default)
            .add_rec(&rec);
        q_src24h.push_back(rec);

        q_dst10.push_back(rec);
        q_dst60.push_back(rec);

        if let Some(prev) = q_sdp300.back() {
            let dt = ts - prev.ts;
            if dt.is_finite() {
                self.iat_online_srcdst300
                    .entry((src_id, dst_id))
                    .or_default()
                    .observe_gap_append_order(dt);
            }
        }
        q_sdp300.push_back(rec);
        q_sdp24h.push_back(rec);

        sact.push_back((ts, end));
        dact.push_back((ts, end));
        pact.push_back((ts, end));
    }

    pub(crate) fn apply_parsed_with_optional_features(
        &mut self,
        p: FlowTcpParsed,
        compute_features: bool,
    ) -> (f64, Option<[f64; DEV_FEATURE_COUNT]>) {
        self.prune_for_parsed(&p);
        let feats = if compute_features {
            let mut f = self.compute_features_for_parsed(&p);
            for v in f.iter_mut() {
                if !v.is_finite() {
                    *v = 0.0;
                }
            }
            debug_assert_eq!(f.len(), DEV_FEATURE_COUNT);
            debug_assert!(f.iter().all(|x| x.is_finite()));
            Some(f)
        } else {
            None
        };
        self.append_parsed_to_windows(&p);
        (p.ts, feats)
    }

    pub(crate) fn apply_flow_with_optional_features(
        &mut self,
        ev: &Value,
        compute_features: bool,
    ) -> Option<(f64, Option<[f64; DEV_FEATURE_COUNT]>)> {
        let p = self.parse_flow_event(ev)?;
        let (ts, feats) = self.apply_parsed_with_optional_features(p, compute_features);
        Some((ts, feats))
    }

    pub fn build_row_from_flow(&mut self, ev: &Value) -> (f64, [f64; DEV_FEATURE_COUNT]) {
        let (ts, f) = self
            .apply_flow_with_optional_features(ev, true)
            .expect("build_row_from_flow: flow object present");
        (
            ts,
            f.expect("build_row_from_flow: compute_features true"),
        )
    }
}

