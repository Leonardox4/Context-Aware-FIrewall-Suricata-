//! Native EVE JSONL ingest + feature extraction + label join + Parquet output.
//! Python orchestrates paths only; no per-line Python I/O for this path.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

use arrow::array::{ArrayRef, Float64Array, Int64Array, RecordBatch, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use csv::ReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;

use crate::extractor::{ExtractorCore, N_FEATURES};

/// Column order must match `ingestion/unified_behavioral_schema.UNIFIED_BEHAVIORAL_FEATURE_NAMES`.
const PARQUET_FEATURE_COLS: [&str; N_FEATURES] = [
    "flow_rate_src_10s",
    "flow_rate_src_60s",
    "flow_rate_dst_10s",
    "rate_ratio_src_10s_60s",
    "rate_ratio_src_60s_300s",
    "concurrent_flows_src_10s",
    "concurrent_flows_dst_10s",
    "concurrent_flows_per_dst_port_10s",
    "unique_src_ips_by_dst_60s",
    "dst_ip_unique_src_ips_10s",
    "new_dst_ip_ratio_src_300s",
    "new_dst_port_ratio_src_300s",
    "new_dst_ips_per_sec",
    "new_dst_ports_per_sec",
    "dst_ip_entropy_src_300s",
    "dst_port_entropy_src_300s",
    "iat_cv_src_60s",
    "iat_cv_srcdst_300s",
    "iat_autocorr_srcdst_300s",
    "bytes_ratio_fwd_rev",
    "short_flow_ratio_src_300s",
    "avg_bytes_per_flow_src_300s",
    "bytes_per_flow_srcdst",
    "connection_reuse_ratio_srcdst",
    "flow_size_mode_src_300s",
    "retry_rate_same_dstport_300s",
    "retry_rate_same_dstip_300s",
    "dst_port_reuse_ratio_src_300s",
    "syn_heavy_ratio_src_60s",
    "syn_to_established_ratio",
    "rst_ratio_src_60s",
    "rst_to_syn_ratio_src_60s",
    "tcp_flag_entropy_src_60s",
    "ack_presence_ratio",
    "small_response_ratio_src_60s",
    "incomplete_flow_duration_ratio_src_300s",
    "low_data_rate_long_flow_ratio_src_300s",
    "src_contribution_to_dst_ratio_60s",
    "rst_micro_flow_ratio_src_60s",
    "single_dst_port_focus_src_60s",
    "rst_after_ack_ratio_src_60s",
    "dst_src_ip_entropy_60s",
    "avg_flow_per_src_to_dst_10s",
    "iat_regularity_src_60s",
    "has_tcp",
];

/// Match `ingestion.identity_key.identity_key_from_strings` (flow_id preferred when valid).
#[inline]
fn identity_key_join(flow_id: &str, flow_key: &str) -> String {
    let fid = flow_id.trim();
    if !fid.is_empty() {
        let sl = fid.to_ascii_lowercase();
        if sl != "nan" && sl != "none" {
            return fid.to_string();
        }
    }
    flow_key.trim().to_string()
}

/// Match `SanityCheck` + `DEFAULT_FILL` / `FEATURE_BOUNDS` in Python (by column index).
fn sanitize_feature_row(f: &mut [f64; N_FEATURES]) {
    // Minimal sanitization:
    // - Default fill: replace NaN/Inf with 0.0
    // - Bounds/clamping is handled in Python during dataset creation.
    for x in f.iter_mut() {
        if !x.is_finite() {
            *x = 0.0;
        }
    }
}

fn parse_binary_label_cell(s: &str) -> Result<i64, String> {
    let t = s.trim().to_ascii_lowercase();
    if matches!(
        t.as_str(),
        "0" | "0.0" | "false" | "no" | "benign" | "normal" | "negative" | "clean" | "safe"
    ) {
        return Ok(0);
    }
    if matches!(
        t.as_str(),
        "1"
            | "1.0"
            | "true"
            | "yes"
            | "attack"
            | "malicious"
            | "malware"
            | "positive"
            | "bad"
    ) {
        return Ok(1);
    }
    t.parse::<f64>()
        .map(|x| if x != 0.0 { 1 } else { 0 })
        .map_err(|_| format!("unrecognized binary_label: {s:?}"))
}

/// Load labels from CSV with headers `identity_key` and `binary_label`.
/// Optional `attack_subclass` when `want_subclass` (last row wins for duplicate keys).
pub fn load_labels_csv(
    path: &Path,
    want_subclass: bool,
) -> Result<(HashMap<String, i64>, HashMap<String, String>), String> {
    let f = File::open(path).map_err(|e| format!("open labels {path:?}: {e}"))?;
    let mut rdr = ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(f);
    let headers = rdr
        .headers()
        .map_err(|e| format!("labels csv headers: {e}"))?
        .clone();
    let pos_ik = headers
        .iter()
        .position(|h| h.trim().eq_ignore_ascii_case("identity_key"))
        .ok_or_else(|| "labels CSV must contain column 'identity_key'".to_string())?;
    let pos_bl = headers
        .iter()
        .position(|h| h.trim().eq_ignore_ascii_case("binary_label"))
        .ok_or_else(|| "labels CSV must contain column 'binary_label'".to_string())?;
    let pos_sub = if want_subclass {
        Some(
            headers
                .iter()
                .position(|h| h.trim().eq_ignore_ascii_case("attack_subclass"))
                .ok_or_else(|| {
                    "labels CSV must contain column 'attack_subclass' when use_subclass=true"
                        .to_string()
                })?,
        )
    } else {
        None
    };

    let mut labels: HashMap<String, i64> = HashMap::new();
    let mut subclasses: HashMap<String, String> = HashMap::new();

    for rec in rdr.records() {
        let rec = rec.map_err(|e| format!("labels csv row: {e}"))?;
        let ik = rec
            .get(pos_ik)
            .ok_or_else(|| "short row (identity_key)".to_string())?
            .trim()
            .to_string();
        if ik.is_empty() {
            continue;
        }
        let bl = rec
            .get(pos_bl)
            .ok_or_else(|| "short row (binary_label)".to_string())?;
        let y = parse_binary_label_cell(bl)?;
        labels.insert(ik.clone(), y);
        if let Some(ps) = pos_sub {
            let sc = rec.get(ps).unwrap_or("").trim().to_string();
            subclasses.insert(ik, sc);
        }
    }
    if labels.is_empty() {
        return Err("no label rows loaded".into());
    }
    Ok((labels, subclasses))
}

struct OutColumns {
    feat: Vec<Vec<f64>>,
    binary_label: Vec<i64>,
    identity_key: Vec<String>,
    flow_key: Vec<String>,
    attack_subclass: Vec<String>,
    use_subclass: bool,
}

impl OutColumns {
    fn new(cap: usize, use_subclass: bool) -> Self {
        let feat: Vec<Vec<f64>> = (0..N_FEATURES).map(|_| Vec::with_capacity(cap)).collect();
        Self {
            feat,
            binary_label: Vec::with_capacity(cap),
            identity_key: Vec::with_capacity(cap),
            flow_key: Vec::with_capacity(cap),
            attack_subclass: if use_subclass {
                Vec::with_capacity(cap)
            } else {
                Vec::new()
            },
            use_subclass,
        }
    }

    fn clear(&mut self) {
        for c in &mut self.feat {
            c.clear();
        }
        self.binary_label.clear();
        self.identity_key.clear();
        self.flow_key.clear();
        self.attack_subclass.clear();
    }

    fn len(&self) -> usize {
        self.binary_label.len()
    }

    fn push_row(
        &mut self,
        row: &[f64; N_FEATURES],
        y: i64,
        ik: String,
        fk: String,
        sub: String,
    ) {
        for (i, v) in row.iter().enumerate() {
            self.feat[i].push(*v);
        }
        self.binary_label.push(y);
        self.identity_key.push(ik);
        self.flow_key.push(fk);
        if self.use_subclass {
            self.attack_subclass.push(sub);
        }
    }
}

fn build_schema(use_subclass: bool) -> Schema {
    let mut fields: Vec<Field> = PARQUET_FEATURE_COLS
        .iter()
        .map(|n| Field::new(*n, DataType::Float64, false))
        .collect();
    fields.push(Field::new("binary_label", DataType::Int64, false));
    if use_subclass {
        fields.push(Field::new("attack_subclass", DataType::Utf8, false));
    }
    fields.push(Field::new("identity_key", DataType::Utf8, false));
    fields.push(Field::new("flow_key", DataType::Utf8, false));
    Schema::new(fields)
}

fn write_batch(
    schema: &Arc<Schema>,
    writer: &mut ArrowWriter<File>,
    buf: &mut OutColumns,
) -> Result<(), String> {
    if buf.len() == 0 {
        return Ok(());
    }
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(N_FEATURES + 4);
    for i in 0..N_FEATURES {
        let v = std::mem::take(&mut buf.feat[i]);
        arrays.push(Arc::new(Float64Array::from(v)) as ArrayRef);
    }
    arrays.push(Arc::new(Int64Array::from(std::mem::take(
        &mut buf.binary_label,
    ))) as ArrayRef);
    if buf.use_subclass {
        let s = std::mem::take(&mut buf.attack_subclass);
        arrays.push(Arc::new(StringArray::from_iter_values(s.into_iter())) as ArrayRef);
    }
    let ik = std::mem::take(&mut buf.identity_key);
    let fk = std::mem::take(&mut buf.flow_key);
    arrays.push(Arc::new(StringArray::from_iter_values(ik.into_iter())) as ArrayRef);
    arrays.push(Arc::new(StringArray::from_iter_values(fk.into_iter())) as ArrayRef);

    let batch = RecordBatch::try_new(schema.clone(), arrays).map_err(|e| format!("record batch: {e}"))?;
    writer
        .write(&batch)
        .map_err(|e| format!("parquet write: {e}"))?;
    buf.clear();
    Ok(())
}

const READ_BUF_CAP: usize = 8 * 1024 * 1024;
const LINE_BATCH: usize = 65_536;
const PARQUET_FLUSH_ROWS: usize = 65_536;

/// Stream `eve_jsonl`, extract features, join to `labels`, write `out_parquet`.
/// `labels` CSV must be pre-normalized (Python `_prepare_labels_csv` + export `identity_key`, `binary_label`, …).
pub fn run_join_parquet(
    eve_jsonl: &Path,
    labels_csv: &Path,
    out_parquet: &Path,
    use_subclass: bool,
) -> Result<u64, String> {
    let (labels, subclasses) = load_labels_csv(labels_csv, use_subclass)?;
    let schema = Arc::new(build_schema(use_subclass));
    let file = File::create(out_parquet).map_err(|e| format!("create out parquet: {e}"))?;
    let props = WriterProperties::builder().build();
    let mut writer =
        ArrowWriter::try_new(file, schema.clone(), Some(props)).map_err(|e| format!("writer: {e}"))?;

    let mut engine = ExtractorCore::new();
    let label_keys: HashSet<String> = labels.keys().cloned().collect();
    engine.set_label_identity_keys(Some(label_keys));
    let mut matched_total: u64 = 0;

    let eve_file = File::open(eve_jsonl).map_err(|e| format!("open eve: {e}"))?;
    let mut reader = BufReader::with_capacity(READ_BUF_CAP, eve_file);
    let mut line_batch: Vec<String> = Vec::with_capacity(LINE_BATCH);
    let mut line_owned = String::new();

    let mut out = OutColumns::new(PARQUET_FLUSH_ROWS, use_subclass);

    loop {
        line_owned.clear();
        let n = reader
            .read_line(&mut line_owned)
            .map_err(|e| format!("read eve line: {e}"))?;
        if n == 0 {
            break;
        }
        let t = line_owned.trim_end();
        if t.is_empty() {
            continue;
        }
        line_batch.push(t.to_string());

        if line_batch.len() >= LINE_BATCH {
            matched_total += process_line_batch_join(
                &mut engine,
                &line_batch,
                &labels,
                &subclasses,
                use_subclass,
                &mut out,
                &schema,
                &mut writer,
            )?;
            line_batch.clear();
        }
    }
    if !line_batch.is_empty() {
        matched_total += process_line_batch_join(
            &mut engine,
            &line_batch,
            &labels,
            &subclasses,
            use_subclass,
            &mut out,
            &schema,
            &mut writer,
        )?;
    }

    write_batch(&schema, &mut writer, &mut out)?;
    writer.close().map_err(|e| format!("parquet close: {e}"))?;
    Ok(matched_total)
}

#[allow(clippy::too_many_arguments)]
fn process_line_batch_join(
    engine: &mut ExtractorCore,
    lines: &[String],
    labels: &HashMap<String, i64>,
    subclasses: &HashMap<String, String>,
    use_subclass: bool,
    out: &mut OutColumns,
    schema: &Arc<Schema>,
    writer: &mut ArrowWriter<File>,
) -> Result<u64, String> {
    let (is_flow, feat_idx, flow_ids, flow_keys, feat_blob) =
        engine.process_line_batch(lines, false);

    let n_lines = lines.len();
    if is_flow.len() != n_lines || feat_idx.len() != n_lines {
        return Err("rust batch length mismatch".into());
    }
    let n_dense = flow_ids.len();
    let expect_bytes = n_dense * N_FEATURES * 8;
    if feat_blob.len() != expect_bytes {
        return Err(format!(
            "feat_blob size {} expected {}",
            feat_blob.len(),
            expect_bytes
        ));
    }

    let mut matched: u64 = 0;

    for i in 0..n_lines {
        let j = feat_idx[i];
        if j < 0 {
            continue;
        }
        let ju = j as usize;
        if ju >= n_dense {
            return Err("feat_idx out of range".into());
        }
        let fid = &flow_ids[ju];
        let fk = &flow_keys[ju];
        let ik = identity_key_join(fid, fk);
        let Some(&y) = labels.get(&ik) else {
            continue;
        };
        let mut row = [0f64; N_FEATURES];
        let base = ju * N_FEATURES * 8;
        for k in 0..N_FEATURES {
            let o = base + k * 8;
            row[k] = f64::from_le_bytes(feat_blob[o..o + 8].try_into().unwrap());
        }
        sanitize_feature_row(&mut row);
        let sub = if use_subclass {
            subclasses.get(&ik).cloned().unwrap_or_default()
        } else {
            String::new()
        };
        out.push_row(&row, y, ik, fk.clone(), sub);
        matched += 1;
        if out.len() >= PARQUET_FLUSH_ROWS {
            write_batch(schema, writer, out)?;
        }
    }

    Ok(matched)
}
