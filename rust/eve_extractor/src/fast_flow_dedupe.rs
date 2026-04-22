//! Cheap scan of a JSONL line to skip **duplicate** Suricata `flow` events before full serde parse.
//! Must stay conservative: on any doubt, return `false` and let the normal parser run.

use std::collections::HashSet;

#[inline]
fn line_looks_like_suricata_flow_event(line: &str) -> bool {
    line.contains("\"event_type\":\"flow\"")
        || line.contains("\"event_type\": \"flow\"")
        || line.contains("\"event_type\" : \"flow\"")
}

/// More than one `flow_id` key on the line → ambiguous (nested / odd exports); fall back to full parse.
#[inline]
fn single_flow_id_key(line: &str) -> bool {
    line.match_indices("\"flow_id\"").count() == 1
}

/// Parse a top-level JSON string or numeric token starting at `s` (first char is `"` or digit/`-`).
/// Normalization must match `extractor::flow_id_string_from_ev` for common Suricata exports.
fn parse_flow_id_value(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }
    match b[0] {
        b'"' => {
            let mut i = 1usize;
            let mut out = Vec::new();
            while i < b.len() {
                match b[i] {
                    b'"' => {
                        let t = String::from_utf8_lossy(&out);
                        let t = t.trim();
                        if t.is_empty() {
                            return None;
                        }
                        let sl = t.to_ascii_lowercase();
                        if sl == "nan" || sl == "none" {
                            return None;
                        }
                        return Some(t.to_string());
                    }
                    b'\\' => {
                        i += 1;
                        if i >= b.len() {
                            return None;
                        }
                        match b[i] {
                            b'"' | b'\\' | b'/' => out.push(b[i]),
                            b'b' => out.push(0x08),
                            b'f' => out.push(0x0c),
                            b'n' => out.push(b'\n'),
                            b'r' => out.push(b'\r'),
                            b't' => out.push(b'\t'),
                            b'u' => return None, // could match `flow_id_string_from_ev`; skip fast path
                            _ => return None,
                        }
                        i += 1;
                    }
                    _ => {
                        out.push(b[i]);
                        i += 1;
                    }
                }
            }
            None
        }
        b'0'..=b'9' | b'-' => {
            let mut i = 0usize;
            if b[0] == b'-' {
                i = 1;
            }
            let start = i;
            while i < b.len()
                && (b[i].is_ascii_digit()
                    || b[i] == b'.'
                    || b[i] == b'e'
                    || b[i] == b'E'
                    || b[i] == b'+'
                    || b[i] == b'-')
            {
                i += 1;
            }
            if i == start || (b[0] == b'-' && i == 1) {
                return None;
            }
            let num = s.get(..i)?;
            let sl = num.trim().to_ascii_lowercase();
            if sl == "nan" || sl == "none" {
                return None;
            }
            Some(num.to_string())
        }
        _ => None,
    }
}

/// Walk `line` for `"flow_id"` and return the value if parsable without full JSON.
pub fn scan_top_level_flow_id(line: &str) -> Option<String> {
    if !single_flow_id_key(line) {
        return None;
    }
    let key = "\"flow_id\"";
    let abs = line.find(key)?;
    // Avoid matching a `"flow_id"` substring inside a late JSON string value; Suricata puts
    // top-level `flow_id` near the start of the line.
    if abs > 2048 {
        return None;
    }
    let mut j = abs + key.len();
    let b = line.as_bytes();
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    if j >= b.len() || b[j] != b':' {
        return None;
    }
    j += 1;
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    if j >= b.len() {
        return None;
    }
    let rest = line.get(j..)?;
    parse_flow_id_value(rest)
}

/// If this line is a flow event and `flow_id` was already emitted once, skip full JSON parse.
#[inline]
pub fn skip_duplicate_flow_before_parse(line_trim: &str, seen: &HashSet<String>) -> bool {
    if !line_looks_like_suricata_flow_event(line_trim) {
        return false;
    }
    let Some(fid) = scan_top_level_flow_id(line_trim) else {
        return false;
    };
    seen.contains(&fid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_numeric_flow_id() {
        let line = r#"{"event_type":"flow","flow_id":12345,"src_ip":"1.1.1.1"}"#;
        assert_eq!(scan_top_level_flow_id(line).as_deref(), Some("12345"));
    }

    #[test]
    fn scan_string_flow_id() {
        let line = r#"{"flow_id":"abc-def","event_type":"flow"}"#;
        assert_eq!(scan_top_level_flow_id(line).as_deref(), Some("abc-def"));
    }

    #[test]
    fn skip_dup_when_seen() {
        let mut seen = HashSet::new();
        let line = r#"{"event_type":"flow","flow_id":99,"flow":{"age":1.0}}"#;
        assert!(!skip_duplicate_flow_before_parse(line, &seen));
        seen.insert("99".to_string());
        assert!(skip_duplicate_flow_before_parse(line, &seen));
    }

    #[test]
    fn non_flow_never_skips() {
        let seen = HashSet::from(["1".to_string()]);
        let line = r#"{"event_type":"dns","flow_id":1}"#;
        assert!(!skip_duplicate_flow_before_parse(line, &seen));
    }

    #[test]
    fn two_flow_id_keys_ambiguous() {
        let line = r#"{"event_type":"flow","flow_id":1,"flow":{"flow_id":2}}"#;
        assert!(scan_top_level_flow_id(line).is_none());
    }
}
