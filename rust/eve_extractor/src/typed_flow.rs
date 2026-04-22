//! Typed EVE JSONL parsing: deserialize into a narrow struct so unknown **top-level** keys are
//! ignored (no `Value` allocation for them). Nested `flow` / `tcp` / … keep full maps so existing
//! helpers (`ts_from_ev`, `tcp_mask_from_ev`, …) stay unchanged.

use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct TypedSuricataLine {
    #[serde(rename = "event_type")]
    pub event_type: Option<Value>,
    pub src_ip: Option<Value>,
    #[serde(rename = "dest_ip")]
    pub dest_ip: Option<Value>,
    #[serde(rename = "src_port")]
    pub src_port: Option<Value>,
    #[serde(rename = "dest_port")]
    pub dest_port: Option<Value>,
    pub proto: Option<Value>,
    pub flow: Option<Map<String, Value>>,
    pub tcp: Option<Map<String, Value>>,
    pub tls: Option<Map<String, Value>>,
    pub ip: Option<Map<String, Value>>,
    pub inner: Option<Map<String, Value>>,
    pub app_proto: Option<Value>,
    pub timestamp: Option<Value>,
    #[serde(rename = "flow_id")]
    pub flow_id: Option<Value>,
}

impl Default for TypedSuricataLine {
    fn default() -> Self {
        Self {
            event_type: None,
            src_ip: None,
            dest_ip: None,
            src_port: None,
            dest_port: None,
            proto: None,
            flow: None,
            tcp: None,
            tls: None,
            ip: None,
            inner: None,
            app_proto: None,
            timestamp: None,
            flow_id: None,
        }
    }
}

impl TypedSuricataLine {
    /// Minimal object matching what `ExtractorCore::process_line_detailed` reads via `Value` paths.
    pub fn into_minimal_value(self) -> Value {
        let mut m = Map::new();
        let mut put = |k: &str, v: Option<Value>| {
            if let Some(val) = v {
                if !val.is_null() {
                    m.insert(k.to_string(), val);
                }
            }
        };
        put("event_type", self.event_type);
        put("src_ip", self.src_ip);
        put("dest_ip", self.dest_ip);
        put("src_port", self.src_port);
        put("dest_port", self.dest_port);
        put("proto", self.proto);
        put("app_proto", self.app_proto);
        put("timestamp", self.timestamp);
        put("flow_id", self.flow_id);
        if let Some(obj) = self.flow {
            m.insert("flow".to_string(), Value::Object(obj));
        }
        if let Some(obj) = self.tcp {
            m.insert("tcp".to_string(), Value::Object(obj));
        }
        if let Some(obj) = self.tls {
            m.insert("tls".to_string(), Value::Object(obj));
        }
        if let Some(obj) = self.ip {
            m.insert("ip".to_string(), Value::Object(obj));
        }
        if let Some(obj) = self.inner {
            m.insert("inner".to_string(), Value::Object(obj));
        }
        Value::Object(m)
    }
}

/// All-or-nothing typed vs full `Value` parse (no fallback). Kept for explicit A/B checks.
#[allow(dead_code)]
#[inline]
pub fn parse_line_to_value(line: &str, use_typed: bool) -> serde_json::Result<Value> {
    if use_typed {
        let t: TypedSuricataLine = serde_json::from_str(line)?;
        Ok(t.into_minimal_value())
    } else {
        serde_json::from_str(line)
    }
}

/// Typed parse when `use_typed`, then full `Value` parse on typed deserialize failure (legacy path).
#[inline]
pub fn parse_line_with_fallback(line: &str, use_typed: bool) -> serde_json::Result<Value> {
    if !use_typed {
        return serde_json::from_str(line);
    }
    match serde_json::from_str::<TypedSuricataLine>(line) {
        Ok(t) => Ok(t.into_minimal_value()),
        Err(_) => serde_json::from_str::<Value>(line),
    }
}
