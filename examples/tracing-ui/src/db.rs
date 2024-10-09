use crate::app::{EventUiData, SpanUiData, UiData, UiTraceLevel};
use clickhouse::{error::Result, Client, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::HashMap;
use tracing::span;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceUndigested {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: UndigestedLevel,
    pub target: String,
    pub fields: HashMap<String, Value>,
    pub span: HashMap<String, Value>,
    pub spans: Vec<HashMap<String, Value>>,
}
#[derive(Deserialize, Serialize, Clone, Copy, Debug)]
pub enum UndigestedLevel {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
}
#[derive(Serialize, Deserialize, Clone, Debug, Row, Default)]
pub struct TraceDigested {
    /// all traces are associated with a request
    pub request_id: u64,
    /// timestamp when request initiated
    pub timestamp: u64,
    /// all requests are associated with a particular browser session
    pub browser_session_id: u128,
    /// if there is a user associated with the request it will be here
    #[serde(with = "clickhouse::serde::uuid")]
    pub auth_id: Uuid,
    /// the path to where the event occurred.
    pub target: String,
    /// if the trace is a span it will have a span_aname
    pub span_name: String,
    /// if the trace is a span it will have a span_parent
    pub span_parent: String,
    /// i,e TRACE, DEBUG, INFO, WARN, ERROR
    pub level: DigestedLevel,
    /// If the trace is an event instead of a span_parent it will have a current_span, which is where the event was emitted
    pub current_span: String,
    /// All traces, spans and events can have fields. Spans will have a field with a message = "new"
    pub fields: Vec<(String, String)>,
}

impl TraceDigested {
    pub fn is_span(&self) -> bool {
        !self.span_name.is_empty()
    }

    pub fn in_span(&self, span_name: &String) -> bool {
        &self.current_span == span_name
    }
}

impl From<TraceDigested> for SpanUiData {
    fn from(value: TraceDigested) -> Self {
        Self {
            name: value.span_name,
            parent: value.span_parent,
            level: UiTraceLevel::from(value.level),
            fields: value.fields,
            request_id: value.request_id,
            timestamp: value.timestamp,
        }
    }
}
impl From<TraceDigested> for EventUiData {
    fn from(value: TraceDigested) -> Self {
        Self {
            current_span: value.current_span,
            level: UiTraceLevel::from(value.level),
            request_id: value.request_id,
            fields: value.fields,
            timestamp: value.timestamp,
        }
    }
}
impl From<DigestedLevel> for UiTraceLevel {
    fn from(value: DigestedLevel) -> Self {
        match value {
            DigestedLevel::TRACE => Self::TRACE,
            DigestedLevel::DEBUG => Self::DEBUG,
            DigestedLevel::INFO => Self::INFO,
            DigestedLevel::WARN => Self::WARN,
            DigestedLevel::ERROR => Self::ERROR,
        }
    }
}

// How to define enums that map to `Enum8`/`Enum16`.
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone, Copy, Default)]
#[repr(u8)]
pub enum DigestedLevel {
    #[default]
    TRACE = 1,
    DEBUG = 2,
    INFO = 3,
    WARN = 4,
    ERROR = 5,
}
impl From<UndigestedLevel> for DigestedLevel {
    fn from(value: UndigestedLevel) -> Self {
        match value {
            UndigestedLevel::TRACE => Self::TRACE,
            UndigestedLevel::DEBUG => Self::DEBUG,
            UndigestedLevel::INFO => Self::INFO,
            UndigestedLevel::WARN => Self::WARN,
            UndigestedLevel::ERROR => Self::ERROR,
        }
    }
}
#[derive(Clone)]
pub struct ClickhouseClient(Client);
impl ClickhouseClient {
    pub async fn new() -> Result<Self> {
        let client = Client::default().with_url("http://localhost:8123");
        // Event and Spans both fit into traces
        client.query(r#"DROP TABLE traces;"#).execute().await?;
        client
            .query(
                r#"
            CREATE TABLE IF NOT EXISTS traces
            (
                request_id UInt64,
                timestamp UInt64,
                auth_id UUID,
                browser_session_id UInt128,
                target LowCardinality(String),
                span_name LowCardinality(String),
                span_parent LowCardinality(String),
                level Enum8('TRACE' = 1, 'DEBUG' = 2, 'INFO' = 3, 'WARN' = 4, 'ERROR' = 5),
                current_span LowCardinality(String),
                fields Array(Tuple(name LowCardinality(String),value String))
            )
            ENGINE = MergeTree()
            ORDER BY (request_id, timestamp);
        "#,
            )
            .execute()
            .await?;
        Ok(Self(client))
    }
    pub async fn insert_trace(&self, trace: TraceDigested) -> Result<()> {
        let mut insert = self.0.insert("traces")?;
        insert.write(&trace).await?;
        insert.end().await?;
        Ok(())
    }
    /// When your server boots up, query get last request id and add 1 to find the first number for your request id middleware.
    pub async fn get_last_request_id(&self) -> Result<u64> {
        self.0
            .query(
                r#"
            SELECT 
                COALESCE(MAX(request_id), 0) AS last_request_id
            FROM traces
            "#,
            )
            .fetch_one::<u64>()
            .await
    }
    pub async fn get_traces_with_limit(&self, limit: u64) -> Result<Vec<TraceDigested>> {
        self.0
            .query(r#"SELECT * FROM traces LIMIT ?"#)
            .bind(limit)
            .fetch_all()
            .await
    }
    pub async fn get_by_session_id(&self, session_id: u64) -> Result<Vec<TraceDigested>> {
        self.0
            .query(r#"SELECT * FROM traces WHERE session_id = ?"#)
            .bind(session_id)
            .fetch_all()
            .await
    }
}

pub fn digest_trace(mut trace: TraceUndigested) -> TraceDigested {
    let is_span = if let Some(message) = trace.fields.get("message") {
        message == "new"
    } else {
        false
    };
    let span_parent = if is_span {
        // the parent of the span is the name of the last span in its spans.
        if let Some(parent_span) = trace.spans.last() {
            parent_span
                .get("name")
                .expect("for every span in spans a name field must exist")
                .as_str()
                .unwrap()
                .to_owned()
        } else {
            // if no parent span, span is root
            "root".to_string()
        }
    } else {
        // an event doesn't have a parent span, it has a current span.
        "".to_string()
    };

    let sort_spans =
        |list: Vec<HashMap<String, Value>>| -> HashMap<String, HashMap<String, Value>> {
            let mut map = HashMap::new();
            for mut span in list {
                let name = span
                    .remove("name")
                    .expect("All spans to have a name")
                    .as_str()
                    .unwrap()
                    .to_owned();
                map.insert(name, span);
            }
            map
        };
    let spans = sort_spans(trace.spans);
    let current_span = if !is_span {
        trace
            .span
            .remove("name")
            .expect("all current spans to have name")
            .as_str()
            .unwrap()
            .to_owned()
    } else {
        "".to_string()
    };
    let span_name = if is_span {
        trace
            .span
            .remove("name")
            .expect("all spans to have a name in the span field (this is itself)")
            .as_str()
            .unwrap()
            .to_owned()
    } else {
        // events don't have names
        "".to_string()
    };
    let target = trace.target;
    let request_id = {
        if let Some(map) = spans.get("http_request") {
            map.get("request_id")
                .expect("map for http_request to contain request_id")
        } else {
            // if there is no http request in spans, we are looking at the new span event for the http request itself
            trace
                .span
                .get("request_id")
                .expect("http request to have request_id as value")
        }
    }
    .as_i64()
    .unwrap() as u64;
    let browser_session_id = {
        if let Some(map) = spans.get("http_request") {
            map.get("browser_session_id")
                .expect("map for http_request to contain request_id")
        } else {
            // if there is no http request in spans, we are looking at the new span event for the http request itself
            trace
                .span
                .get("browser_session_id")
                .expect("http request to have request_id as value")
        }
    }
    .as_str()
    .unwrap()
    .to_string()
    .parse::<u128>()
    // the client can set the browser-session-id so this is a potential vulnerability if we treat it as trusted input.
    // this is as opposed to the request id which we full control over.
    .unwrap_or_default();
    let timestamp = trace.timestamp.timestamp() as u64;
    let map_value_to_string = |(name, value)| -> (String, String) {
        (
            name,
            match value {
                Value::Null => "".to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::String(s) => s,
                Value::Array(vec) => format!("{vec:#?}"),
                Value::Object(map) => format!("{map:#?}"),
            },
        )
    };
    let mut fields = trace
        .fields
        .into_iter()
        .map(map_value_to_string)
        .collect::<Vec<(String, String)>>();
    if is_span {
        fields.extend(
            trace
                .span
                .into_iter()
                .map(map_value_to_string)
                .collect::<Vec<(String, String)>>(),
        );
    }
    TraceDigested {
        request_id,
        timestamp,
        browser_session_id,
        auth_id: Uuid::default(),
        target,
        span_name,
        span_parent,
        level: DigestedLevel::from(trace.level),
        current_span,
        fields,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serial_test::serial;
    #[tokio::test]
    #[serial]
    pub async fn insert_trace() {
        let client = ClickhouseClient::new().await.unwrap();
        client.insert_trace(TraceDigested::default()).await.unwrap();
    }
    #[tokio::test]
    #[serial]
    pub async fn get_ids() {
        let client = ClickhouseClient::new().await.unwrap();
        let result = client.get_last_request_id().await.unwrap();
        assert_eq!(result, 0);
        client
            .insert_trace(TraceDigested {
                request_id: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        let result = client.get_last_request_id().await.unwrap();
        assert_eq!(100, result);
    }

    #[tokio::test]
    #[serial]
    pub async fn test_digest_trace() {
        let json = r#"{"timestamp":"2024-10-07T19:01:29.169320Z","level":"INFO","fields":{"message":"new"},"target":"dev_example","span":{"request_id":0,"name":"http_request"},"spans":[]}"#;
        let trace: TraceUndigested = serde_json::from_str(json).unwrap();
        let client = ClickhouseClient::new().await.unwrap();
        let trace = digest_trace(trace);
        println!("{trace:#?}");
        client.insert_trace(trace).await.unwrap();
    }
}
