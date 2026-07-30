//! JSON-RPC 2.0 framing for the MCP stdio transport.
//!
//! Targets MCP protocol revision **2025-06-18**. The transport is newline-delimited JSON:
//! one JSON-RPC object per line on stdin and stdout, with diagnostics on stderr. Only three
//! methods are needed for a tool server — `initialize`, `tools/list`, and `tools/call` — plus
//! the `notifications/initialized` notification.
//!
//! # Nothing may be written to stdout except protocol messages
//!
//! stdout *is* the transport. A stray `println!` corrupts the stream and the host sees a
//! protocol error rather than the debugging output whoever wrote it expected. Every
//! diagnostic goes to stderr.

use serde::{Deserialize, Serialize};

/// MCP protocol revision this server implements.
pub const PROTOCOL_REVISION: &str = "2025-06-18";

/// Largest accepted request line, in bytes.
///
/// The host is more trusted than a web page, but it is still another process passing us
/// attacker-influenced content — an agent's arguments derive from whatever the model read.
/// A bound before allocation costs nothing.
pub const MAX_LINE_LEN: usize = 1024 * 1024;

/// A JSON-RPC request or notification.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    /// Always `"2.0"`.
    #[serde(default)]
    pub jsonrpc: String,
    /// Absent for a notification, which expects no reply.
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    /// Method name.
    pub method: String,
    /// Method parameters.
    #[serde(default)]
    pub params: serde_json::Value,
}

impl Request {
    /// Whether this is a notification, which must not be answered.
    ///
    /// Replying to a notification is a protocol violation that some hosts treat as fatal.
    #[must_use]
    pub const fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// A JSON-RPC response.
#[derive(Debug, Clone, Serialize)]
pub struct Response {
    /// Always `"2.0"`.
    pub jsonrpc: &'static str,
    /// Echoes the request id.
    pub id: serde_json::Value,
    /// Present on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Present on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorObject {
    /// Error code.
    pub code: i32,
    /// Human-readable message.
    pub message: String,
}

/// Standard JSON-RPC error codes.
pub mod codes {
    /// The request was not valid JSON.
    pub const PARSE_ERROR: i32 = -32700;
    /// The request object was malformed.
    pub const INVALID_REQUEST: i32 = -32600;
    /// No such method.
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// The parameters were wrong.
    pub const INVALID_PARAMS: i32 = -32602;
    /// Something went wrong inside the server.
    pub const INTERNAL_ERROR: i32 = -32603;
}

impl Response {
    /// A successful response.
    #[must_use]
    pub fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    /// A failed response.
    #[must_use]
    pub fn error(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(ErrorObject {
                code,
                message: message.into(),
            }),
        }
    }
}

/// A tool the server offers.
#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    /// Tool name, as the model will call it.
    pub name: &'static str,
    /// What it does. The model reads this, so it states the security behaviour too — an
    /// agent should be able to tell from the description that `use_secret` will not hand it a
    /// password, and choose it deliberately.
    pub description: &'static str,
    /// JSON Schema for the arguments.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// The result of a tool call.
///
/// MCP distinguishes a *protocol* failure (a JSON-RPC error) from a *tool* failure
/// (`isError` inside a successful response). Refusals go in the second category
/// deliberately: "you may not do that, here is why, here is the safe alternative" is
/// information the model should read and act on, not a transport fault it should retry.
#[derive(Debug, Clone, Serialize)]
pub struct ToolResult {
    /// Result content blocks.
    pub content: Vec<Content>,
    /// Whether the tool itself failed.
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

/// A content block.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Content {
    /// Plain text.
    Text {
        /// The text.
        text: String,
    },
}

impl ToolResult {
    /// A successful text result.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content::Text { text: text.into() }],
            is_error: None,
        }
    }

    /// A tool-level failure.
    #[must_use]
    pub fn failure(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content::Text { text: text.into() }],
            is_error: Some(true),
        }
    }

    /// A successful result carrying JSON.
    #[must_use]
    pub fn json(value: &serde_json::Value) -> Self {
        Self::text(
            serde_json::to_string_pretty(value)
                .unwrap_or_else(|_| "{\"error\":\"could not render result\"}".to_owned()),
        )
    }
}

/// Extract a required string argument.
pub fn require_str(params: &serde_json::Value, key: &str) -> Result<String, String> {
    params
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("the `{key}` argument is required and must be a string"))
}

/// Extract an optional string argument.
#[must_use]
pub fn optional_str(params: &serde_json::Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Extract an optional bounded integer argument.
#[must_use]
pub fn optional_u32(params: &serde_json::Value, key: &str, max: u32) -> Option<u32> {
    params
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .map(|v| v.min(max))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_without_an_id_is_a_notification() {
        // Replying to a notification is a protocol violation some hosts treat as fatal.
        let notification: Request =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .unwrap();
        assert!(notification.is_notification());

        let call: Request =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        assert!(!call.is_notification());
    }

    #[test]
    fn a_request_with_no_params_still_parses() {
        let request: Request =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        assert_eq!(request.method, "tools/list");
        assert!(request.params.is_null());
    }

    #[test]
    fn responses_omit_the_field_they_do_not_use() {
        // A JSON-RPC response carries `result` or `error`, never both.
        let ok = Response::ok(serde_json::json!(1), serde_json::json!({"a": 1}));
        let text = serde_json::to_string(&ok).unwrap();
        assert!(text.contains("result"));
        assert!(!text.contains("error"));

        let bad = Response::error(serde_json::json!(1), codes::INVALID_PARAMS, "nope");
        let text = serde_json::to_string(&bad).unwrap();
        assert!(text.contains("error"));
        assert!(!text.contains("result"));
    }

    #[test]
    fn a_tool_failure_is_a_successful_response_with_is_error() {
        // MCP distinguishes a transport fault from a tool refusal. A refusal is information
        // the model should read, not something it should retry.
        let failure = ToolResult::failure("not permitted");
        let text = serde_json::to_string(&failure).unwrap();
        assert!(text.contains("isError"));
        assert!(text.contains("not permitted"));

        let success = ToolResult::text("done");
        assert!(!serde_json::to_string(&success).unwrap().contains("isError"));
    }

    #[test]
    fn required_arguments_are_checked_with_a_useful_message() {
        let params = serde_json::json!({"query": "bank"});
        assert_eq!(require_str(&params, "query").unwrap(), "bank");

        let error = require_str(&params, "reference").unwrap_err();
        assert!(error.contains("reference"));
        assert!(error.contains("required"));
    }

    #[test]
    fn a_non_string_argument_is_rejected_rather_than_coerced() {
        // Coercing 42 into "42" would let a confused model address the wrong entry.
        let params = serde_json::json!({"query": 42});
        assert!(require_str(&params, "query").is_err());
    }

    #[test]
    fn optional_integers_are_clamped_not_rejected() {
        // A model asking for a million results should get the maximum, not an error: the
        // request is reasonable in spirit and refusing it wastes a turn.
        let params = serde_json::json!({"limit": 1_000_000});
        assert_eq!(optional_u32(&params, "limit", 25), Some(25));
        assert_eq!(
            optional_u32(&serde_json::json!({"limit": 5}), "limit", 25),
            Some(5)
        );
        assert_eq!(optional_u32(&serde_json::json!({}), "limit", 25), None);
        // Negative and non-numeric values are simply absent rather than an error.
        assert_eq!(
            optional_u32(&serde_json::json!({"limit": -1}), "limit", 25),
            None
        );
        assert_eq!(
            optional_u32(&serde_json::json!({"limit": "x"}), "limit", 25),
            None
        );
    }
}
