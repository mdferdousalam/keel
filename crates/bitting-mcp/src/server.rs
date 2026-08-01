// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The stdio server loop.
//!
//! Reads newline-delimited JSON-RPC from stdin, writes responses to stdout, and puts every
//! diagnostic on stderr. stdout *is* the transport, so nothing else may be written there.
//!
//! # Connecting to the agent lazily
//!
//! The agent connection is established on the first request that needs it rather than at
//! startup. Two reasons, and the second is the important one:
//!
//! * A host may launch this server long before the user asks it to do anything, and failing at
//!   startup because no agent was running would make Bitting look broken.
//! * The connection is *not* allowed to spawn an agent. An MCP server starting a daemon and
//!   causing a passphrase prompt, in response to something a model decided, is a prompt-injected
//!   agent's dream. If no agent is running, the answer is to tell the user to open Bitting.

use std::io::{BufRead, Write};

use bitting_client::Client;
use bitting_proto::ClientKind;

use crate::protocol::{codes, Request, Response, ToolResult, MAX_LINE_LEN, PROTOCOL_REVISION};
use crate::tools;

/// Client identifier reported to the agent and shown in approval dialogs.
///
/// Overridable so a user running several agents can tell them apart in the audit log and in
/// approval prompts — "an AI agent wants your password" is much less useful than "claude-code
/// wants your password".
const DEFAULT_CLIENT_ID: &str = "bitting-mcp";

/// Environment variable overriding the client identifier.
pub const CLIENT_ID_ENV: &str = "BITTING_MCP_CLIENT_ID";

/// Server state.
struct Server {
    client_id: String,
    agent: Option<Client>,
    initialized: bool,
}

impl Server {
    fn new() -> Self {
        Self {
            client_id: std::env::var(CLIENT_ID_ENV)
                .ok()
                .filter(|v| !v.is_empty() && v.len() <= 128)
                .unwrap_or_else(|| DEFAULT_CLIENT_ID.to_owned()),
            agent: None,
            initialized: false,
        }
    }

    /// Connect to a *running* agent.
    ///
    /// Deliberately `connect_existing`: see the module documentation for why this must never
    /// spawn one.
    fn agent(&mut self) -> Result<&mut Client, String> {
        if self.agent.is_none() {
            let client =
                Client::connect_existing(ClientKind::Mcp, &self.client_id).map_err(|error| {
                    format!(
                        "Bitting is not running, so the vault cannot be reached ({error}). Ask the \
                         user to open the Bitting app or run `bitting unlock`. Do not retry until they \
                         confirm they have."
                    )
                })?;
            self.agent = Some(client);
        }
        self.agent
            .as_mut()
            .ok_or_else(|| "the agent connection was lost".to_owned())
    }

    /// Handle one request, returning a response unless it was a notification.
    fn handle(&mut self, request: &Request) -> Option<Response> {
        let id = request.id.clone();

        // Notifications get no reply, ever. Answering one is a protocol violation that some
        // hosts treat as fatal.
        if request.is_notification() {
            if request.method == "notifications/initialized" {
                self.initialized = true;
            }
            return None;
        }
        let id = id.unwrap_or(serde_json::Value::Null);

        match request.method.as_str() {
            "initialize" => Some(Response::ok(
                id,
                serde_json::json!({
                    "protocolVersion": PROTOCOL_REVISION,
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "bitting",
                        "version": crate::VERSION,
                    },
                    "instructions":
                        "Bitting is a local password manager. Call vault_status first. To log the \
                         user in, use use_secret, which applies a password without revealing it \
                         to you — prefer it over reveal_secret, which is disabled by default and \
                         requires the user to approve every request. There is no way to export \
                         or enumerate the vault.",
                }),
            )),

            "ping" => Some(Response::ok(id, serde_json::json!({}))),

            "tools/list" => Some(Response::ok(
                id,
                serde_json::json!({ "tools": tools::all() }),
            )),

            "tools/call" => Some(self.call_tool(id, &request.params)),

            other => Some(Response::error(
                id,
                codes::METHOD_NOT_FOUND,
                format!("unsupported method {other:?}"),
            )),
        }
    }

    fn call_tool(&mut self, id: serde_json::Value, params: &serde_json::Value) -> Response {
        let Some(name) = params.get("name").and_then(serde_json::Value::as_str) else {
            return Response::error(
                id,
                codes::INVALID_PARAMS,
                "tools/call requires a `name` argument",
            );
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        // A malformed or refused call is a *tool* failure, not a transport failure: the model
        // should read the explanation and adjust, not treat it as a broken connection.
        let agent_request = match tools::to_request(name, &arguments) {
            Ok(request) => request,
            Err(message) => {
                return Response::ok(id, to_value(&ToolResult::failure(message)));
            }
        };

        let agent = match self.agent() {
            Ok(agent) => agent,
            Err(message) => {
                return Response::ok(id, to_value(&ToolResult::failure(message)));
            }
        };

        match agent.request(&agent_request) {
            Ok(response) => Response::ok(id, to_value(&tools::render(name, &response))),
            Err(bitting_client::Error::Agent { code, message }) => {
                // Reconstruct the protocol error so the renderer can add the guidance that
                // turns a refusal into a redirection.
                let response = bitting_proto::Response::Error { code, message };
                Response::ok(id, to_value(&tools::render(name, &response)))
            }
            Err(error) => {
                // The connection is unusable; drop it so the next call reconnects rather than
                // failing forever against a dead socket.
                self.agent = None;
                Response::ok(
                    id,
                    to_value(&ToolResult::failure(format!(
                        "lost the connection to Bitting ({error}). Ask the user to check that Bitting \
                         is running."
                    ))),
                )
            }
        }
    }
}

/// Serialize a tool result, degrading to a plain error rather than panicking.
fn to_value(result: &ToolResult) -> serde_json::Value {
    serde_json::to_value(result).unwrap_or_else(|_| {
        serde_json::json!({
            "content": [{"type": "text", "text": "the result could not be serialized"}],
            "isError": true,
        })
    })
}

/// Run the server until stdin closes.
pub fn run() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut server = Server::new();
    let mut line = String::new();
    let mut reader = stdin.lock();

    loop {
        line.clear();
        // Read with a bound. The host is more trusted than a web page, but its input still
        // derives from whatever a model read, so an unbounded line is an unbounded allocation.
        let read = read_line_bounded(&mut reader, &mut line, MAX_LINE_LEN)?;
        if read == 0 {
            // stdin closed: the host has gone. Nothing to clean up — this process holds no
            // keys and no vault.
            return Ok(());
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(trimmed) {
            Ok(request) => server.handle(&request),
            Err(error) => Some(Response::error(
                serde_json::Value::Null,
                codes::PARSE_ERROR,
                format!("could not parse the request: {error}"),
            )),
        };

        if let Some(response) = response {
            let encoded = serde_json::to_string(&response).unwrap_or_else(|_| {
                r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"could not serialize the response"}}"#
                    .to_owned()
            });
            writeln!(stdout, "{encoded}")?;
            // Flush every message: the host is waiting on this line, and a buffered response
            // looks to it exactly like a hung server.
            stdout.flush()?;
        }
    }
}

/// Read one line, refusing anything longer than `max`.
fn read_line_bounded(
    reader: &mut impl BufRead,
    out: &mut String,
    max: usize,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    loop {
        let mut byte = [0u8; 1];
        let read = std::io::Read::read(reader, &mut byte)?;
        if read == 0 {
            return Ok(total);
        }
        total += 1;
        let byte = byte[0];
        if byte == b'\n' {
            return Ok(total);
        }
        if total > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the request line exceeded the maximum length",
            ));
        }
        out.push(char::from(byte));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, id: Option<i64>, params: serde_json::Value) -> Request {
        let mut object = serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params});
        if let Some(id) = id {
            object["id"] = serde_json::json!(id);
        }
        serde_json::from_value(object).unwrap()
    }

    #[test]
    fn initialize_advertises_tools_and_explains_the_safe_path() {
        let mut server = Server::new();
        let response = server
            .handle(&request("initialize", Some(1), serde_json::json!({})))
            .unwrap();
        let result = response.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_REVISION);
        assert!(result["capabilities"]["tools"].is_object());
        // The instructions steer the model toward use_secret before it tries reveal_secret and
        // gets refused.
        let instructions = result["instructions"].as_str().unwrap();
        assert!(instructions.contains("use_secret"));
        assert!(instructions.contains("disabled by default"));
        assert!(instructions.contains("no way to export"));
    }

    #[test]
    fn a_notification_is_never_answered() {
        let mut server = Server::new();
        let response = server.handle(&request(
            "notifications/initialized",
            None,
            serde_json::json!({}),
        ));
        assert!(response.is_none(), "notifications must not be answered");
        assert!(server.initialized);
    }

    #[test]
    fn tools_list_returns_the_surface() {
        let mut server = Server::new();
        let response = server
            .handle(&request("tools/list", Some(2), serde_json::json!({})))
            .unwrap();
        let tools = response.result.unwrap()["tools"].clone();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"use_secret"));
        assert!(names.contains(&"vault_status"));
        assert!(!names.contains(&"export_vault"));
    }

    #[test]
    fn an_unknown_method_is_a_protocol_error() {
        let mut server = Server::new();
        let response = server
            .handle(&request("tools/invoke", Some(3), serde_json::json!({})))
            .unwrap();
        assert_eq!(response.error.unwrap().code, codes::METHOD_NOT_FOUND);
    }

    #[test]
    fn a_call_without_a_name_is_a_parameter_error() {
        let mut server = Server::new();
        let response = server
            .handle(&request("tools/call", Some(4), serde_json::json!({})))
            .unwrap();
        assert_eq!(response.error.unwrap().code, codes::INVALID_PARAMS);
    }

    #[test]
    fn a_refused_tool_is_a_successful_response_carrying_is_error() {
        // A refusal is information the model should read and act on, not a transport fault it
        // should retry. Asking for a bulk export needs no agent, so this works offline.
        let mut server = Server::new();
        let response = server
            .handle(&request(
                "tools/call",
                Some(5),
                serde_json::json!({"name": "export_vault", "arguments": {}}),
            ))
            .unwrap();
        assert!(response.error.is_none(), "should not be a protocol error");
        let result = response.result.unwrap();
        assert_eq!(result["isError"], serde_json::json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("search_entries"));
    }

    #[test]
    fn a_malformed_tool_call_needs_no_agent_to_be_refused() {
        // Argument validation happens before connecting, so a bad call gets a useful answer
        // even with no agent running.
        let mut server = Server::new();
        let response = server
            .handle(&request(
                "tools/call",
                Some(6),
                serde_json::json!({"name": "search_entries", "arguments": {"query": "x"}}),
            ))
            .unwrap();
        let result = response.result.unwrap();
        assert_eq!(result["isError"], serde_json::json!(true));
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("two characters"));
    }

    #[test]
    fn ping_is_answered() {
        let mut server = Server::new();
        let response = server
            .handle(&request("ping", Some(7), serde_json::json!({})))
            .unwrap();
        assert!(response.error.is_none());
    }

    #[test]
    fn the_client_id_can_be_overridden_so_prompts_name_the_real_agent() {
        // "An AI agent wants your password" is much less useful to a user than
        // "claude-code wants your password".
        let previous = std::env::var(CLIENT_ID_ENV).ok();
        std::env::set_var(CLIENT_ID_ENV, "claude-code");
        assert_eq!(Server::new().client_id, "claude-code");

        std::env::set_var(CLIENT_ID_ENV, "");
        assert_eq!(Server::new().client_id, DEFAULT_CLIENT_ID);

        std::env::set_var(CLIENT_ID_ENV, "x".repeat(500));
        assert_eq!(
            Server::new().client_id,
            DEFAULT_CLIENT_ID,
            "an absurd identifier should fall back rather than be forwarded"
        );

        match previous {
            Some(v) => std::env::set_var(CLIENT_ID_ENV, v),
            None => std::env::remove_var(CLIENT_ID_ENV),
        }
    }

    #[test]
    fn a_bounded_line_read_stops_at_the_newline() {
        let mut input = std::io::Cursor::new(b"hello\nworld\n".to_vec());
        let mut line = String::new();
        assert_eq!(read_line_bounded(&mut input, &mut line, 1024).unwrap(), 6);
        assert_eq!(line, "hello");

        line.clear();
        read_line_bounded(&mut input, &mut line, 1024).unwrap();
        assert_eq!(line, "world");
    }

    #[test]
    fn an_oversized_line_is_refused_rather_than_buffered() {
        let mut input = std::io::Cursor::new(vec![b'a'; 10_000]);
        let mut line = String::new();
        let result = read_line_bounded(&mut input, &mut line, 100);
        assert!(
            result.is_err(),
            "an unbounded line is an unbounded allocation"
        );
    }

    #[test]
    fn a_closed_input_reports_zero_rather_than_erroring() {
        let mut input = std::io::Cursor::new(Vec::new());
        let mut line = String::new();
        assert_eq!(read_line_bounded(&mut input, &mut line, 100).unwrap(), 0);
    }
}
