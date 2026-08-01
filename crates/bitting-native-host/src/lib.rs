// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The browser native-messaging bridge.
//!
//! Browsers do not let an extension open a socket, so they offer this instead: the browser
//! launches a small program and speaks a length-prefixed JSON protocol to it over stdio. This
//! is that program, and it is deliberately the least interesting binary in the project.
//!
//! # It is a pipe, not a participant
//!
//! It holds no keys, opens no vault, and makes no decisions. Every question about whether
//! something is allowed — does this entry belong on this page, may this client fill a
//! credential, is the vault even unlocked — is answered by the agent. That placement is the
//! whole design: this process is launched by the browser, lives as long as a page, and is the
//! component closest to hostile input, so it is the one that should know the least.
//!
//! What it does do is translate framing. The browser speaks a 4-byte little-endian length
//! followed by JSON; the agent speaks the Bitting wire protocol. That is the entire job.
//!
//! # Refusing to be a launcher
//!
//! If the agent is not running, this reports `agent_not_running` and stops. It must **never**
//! start the agent or prompt for a passphrase.
//!
//! A browser extension can be induced to send a message by any page the user visits. If that
//! could spawn an unlock prompt, then any web page could summon a Bitting passphrase dialog at a
//! moment of its choosing — which is a phishing primitive, not a feature. The user opens Bitting
//! themselves, from a window they went to on purpose.
//!
//! # The frame cap
//!
//! Chrome allows up to 1 MiB from an extension. This accepts 64 KiB, which is far more than
//! any legitimate message here needs — the largest is a page origin — and is checked *before*
//! allocating, so a hostile length prefix cannot make this process reserve a megabyte on
//! demand.

// Tests build values and assert on them; production lints that forbid panicking would only
// make them longer. Matches every other crate here.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )
)]

use std::io::{Read, Write};

use bitting_client::Client;
use bitting_proto::{ClientKind, EntryRef, Request, Response};

/// Identifier this bridge presents to the agent.
const CLIENT_ID: &str = "bitting-browser";

/// Largest frame accepted from the browser, in bytes.
///
/// Our own limit, well below the browser's. The biggest legitimate message is a request
/// carrying an origin; nothing here has a reason to be large, and a smaller cap is a smaller
/// target.
pub const MAX_FRAME: u32 = 64 * 1024;

/// A message from the extension.
///
/// Untagged on purpose in one respect: the `type` field selects the variant, so an unknown
/// type is a clean parse failure rather than a partially-understood message.
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum FromExtension {
    /// Is the vault unlocked?
    Status,
    /// Which entries may be filled into this page?
    Candidates {
        /// Page origin, from `sender.origin`.
        origin: String,
    },
    /// Give me this credential for this page.
    Fill {
        /// Opaque handle from a previous `candidates` reply.
        reference: String,
        /// Page origin, from `sender.origin`. Re-checked by the agent.
        origin: String,
    },
}

/// A reply to the extension.
///
/// Always carries the request's `id`, so the extension can match replies without relying on
/// ordering.
#[derive(Debug, serde::Serialize)]
struct ToExtension {
    id: u64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

impl ToExtension {
    fn ok(id: u64, result: serde_json::Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
            code: None,
        }
    }

    fn failed(id: u64, code: &str, error: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(error.into()),
            code: Some(code.to_owned()),
        }
    }
}

/// Why reading a frame stopped.
#[derive(Debug)]
pub enum ReadError {
    /// The browser closed the pipe. Normal shutdown.
    Closed,
    /// The declared length exceeds [`MAX_FRAME`].
    TooLarge(u32),
    /// An I/O failure.
    Io(std::io::Error),
}

/// Read one length-prefixed frame.
///
/// The length is validated **before** the body is allocated. Reading the prefix, trusting it,
/// and calling `vec![0; len]` is the obvious implementation and hands any sender a
/// memory-exhaustion primitive.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, ReadError> {
    let mut prefix = [0u8; 4];
    match reader.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(ReadError::Closed),
        Err(e) => return Err(ReadError::Io(e)),
    }
    let len = u32::from_le_bytes(prefix);
    if len > MAX_FRAME {
        return Err(ReadError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ReadError::Closed
        } else {
            ReadError::Io(e)
        }
    })?;
    Ok(body)
}

/// Write one length-prefixed frame.
///
/// # Errors
///
/// Returns an error if the frame exceeds [`MAX_FRAME`] or the pipe fails.
pub fn write_frame<W: Write>(writer: &mut W, body: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame length overflows u32",
        )
    })?;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame exceeds the maximum size",
        ));
    }
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

/// Turn one extension message into a reply.
///
/// Takes the connection rather than owning it so the caller controls reconnection, and so
/// this is testable without a browser.
fn handle(client: &mut Client, id: u64, message: FromExtension) -> ToExtension {
    let request = match message {
        FromExtension::Status => Request::Status,
        FromExtension::Candidates { origin } => Request::CandidatesForOrigin { origin },
        FromExtension::Fill { reference, origin } => Request::FillCredential {
            reference: EntryRef(reference),
            origin,
        },
    };

    match client.request(&request) {
        Ok(Response::Status(info)) => ToExtension::ok(
            id,
            serde_json::json!({
                "state": match info.state {
                    bitting_proto::LockState::Unlocked => "unlocked",
                    bitting_proto::LockState::Locked => "locked",
                    bitting_proto::LockState::NoVault => "no_vault",
                },
            }),
        ),
        Ok(Response::Entries { entries, .. }) => ToExtension::ok(
            id,
            // Metadata only. There is no password field in an `EntrySummary`, so the popup
            // list cannot carry one even by accident.
            serde_json::json!({
                "entries": entries.iter().map(|e| serde_json::json!({
                    "reference": e.reference.0,
                    "title": e.title,
                    "username": e.username,
                })).collect::<Vec<_>>(),
            }),
        ),
        Ok(Response::Fill {
            username,
            password,
            origin,
        }) => ToExtension::ok(
            id,
            serde_json::json!({
                "username": username,
                "password": password,
                // Echoed so the extension can confirm the page has not navigated since it
                // asked. Without this there is a window in which a redirect during the round
                // trip lands the credential on a different origin.
                "origin": origin,
            }),
        ),
        Ok(Response::Error { code, message }) => {
            ToExtension::failed(id, error_code_name(code), message)
        }
        Ok(other) => ToExtension::failed(
            id,
            "unexpected_response",
            format!(
                "the agent sent a {} response, which the browser bridge did not ask for",
                variant_name(&other)
            ),
        ),
        Err(e) => ToExtension::failed(id, "agent_unreachable", e.to_string()),
    }
}

/// A stable name for an error code, for the extension to branch on.
const fn error_code_name(code: bitting_proto::ErrorCode) -> &'static str {
    match code {
        bitting_proto::ErrorCode::Locked => "locked",
        bitting_proto::ErrorCode::UnlockFailed => "unlock_failed",
        bitting_proto::ErrorCode::NoVault => "no_vault",
        bitting_proto::ErrorCode::VaultExists => "vault_exists",
        bitting_proto::ErrorCode::NotFound => "not_found",
        bitting_proto::ErrorCode::Denied => "denied",
        bitting_proto::ErrorCode::RateLimited => "rate_limited",
        bitting_proto::ErrorCode::ApprovalRefused => "approval_refused",
        bitting_proto::ErrorCode::BadRequest => "bad_request",
        bitting_proto::ErrorCode::VaultDamaged => "vault_damaged",
        bitting_proto::ErrorCode::Conflict => "conflict",
        bitting_proto::ErrorCode::Internal => "internal",
    }
}

/// A response variant's name, never its contents.
///
/// The same rule as everywhere else: a variant that arrives unexpectedly may carry a secret,
/// and an error message that interpolated it would be the disclosure.
const fn variant_name(response: &Response) -> &'static str {
    match response {
        Response::Ok => "ok",
        Response::Hello { .. } => "hello",
        Response::Status(_) => "status",
        Response::Entries { .. } => "entries",
        Response::Entry(_) => "entry",
        Response::Created { .. } => "created",
        Response::Applied { .. } => "applied",
        Response::Secret { .. } => "secret",
        Response::Generated { .. } => "generated",
        Response::Grants { .. } => "grants",
        Response::Audit { .. } => "audit",
        Response::PendingApprovals { .. } => "pending approvals",
        Response::Health { .. } => "health",
        Response::Exported { .. } => "export",
        Response::Fill { .. } => "fill",
        Response::Settings(_) => "settings",
        Response::ApprovalRequired { .. } => "approval required",
        Response::Error { .. } => "error",
    }
}

/// Serve the browser until it closes the pipe.
///
/// # Errors
///
/// Returns an error only for a failure of the pipe itself. Everything else — no agent, a
/// locked vault, a refused fill — is reported to the extension as a failed reply, because
/// those are answers rather than faults.
pub fn run() -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    // Connected lazily and never spawned. See the module documentation for why a page must
    // not be able to cause an unlock prompt to appear.
    let mut client: Option<Client> = None;

    loop {
        let frame = match read_frame(&mut reader) {
            Ok(frame) => frame,
            Err(ReadError::Closed) => return Ok(()),
            Err(ReadError::TooLarge(len)) => {
                // Not answerable: the stream is now mid-frame at an unknown offset, so the
                // only safe move is to stop rather than to resynchronise on data a hostile
                // sender chose.
                return Err(format!(
                    "the browser sent a {len}-byte frame; the limit is {MAX_FRAME}"
                ));
            }
            Err(ReadError::Io(e)) => return Err(format!("reading from the browser: {e}")),
        };

        // The id is parsed separately so a malformed body can still be answered with the id
        // it claimed, rather than leaving the extension waiting for a reply that never comes.
        let envelope: serde_json::Value = match serde_json::from_slice(&frame) {
            Ok(value) => value,
            Err(e) => {
                let reply = ToExtension::failed(0, "bad_request", format!("unparseable: {e}"));
                respond(&mut writer, &reply)?;
                continue;
            }
        };
        let id = envelope
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);

        let message: FromExtension = match serde_json::from_value(envelope) {
            Ok(message) => message,
            Err(e) => {
                let reply = ToExtension::failed(id, "bad_request", e.to_string());
                respond(&mut writer, &reply)?;
                continue;
            }
        };

        if client.is_none() {
            match Client::connect_existing(ClientKind::Extension, CLIENT_ID) {
                Ok(connected) => client = Some(connected),
                Err(_) => {
                    // The distinct code lets the extension say "open Bitting" rather than
                    // showing a generic failure — and it must not offer to open it *for* the
                    // user, because a page can cause this message.
                    let reply = ToExtension::failed(
                        id,
                        "agent_not_running",
                        "Bitting is not running. Open Bitting and unlock your vault.",
                    );
                    respond(&mut writer, &reply)?;
                    continue;
                }
            }
        }

        let reply = match client.as_mut() {
            Some(connected) => {
                let reply = handle(connected, id, message);
                // A dropped connection is the normal end of an idle agent's life. Forget it
                // so the next message reconnects instead of failing forever.
                if reply.code.as_deref() == Some("agent_unreachable") {
                    client = None;
                }
                reply
            }
            None => ToExtension::failed(id, "agent_not_running", "Bitting is not running."),
        };
        respond(&mut writer, &reply)?;
    }
}

fn respond<W: Write>(writer: &mut W, reply: &ToExtension) -> Result<(), String> {
    let body = serde_json::to_vec(reply).map_err(|e| format!("encoding a reply: {e}"))?;
    write_frame(writer, &body).map_err(|e| format!("writing to the browser: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_frame_round_trips() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"{\"hello\":1}").unwrap();
        let mut cursor = std::io::Cursor::new(buffer);
        assert_eq!(read_frame(&mut cursor).unwrap(), b"{\"hello\":1}");
    }

    #[test]
    fn an_oversized_length_is_refused_before_allocating() {
        // The property that matters: a hostile 4-byte prefix must not cause a large
        // allocation. Only the prefix is present in the input, so if the implementation
        // allocated first it would either hang or reserve 4 GiB before noticing.
        let mut cursor = std::io::Cursor::new(u32::MAX.to_le_bytes().to_vec());
        match read_frame(&mut cursor) {
            Err(ReadError::TooLarge(len)) => assert_eq!(len, u32::MAX),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn a_frame_at_the_limit_is_accepted_and_one_over_is_not() {
        let mut at = std::io::Cursor::new(frame(&vec![b'x'; MAX_FRAME as usize]));
        assert_eq!(read_frame(&mut at).unwrap().len(), MAX_FRAME as usize);

        let mut over = std::io::Cursor::new((MAX_FRAME + 1).to_le_bytes().to_vec());
        assert!(matches!(read_frame(&mut over), Err(ReadError::TooLarge(_))));
    }

    #[test]
    fn a_closed_pipe_is_not_an_error() {
        // The browser closing the pipe is how this process is meant to end.
        let mut empty = std::io::Cursor::new(Vec::new());
        assert!(matches!(read_frame(&mut empty), Err(ReadError::Closed)));

        // Truncated mid-body is also a close, not a fault: the browser died.
        let mut truncated = std::io::Cursor::new({
            let mut v = 10u32.to_le_bytes().to_vec();
            v.extend_from_slice(b"abc");
            v
        });
        assert!(matches!(read_frame(&mut truncated), Err(ReadError::Closed)));
    }

    #[test]
    fn writing_refuses_an_oversized_frame() {
        let mut buffer = Vec::new();
        let big = vec![0u8; MAX_FRAME as usize + 1];
        assert!(write_frame(&mut buffer, &big).is_err());
        assert!(buffer.is_empty(), "nothing should have been written");
    }

    #[test]
    fn known_message_types_parse() {
        let cases = [
            r#"{"id":1,"type":"status"}"#,
            r#"{"id":2,"type":"candidates","origin":"https://example.com"}"#,
            r#"{"id":3,"type":"fill","reference":"abc","origin":"https://example.com"}"#,
        ];
        for raw in cases {
            let value: serde_json::Value = serde_json::from_str(raw).unwrap();
            serde_json::from_value::<FromExtension>(value)
                .unwrap_or_else(|e| panic!("{raw} should parse: {e}"));
        }
    }

    #[test]
    fn an_unknown_message_type_is_a_clean_failure() {
        // Not a partially-understood message. An extension asking for something this bridge
        // does not implement must be told so, not silently treated as the nearest match.
        for raw in [
            r#"{"id":1,"type":"export"}"#,
            r#"{"id":1,"type":"unlock","passphrase":"x"}"#,
            r#"{"id":1,"type":"reveal","reference":"a"}"#,
            r#"{"id":1}"#,
            r#"{"id":1,"type":"candidates"}"#,
        ] {
            let value: serde_json::Value = serde_json::from_str(raw).unwrap();
            assert!(
                serde_json::from_value::<FromExtension>(value).is_err(),
                "{raw} must not parse"
            );
        }
    }

    #[test]
    fn there_is_no_message_that_unlocks_or_exports() {
        // A guard on the shape of the bridge rather than on one message. If either ever
        // becomes reachable from a browser, the argument has to be made here first: a page
        // can cause the extension to send a message, so an unlock prompt reachable this way
        // is a phishing primitive.
        // Only the implementation, not this module: `include_str!` pulls in the test source
        // too, and the names being searched for appear in the list below.
        let whole = include_str!("lib.rs");
        let source = whole.split("#[cfg(test)]").next().unwrap_or(whole);
        for forbidden in ["Request::Unlock", "Request::Export", "Request::CreateVault"] {
            assert!(
                !source.contains(forbidden),
                "the browser bridge must never be able to send {forbidden}"
            );
        }
        // And it must not spawn the agent.
        assert!(
            !source.contains("Client::connect("),
            "the bridge must use connect_existing: starting the agent from a browser message \
             would let a page summon a passphrase prompt"
        );
    }

    #[test]
    fn a_reply_carries_the_request_id() {
        let ok = ToExtension::ok(7, serde_json::json!({"state":"locked"}));
        let json = serde_json::to_string(&ok).unwrap();
        assert!(json.contains("\"id\":7"));
        assert!(json.contains("\"ok\":true"));
        // Absent fields are omitted rather than sent as null, so the extension's checks are
        // simple.
        assert!(!json.contains("error"));
    }

    #[test]
    fn a_failure_carries_a_stable_code() {
        let failed = ToExtension::failed(9, "locked", "the vault is locked");
        let json = serde_json::to_string(&failed).unwrap();
        assert!(json.contains("\"code\":\"locked\""));
        assert!(json.contains("\"ok\":false"));
        assert!(!json.contains("result"));
    }

    #[test]
    fn every_error_code_has_a_name() {
        use bitting_proto::ErrorCode;
        for code in [
            ErrorCode::Locked,
            ErrorCode::UnlockFailed,
            ErrorCode::NoVault,
            ErrorCode::VaultExists,
            ErrorCode::NotFound,
            ErrorCode::Denied,
            ErrorCode::RateLimited,
            ErrorCode::ApprovalRefused,
            ErrorCode::BadRequest,
            ErrorCode::VaultDamaged,
            ErrorCode::Conflict,
            ErrorCode::Internal,
        ] {
            let name = error_code_name(code);
            assert!(!name.is_empty());
            assert_eq!(name, name.to_lowercase());
        }
    }
}
