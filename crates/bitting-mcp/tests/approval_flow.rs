// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The opt-in path: what happens when a user *does* let an agent see a password.
//!
//! `rogue_agent.rs` proves the shipped default — an agent cannot obtain a password however
//! it is granted. This file is its counterpart, and the two together are the whole claim:
//! the safe default holds, and the deliberate exception behaves exactly as advertised
//! rather than quietly becoming a standing permission.
//!
//! Before this was built, none of it worked. `resolve_reveal_approval` cleared an in-flight
//! flag and nothing else, so an approved retry was escalated again forever and a reveal
//! could never succeed no matter what the user did. The escalation details were discarded
//! too, so no dialog could have been rendered from them.
//!
//! The properties pinned here:
//!
//! * Reveal is refused outright until the user turns it on, and the switch is off by
//!   default.
//! * An escalation is raised with **ground truth** — the entry title from the vault, the
//!   client kind from the verified peer — and with the agent's own justification kept
//!   separate and labelled.
//! * Approval is **one-shot**. One "yes" permits one reveal; the next request asks again.
//! * A refusal denies that request.
//! * Nothing is ever auto-approved.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

const CANARY: &str = "APPROVAL-FLOW-CANARY-8842";
const PASSPHRASE: &str = "correct-horse-battery-staple";
const CLIENT_ID: &str = "claude-under-test";

static FIXTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn binary(name: &str) -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(name)
}

struct Fixture {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    vault: PathBuf,
    passphrase_file: PathBuf,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let guard = FIXTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("agent.sock");
        let vault = dir.path().join("vault.bitting");
        let passphrase_file = dir.path().join("passphrase");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::write(&passphrase_file, PASSPHRASE).expect("write passphrase");
            std::fs::set_permissions(&passphrase_file, std::fs::Permissions::from_mode(0o600))
                .expect("restrict the passphrase file");
        }
        let fixture = Self {
            _dir: dir,
            socket,
            vault,
            passphrase_file,
            _guard: guard,
        };
        fixture.bitting(&["init", "--tier", "interactive"]);
        fixture.store_canary();
        fixture.bitting(&[
            "grant",
            CLIENT_ID,
            "--scope",
            "metadata",
            "--scope",
            "reveal",
            "--all-entries",
            "--minutes",
            "10",
        ]);
        fixture
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(binary(program));
        command
            .env("BITTING_AGENT_SOCKET", &self.socket)
            .env("BITTING_VAULT", &self.vault)
            .env("BITTING_AGENT_BINARY", binary("bitting-agent"))
            .env("BITTING_PASSPHRASE_FILE", &self.passphrase_file)
            .env("BITTING_AGENT_IDLE_EXIT_SECS", "30")
            .env_remove("XDG_RUNTIME_DIR");
        command
    }

    fn bitting(&self, args: &[&str]) -> String {
        let output = self
            .command("bitting")
            .args(args)
            .output()
            .expect("run bitting");
        assert!(
            output.status.success(),
            "`bitting {}` failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn store_canary(&self) {
        let mut child = self
            .command("bitting")
            .args([
                "add",
                "Chase Bank",
                "--username",
                "ada@example.com",
                "--password-stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bitting add");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(CANARY.as_bytes())
            .expect("write the canary");
        assert!(
            child.wait().expect("bitting add").success(),
            "storing the canary failed"
        );
    }

    /// The identifier of the first escalation waiting, if any.
    fn first_pending(&self) -> Option<serde_json::Value> {
        let json = self.bitting(&["approvals", "--json"]);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("approvals json");
        parsed
            .get("approvals")
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .cloned()
    }

    /// Poll until an escalation appears, or give up.
    fn wait_for_pending(&self) -> serde_json::Value {
        for _ in 0..60 {
            if let Some(item) = self.first_pending() {
                return item;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("no escalation appeared for the user to answer");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.socket.exists() {
            let _ = self.command("bitting").arg("lock").output();
        }
    }
}

/// An MCP client driven over real stdio.
struct Agent {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl Agent {
    fn connect(fixture: &Fixture) -> Self {
        let mut child = fixture
            .command("bitting-mcp")
            .env("BITTING_MCP_CLIENT_ID", CLIENT_ID)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitting-mcp");
        let reader = BufReader::new(child.stdout.take().expect("stdout"));
        let mut agent = Self {
            child,
            reader,
            next_id: 0,
        };
        agent.call(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            }),
        );
        agent
    }

    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let request = serde_json::json!({
            "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params,
        });
        let stdin = self.child.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{request}").expect("write");
        stdin.flush().expect("flush");
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("read");
        serde_json::from_str(&line).unwrap_or(serde_json::Value::Null)
    }

    fn tool(&mut self, name: &str, arguments: serde_json::Value) -> String {
        let response = self.call(
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
        );
        response
            .pointer("/result/content/0/text")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| response.to_string())
    }

    fn reference(&mut self) -> String {
        let found = self.tool("search_entries", serde_json::json!({"query": "chase"}));
        serde_json::from_str::<serde_json::Value>(&found)
            .ok()
            .and_then(|v| {
                v.pointer("/entries/0/reference")
                    .and_then(|r| r.as_str())
                    .map(str::to_owned)
            })
            .expect("a reference for the stored entry")
    }

    fn ask_to_reveal(&mut self, reason: &str, reference: &str) -> String {
        self.tool(
            "reveal_secret",
            serde_json::json!({
                "reference": reference,
                "field": "password",
                "reason": reason,
            }),
        )
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------

#[test]
fn reveal_is_off_until_the_user_turns_it_on() {
    let fixture = Fixture::new();

    let settings = fixture.bitting(&["settings", "--json"]);
    assert!(
        settings.contains("\"mcp_reveal_enabled\": false"),
        "the shipped default must be off: {settings}"
    );

    let mut agent = Agent::connect(&fixture);
    let reference = agent.reference();
    let refused = agent.ask_to_reveal("the user asked me to sign in", &reference);
    assert!(
        refused.contains("disabled"),
        "reveal should be refused while the setting is off: {refused}"
    );
    assert!(
        !refused.contains(CANARY),
        "a refusal must not carry the secret: {refused}"
    );
    // Nothing should be waiting for the user, because nothing was escalated.
    assert!(
        fixture.first_pending().is_none(),
        "a refused request must not queue an escalation"
    );
}

#[test]
fn one_approval_permits_exactly_one_reveal() {
    // The property that makes this per-request approval rather than a silent grant, checked
    // through the real transport rather than in the policy engine.
    let fixture = Fixture::new();
    fixture.bitting(&["settings", "--agent-reveal", "on"]);

    let mut agent = Agent::connect(&fixture);
    let reference = agent.reference();

    // First ask: escalated, not answered.
    let waiting = agent.ask_to_reveal("the user asked me to sign in", &reference);
    assert!(
        !waiting.contains(CANARY),
        "an unanswered request must not produce the secret: {waiting}"
    );
    assert!(
        waiting.contains("approval"),
        "the agent should be told it is waiting: {waiting}"
    );

    // The escalation the user sees carries ground truth from the vault, plus the agent's own
    // words kept separate.
    let pending = fixture.wait_for_pending();
    assert_eq!(
        pending.get("entry_title").and_then(|v| v.as_str()),
        Some("Chase Bank"),
        "the entry title must come from the vault: {pending}"
    );
    assert_eq!(
        pending.get("client_id").and_then(|v| v.as_str()),
        Some(CLIENT_ID)
    );
    assert_eq!(
        pending.get("agent_text").and_then(|v| v.as_str()),
        Some("the user asked me to sign in")
    );
    assert!(
        pending
            .get("arm_delay_ms")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|ms| ms > 0),
        "the Allow control must start disabled: {pending}"
    );
    let id = pending
        .get("approval_id")
        .and_then(|v| v.as_str())
        .expect("an approval id")
        .to_owned();

    // The user allows it.
    fixture.bitting(&["approvals", "--allow", &id]);

    // The retry succeeds. This is the one place in the whole suite where the canary is
    // *expected* to appear: the user asked for exactly this.
    let revealed = agent.ask_to_reveal("retrying after approval", &reference);
    assert!(
        revealed.contains(CANARY),
        "the approved retry should produce the secret: {revealed}"
    );

    // And the next one is asked again rather than waved through.
    let again = agent.ask_to_reveal("asking once more", &reference);
    assert!(
        !again.contains(CANARY),
        "one approval must permit one reveal, not a session: {again}"
    );
    assert!(
        again.contains("approval"),
        "the second request should be escalated again: {again}"
    );
}

#[test]
fn refusing_denies_the_request() {
    let fixture = Fixture::new();
    fixture.bitting(&["settings", "--agent-reveal", "on"]);

    let mut agent = Agent::connect(&fixture);
    let reference = agent.reference();
    agent.ask_to_reveal("let me read it", &reference);

    let pending = fixture.wait_for_pending();
    let id = pending
        .get("approval_id")
        .and_then(|v| v.as_str())
        .expect("an approval id")
        .to_owned();
    fixture.bitting(&["approvals", "--refuse", &id]);

    let denied = agent.ask_to_reveal("retrying after refusal", &reference);
    assert!(
        !denied.contains(CANARY),
        "a refused request must never produce the secret: {denied}"
    );
}

#[test]
fn turning_the_setting_back_off_takes_effect_immediately() {
    // A user who changes their mind should not have to restart anything, and the switch
    // should not be one of those settings that only applies to new sessions.
    let fixture = Fixture::new();
    fixture.bitting(&["settings", "--agent-reveal", "on"]);
    fixture.bitting(&["settings", "--agent-reveal", "off"]);

    let mut agent = Agent::connect(&fixture);
    let reference = agent.reference();
    let refused = agent.ask_to_reveal("please", &reference);
    assert!(
        refused.contains("disabled"),
        "the setting should be off again: {refused}"
    );
    assert!(!refused.contains(CANARY));
}

#[test]
fn the_setting_survives_a_lock_and_unlock() {
    // It is persisted in the vault rather than held in memory, so a restart must not
    // silently re-disable something the user deliberately enabled — nor silently keep it on
    // if they never did.
    let fixture = Fixture::new();
    fixture.bitting(&["settings", "--agent-reveal", "on"]);
    fixture.bitting(&["lock"]);
    fixture.bitting(&["unlock"]);

    let settings = fixture.bitting(&["settings", "--json"]);
    assert!(
        settings.contains("\"mcp_reveal_enabled\": true"),
        "the setting should have survived: {settings}"
    );

    // Grants do *not* survive a lock — that is deliberate, and the reason a fresh unlock is
    // what clears a tripped circuit breaker. So the access has to be given again before the
    // setting can be shown to be in force. The two lifetimes are different on purpose: the
    // setting is a standing decision about what is possible, a grant is a short-lived
    // decision about who may do it.
    fixture.bitting(&[
        "grant",
        CLIENT_ID,
        "--scope",
        "metadata",
        "--scope",
        "reveal",
        "--all-entries",
        "--minutes",
        "10",
    ]);

    // And it is actually in force, not merely reported.
    let mut agent = Agent::connect(&fixture);
    let reference = agent.reference();
    let waiting = agent.ask_to_reveal("after a restart", &reference);
    assert!(
        !waiting.contains("disabled"),
        "the persisted setting should be in force after unlock: {waiting}"
    );
}

#[test]
fn an_agent_cannot_enable_its_own_reveal_permission() {
    // The first thing a compromised agent would try. There is no tool for it, and the agent
    // process refuses the request by client type, so this is defence in depth.
    let fixture = Fixture::new();
    let mut agent = Agent::connect(&fixture);

    for attempt in ["set_settings", "settings", "enable_reveal", "set_policy"] {
        let response = agent.tool(attempt, serde_json::json!({"mcp_reveal_enabled": true}));
        assert!(!response.contains(CANARY));
    }

    // Still off.
    let settings = fixture.bitting(&["settings", "--json"]);
    assert!(
        settings.contains("\"mcp_reveal_enabled\": false"),
        "an agent must not be able to turn this on: {settings}"
    );
}
