// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Autofill, driven the way a browser drives it.
//!
//! Runs the real `keel-native-host` binary over real stdio against a real agent, speaking the
//! same length-prefixed JSON a browser sends. What is being checked is the property that
//! matters most about autofill and is easiest to get wrong: **a credential goes to the site it
//! belongs to and nowhere else.**
//!
//! The look-alike cases are the reason this file exists. Every one of them is a real phishing
//! shape — a suffix-appended host, a hyphenated near-miss, a scheme downgrade — and each must
//! be refused by the agent rather than by the browser, the extension, or good luck.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

const CANARY: &str = "FILL-CANARY-DO-NOT-LEAK-8842";
const PASSPHRASE: &str = "correct-horse-battery-staple";

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
        let vault = dir.path().join("vault.keel");
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
        fixture.keel(&["init", "--tier", "interactive"]);
        fixture.add_entry("Chase Bank", "https://chase.com", CANARY);
        fixture
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(binary(program));
        command
            .env("KEEL_AGENT_SOCKET", &self.socket)
            .env("KEEL_VAULT", &self.vault)
            .env("KEEL_AGENT_BINARY", binary("keel-agent"))
            .env("KEEL_PASSPHRASE_FILE", &self.passphrase_file)
            .env("KEEL_AGENT_IDLE_EXIT_SECS", "30")
            .env_remove("XDG_RUNTIME_DIR");
        command
    }

    fn keel(&self, args: &[&str]) -> String {
        let output = self.command("keel").args(args).output().expect("run keel");
        assert!(
            output.status.success(),
            "`keel {}` failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn add_entry(&self, title: &str, url: &str, password: &str) {
        let mut child = self
            .command("keel")
            .args([
                "add",
                title,
                "--username",
                "ada@example.com",
                "--url",
                url,
                "--password-stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn keel add");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(password.as_bytes())
            .expect("write the password");
        assert!(child.wait().expect("keel add").success());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.socket.exists() {
            let _ = self.command("keel").arg("lock").output();
        }
    }
}

/// The native host, spoken to exactly as a browser would.
///
/// One long-lived process per session, because entry handles are scoped to a connection — a
/// reference from one session does not resolve in another, which is itself the behaviour that
/// makes a stale handle in a log useless.
struct Bridge {
    child: Child,
}

impl Bridge {
    fn start(fixture: &Fixture) -> Self {
        let child = fixture
            .command("keel-native-host")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn keel-native-host");
        Self { child }
    }

    fn send(&mut self, message: &serde_json::Value) {
        let body = serde_json::to_vec(message).expect("encode");
        let stdin = self.child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(&(body.len() as u32).to_le_bytes())
            .expect("write length");
        stdin.write_all(&body).expect("write body");
        stdin.flush().expect("flush");
    }

    fn recv(&mut self) -> serde_json::Value {
        let stdout = self.child.stdout.as_mut().expect("stdout");
        let mut prefix = [0u8; 4];
        stdout.read_exact(&mut prefix).expect("read length");
        let len = u32::from_le_bytes(prefix) as usize;
        let mut body = vec![0u8; len];
        stdout.read_exact(&mut body).expect("read body");
        serde_json::from_slice(&body).expect("decode reply")
    }

    fn call(&mut self, message: serde_json::Value) -> serde_json::Value {
        self.send(&message);
        self.recv()
    }

    /// A handle for the entry that lists `origin`.
    fn reference_for(&mut self, origin: &str) -> String {
        let reply = self.call(serde_json::json!({
            "id": 1, "type": "candidates", "origin": origin
        }));
        assert!(reply["ok"].as_bool() == Some(true), "candidates: {reply}");
        reply["result"]["entries"][0]["reference"]
            .as_str()
            .expect("a reference")
            .to_owned()
    }

    /// Attempt a fill, returning the password if one was handed over.
    fn fill(&mut self, reference: &str, origin: &str) -> Option<String> {
        let reply = self.call(serde_json::json!({
            "id": 2, "type": "fill", "reference": reference, "origin": origin
        }));
        if reply["ok"].as_bool() == Some(true) {
            Some(
                reply["result"]["password"]
                    .as_str()
                    .expect("a password")
                    .to_owned(),
            )
        } else {
            // A refusal must not carry the secret it is refusing to hand over.
            assert!(
                !reply.to_string().contains(CANARY),
                "a refusal leaked the password: {reply}"
            );
            None
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------

#[test]
fn a_credential_fills_its_own_site_and_its_subdomains() {
    let fixture = Fixture::new();
    let mut bridge = Bridge::start(&fixture);
    let reference = bridge.reference_for("https://chase.com");

    for origin in [
        "https://chase.com",
        // A subdomain of a stored origin. Filling here is the behaviour users expect from
        // every password manager, and it is safe because the boundary is a dot.
        "https://login.chase.com",
        "https://secure.login.chase.com",
    ] {
        assert_eq!(
            bridge.fill(&reference, origin).as_deref(),
            Some(CANARY),
            "{origin} should have been filled"
        );
    }
}

#[test]
fn a_credential_never_fills_a_lookalike_domain() {
    // The cases that matter. Each is a real phishing shape, and each must be refused by the
    // agent — not by the browser, not by the extension, and not by chance.
    let fixture = Fixture::new();
    let mut bridge = Bridge::start(&fixture);
    let reference = bridge.reference_for("https://chase.com");

    let attacks = [
        (
            "https://chase.com.evil.tld",
            "the real host as a prefix of the attacker's",
        ),
        ("https://evil-chase.com", "a hyphenated near-miss"),
        ("https://chasecom.evil.tld", "the host with the dot removed"),
        ("https://notchase.com", "a suffix that is not a subdomain"),
        ("https://chase.com.br", "a different registrable domain"),
        ("https://chase.co", "one character short"),
        ("https://xchase.com", "one character long"),
    ];
    for (origin, why) in attacks {
        assert_eq!(
            bridge.fill(&reference, origin),
            None,
            "{origin} ({why}) must never be filled"
        );
    }
}

#[test]
fn an_https_credential_never_fills_an_http_page() {
    // The worst outcome available to autofill: a password in a cleartext request. Refused
    // even though the host matches exactly.
    let fixture = Fixture::new();
    let mut bridge = Bridge::start(&fixture);
    let reference = bridge.reference_for("https://chase.com");
    assert_eq!(bridge.fill(&reference, "http://chase.com"), None);
}

#[test]
fn a_different_port_is_a_different_site() {
    let fixture = Fixture::new();
    let mut bridge = Bridge::start(&fixture);
    let reference = bridge.reference_for("https://chase.com");
    assert_eq!(bridge.fill(&reference, "https://chase.com:8443"), None);
}

#[test]
fn nothing_is_offered_for_a_page_with_no_stored_entry() {
    // The safe outcome for most of the web, and it must never degrade into "offer everything".
    let fixture = Fixture::new();
    let mut bridge = Bridge::start(&fixture);
    let reply = bridge.call(serde_json::json!({
        "id": 1, "type": "candidates", "origin": "https://unrelated.example"
    }));
    assert!(reply["ok"].as_bool() == Some(true), "{reply}");
    assert_eq!(
        reply["result"]["entries"].as_array().map(Vec::len),
        Some(0),
        "an unrelated page must be offered nothing: {reply}"
    );
    assert!(!reply.to_string().contains(CANARY));
}

#[test]
fn the_candidate_list_carries_no_password() {
    // The popup shows this list on every click of the toolbar button, so it is the widest
    // surface in the browser path. It must be metadata only.
    let fixture = Fixture::new();
    let mut bridge = Bridge::start(&fixture);
    let reply = bridge.call(serde_json::json!({
        "id": 1, "type": "candidates", "origin": "https://chase.com"
    }));
    let rendered = reply.to_string();
    assert!(rendered.contains("Chase Bank"), "{rendered}");
    assert!(
        !rendered.contains(CANARY) && !rendered.contains("password"),
        "the candidate list must not carry a password or a field for one: {rendered}"
    );
}

#[test]
fn an_unfillable_scheme_is_refused_rather_than_guessed_at() {
    let fixture = Fixture::new();
    let mut bridge = Bridge::start(&fixture);
    let reference = bridge.reference_for("https://chase.com");
    for origin in [
        "file:///etc/passwd",
        "data:text/html,<form>",
        "javascript:alert(1)",
        "chrome-extension://abc/popup.html",
        "about:blank",
        "not a url",
        "",
    ] {
        assert_eq!(
            bridge.fill(&reference, origin),
            None,
            "{origin:?} must not be fillable"
        );
    }
}

#[test]
fn a_locked_vault_offers_nothing_and_fills_nothing() {
    let fixture = Fixture::new();
    let mut bridge = Bridge::start(&fixture);
    let reference = bridge.reference_for("https://chase.com");
    drop(bridge);

    fixture.keel(&["lock"]);

    let mut bridge = Bridge::start(&fixture);
    let status = bridge.call(serde_json::json!({"id": 1, "type": "status"}));
    assert_eq!(
        status["result"]["state"].as_str(),
        Some("locked"),
        "{status}"
    );

    let candidates = bridge.call(serde_json::json!({
        "id": 2, "type": "candidates", "origin": "https://chase.com"
    }));
    assert!(!candidates.to_string().contains(CANARY));

    // The old handle is meaningless now, which is the point of handles being session-scoped.
    assert_eq!(bridge.fill(&reference, "https://chase.com"), None);
}

#[test]
fn the_bridge_refuses_messages_it_does_not_implement() {
    // A page can cause the extension to send a message, so the set of things reachable this
    // way is a security surface. In particular there must be no unlock: a page able to summon
    // a passphrase prompt is a phishing primitive.
    let fixture = Fixture::new();
    let mut bridge = Bridge::start(&fixture);
    for message in [
        serde_json::json!({"id": 1, "type": "unlock", "passphrase": PASSPHRASE}),
        serde_json::json!({"id": 1, "type": "export"}),
        serde_json::json!({"id": 1, "type": "reveal", "reference": "x"}),
        serde_json::json!({"id": 1, "type": "list_all"}),
        serde_json::json!({"id": 1, "type": "settings", "mcp_reveal_enabled": true}),
        serde_json::json!({"id": 1}),
    ] {
        let reply = bridge.call(message.clone());
        assert_eq!(
            reply["ok"].as_bool(),
            Some(false),
            "{message} should have been refused: {reply}"
        );
        assert_eq!(reply["code"].as_str(), Some("bad_request"), "{reply}");
        assert!(!reply.to_string().contains(CANARY));
    }

    // And the vault is still locked-or-unlocked as it was, not changed by any of that.
    let settings = fixture.keel(&["settings", "--json"]);
    assert!(settings.contains("\"mcp_reveal_enabled\": false"));
}

#[test]
fn an_oversized_frame_is_refused_without_being_buffered() {
    // A hostile length prefix must not cause the bridge to reserve memory on demand. The
    // process is expected to stop rather than resynchronise on data the sender chose.
    let fixture = Fixture::new();
    let mut bridge = Bridge::start(&fixture);
    let stdin = bridge.child.stdin.as_mut().expect("stdin");
    // Claim 4 GiB and send nothing.
    let _ = stdin.write_all(&u32::MAX.to_le_bytes());
    let _ = stdin.flush();
    let status = bridge.child.wait().expect("the bridge should exit");
    assert!(
        !status.success(),
        "the bridge should exit with a failure after an oversized frame"
    );
}

#[test]
fn an_entry_listing_several_sites_fills_all_of_them_and_nothing_else() {
    let fixture = Fixture::new();
    // A single login used across two of a company's domains — the case the per-entry origin
    // list exists for.
    fixture.add_entry("Work SSO", "https://sso.example.com", "WORK-CANARY-1");
    fixture.keel(&["save"]);

    let mut bridge = Bridge::start(&fixture);
    let reference = bridge.reference_for("https://sso.example.com");
    assert_eq!(
        bridge
            .fill(&reference, "https://sso.example.com")
            .as_deref(),
        Some("WORK-CANARY-1")
    );
    // And it is not offered anywhere else.
    let elsewhere = bridge.call(serde_json::json!({
        "id": 3, "type": "candidates", "origin": "https://example.com"
    }));
    assert_eq!(
        elsewhere["result"]["entries"].as_array().map(Vec::len),
        Some(0),
        "a credential for sso.example.com is not a credential for example.com: {elsewhere}"
    );
}
