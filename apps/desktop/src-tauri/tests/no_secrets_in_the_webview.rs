// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The GUI invariant, checked rather than asserted in prose.
//!
//! The claim is that no secret stored in the vault ever reaches the webview. This drives the
//! real command layer against a real agent holding a real vault, serialises every result
//! exactly as Tauri would before handing it to JavaScript, and searches for a canary
//! password.
//!
//! Why serialised rather than inspected field by field: serialisation is what actually
//! crosses the boundary. A field-by-field check would pass while a `#[serde(flatten)]`, a
//! newly added variant, or a `Debug` impl folded into a message quietly carried a password
//! across. Searching the bytes that JavaScript receives is the only check that cannot be
//! fooled by the shape of the types.
//!
//! The plan calls this a release blocker, so it is written to fail loudly and to print
//! everything the webview would have seen when it does.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use keel_desktop::masking;
use keel_proto::{ClientKind, EntryRef, Field, Request, Response, SecretAction};

/// The password that must not appear in anything the webview receives.
const CANARY: &str = "CANARY-GUI-PASSWORD-DO-NOT-LEAK-8842";
const PASSPHRASE: &str = "correct-horse-battery-staple";

/// Serialised for the same reason every other suite here is: each fixture runs a real
/// Argon2 derivation, and several at once go to swap rather than reporting an error.
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
        // The environment has to be set before anything connects, because the client reads
        // it to find the socket.
        std::env::set_var("KEEL_AGENT_SOCKET", &fixture.socket);
        std::env::set_var("KEEL_VAULT", &fixture.vault);
        std::env::set_var("KEEL_AGENT_BINARY", binary("keel-agent"));
        std::env::set_var("KEEL_PASSPHRASE_FILE", &fixture.passphrase_file);
        std::env::set_var("KEEL_AGENT_IDLE_EXIT_SECS", "20");
        std::env::remove_var("XDG_RUNTIME_DIR");

        fixture.keel(&["init", "--tier", "interactive"]);
        fixture.store_canary();
        fixture
    }

    fn command(&self) -> Command {
        let mut command = Command::new(binary("keel"));
        command
            .env("KEEL_AGENT_SOCKET", &self.socket)
            .env("KEEL_VAULT", &self.vault)
            .env("KEEL_AGENT_BINARY", binary("keel-agent"))
            .env("KEEL_PASSPHRASE_FILE", &self.passphrase_file)
            .env("KEEL_AGENT_IDLE_EXIT_SECS", "20")
            .env_remove("XDG_RUNTIME_DIR");
        command
    }

    fn keel(&self, args: &[&str]) {
        let output = self.command().args(args).output().expect("run keel");
        assert!(
            output.status.success(),
            "`keel {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn store_canary(&self) {
        let mut child = self
            .command()
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
            .expect("spawn keel add");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(CANARY.as_bytes())
            .expect("write the canary");
        let output = child.wait_with_output().expect("keel add");
        assert!(
            output.status.success(),
            "storing the canary failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.socket.exists() {
            let _ = self.command().arg("lock").output();
        }
    }
}

/// A direct agent connection, standing in for the shell's `AgentLink`.
///
/// The Tauri commands themselves cannot be called without a running webview, so the test
/// exercises the layer they are made of: the same requests, through the same `masking`
/// constructors, serialised the same way. That is where a leak would live — a command body
/// is three lines of plumbing over these two things.
fn agent() -> keel_client::Client {
    keel_client::Client::connect(ClientKind::Gui, "keel-desktop-test")
        .expect("connect to the agent")
}

/// Everything the webview would have received, as one string.
struct Transcript {
    seen: Vec<String>,
}

impl Transcript {
    fn new() -> Self {
        Self { seen: Vec::new() }
    }

    /// Record a view exactly as Tauri would hand it to JavaScript.
    fn record<T: serde::Serialize>(&mut self, label: &str, value: &T) {
        let json = serde_json::to_string(value).expect("a view must serialise");
        self.seen.push(format!("{label}: {json}"));
    }

    fn record_result<T: serde::Serialize>(&mut self, label: &str, value: &Result<T, String>) {
        match value {
            Ok(v) => self.record(label, v),
            // Errors cross the boundary too, and an error is exactly where a careless
            // implementation interpolates the thing it failed on.
            Err(e) => self.seen.push(format!("{label} error: {e}")),
        }
    }

    fn assert_clean(&self) {
        let blob = self.seen.join("\n");
        assert!(
            !blob.contains(CANARY),
            "a stored password reached the webview. Everything it would have seen:\n{blob}"
        );
        // Fragments are just as bad: half a password is a much smaller search space.
        for fragment in ["CANARY-GUI", "DO-NOT-LEAK", "8842"] {
            assert!(
                !blob.contains(fragment),
                "a fragment of a stored password ({fragment:?}) reached the webview:\n{blob}"
            );
        }
    }
}

#[test]
fn no_command_result_carries_a_stored_password() {
    let _fixture = Fixture::new();
    let mut client = agent();
    let mut transcript = Transcript::new();

    // Status.
    let status = client.request(&Request::Status).expect("status");
    transcript.record_result("status", &masking::StatusView::from_response(&status));

    // The entry list, which is where a naive implementation would include the password.
    let listed = client
        .request(&Request::List {
            limit: None,
            offset: None,
        })
        .expect("list");
    let views = masking::entry_views(&listed).expect("entry views");
    transcript.record("list_entries", &views);
    assert!(
        views.iter().any(|v| v.title == "Chase Bank"),
        "the canary entry should be listed"
    );

    // Search.
    let found = client
        .request(&Request::Search {
            query: "chase".to_owned(),
            limit: None,
        })
        .expect("search");
    transcript.record_result("search", &masking::entry_views(&found));

    let reference = views
        .first()
        .map(|v| v.reference.clone())
        .expect("a reference");

    // Detail, the panel that shows the password field.
    let detail = client
        .request(&Request::GetMetadata {
            reference: EntryRef(reference.clone()),
        })
        .expect("metadata");
    let detail_view = masking::DetailView::from_response(&detail).expect("detail view");
    transcript.record("entry_detail", &detail_view);
    assert!(
        detail_view.password.present,
        "the entry has a password, so the mask should say so"
    );
    assert!(
        detail_view
            .password
            .bullets
            .chars()
            .all(|c| c == '\u{2022}'),
        "the mask must be bullets and nothing else"
    );

    // Copying. The description crosses the boundary; the value must not.
    let applied = client.request(&Request::UseSecret {
        reference: EntryRef(reference.clone()),
        field: Field::Password,
        action: SecretAction::Clipboard,
    });
    match applied {
        Ok(Response::Applied { description }) => transcript.record("copy_field", &description),
        Ok(other) => transcript.record("copy_field unexpected", &masking::variant_name(&other)),
        // A headless runner may have no clipboard, which is a legitimate failure and is
        // itself worth putting through the canary check.
        Err(e) => transcript.record("copy_field error", &e.to_string()),
    }

    // Health, which decrypts every record — the widest exposure in the product.
    let health = client.request(&Request::VaultHealth).expect("health");
    transcript.record_result("health", &masking::HealthView::from_response(&health));

    // The activity log.
    let audit = client
        .request(&Request::AuditTail { limit: Some(100) })
        .expect("audit");
    transcript.record_result("activity", &masking::LogView::from_response(&audit));

    // Grants and approvals.
    let grants = client.request(&Request::ListGrants).expect("grants");
    transcript.record_result("grants", &masking::grant_views(&grants));
    let approvals = client
        .request(&Request::PendingApprovals)
        .expect("pending approvals");
    if let Response::PendingApprovals { approvals } = approvals {
        transcript.record("pending_approvals", &approvals);
    }

    // Rotating produces a new password; the strength may cross, the value may not.
    let rotated = client
        .request(&Request::RotateSecret {
            reference: EntryRef(reference),
            secret: keel_proto::SecretSource::Generate {
                length: None,
                words: None,
            },
        })
        .expect("rotate");
    transcript.record_result("rotate", &masking::CreatedView::from_response(&rotated));

    transcript.assert_clean();
}

#[test]
fn the_shell_cannot_ask_for_a_plaintext_secret_at_all() {
    // Stronger than checking that results are masked: the command surface has no reveal and
    // no export, so there is no code path from the webview to a plaintext value. If either
    // is ever added, this test is where the decision has to be argued.
    let source = include_str!("../src/lib.rs");
    // `Request::Reveal {` and not `Request::Reveal`, because `Request::RevealOnScreen` is
    // permitted and is a different thing: it returns no secret. The agent spawns the overlay and
    // pipes the value there itself, so the plaintext never enters this process. Matching the
    // brace keeps the distinction sharp instead of banning a name prefix.
    for forbidden in ["Request::Reveal {", "Request::Export {"] {
        assert!(
            !source.contains(forbidden),
            "the desktop shell must not be able to send {forbidden}: a reveal that returned \
             the value would put a password in a webview, and exporting belongs at the command \
             line where a passphrase can be re-entered. `RevealOnScreen`, which returns no \
             secret, is the supported way to show one."
        );
    }
    // And nothing in the shell should be handling a response that carries plaintext other
    // than to name it in an error.
    let masking_source = include_str!("../src/masking.rs");
    assert!(
        masking_source.contains("Response::Secret { .. } => \"secret\""),
        "the secret variant should be named for errors and never destructured for its value"
    );
}

#[test]
fn a_mask_never_carries_the_length_of_a_real_password() {
    // The detail view uses a fixed-width mask. A width that tracked the true length would
    // put the password's length on screen for anyone standing behind the user, and into the
    // webview for anything reading the DOM.
    let short = masking::Mask::present();
    let also = masking::Mask::present();
    assert_eq!(short.bullets, also.bullets);
    assert!(!short.bullets.is_empty());
}
