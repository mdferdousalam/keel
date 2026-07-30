//! End-to-end tests driving the real `keel` binary against a real agent.
//!
//! These are the tests that would catch an integration mistake no unit test can see: a
//! protocol field renamed on one side only, an exit code that drifted, a secret that starts
//! appearing where it should not. They run the actual binaries over a real Unix socket.
//!
//! Each test gets its own temporary directory, socket, and agent, so they cannot interfere
//! with each other or with a developer's real vault. The `interactive` KDF tier keeps the
//! suite fast; real vaults default to `balanced`.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PASSPHRASE: &str = "correct-horse-battery-staple";

/// Serialises the fixtures.
///
/// Each fixture creates a vault, which means a real Argon2 derivation. Even at the cheapest
/// tier that is 256 MiB, so eighteen tests in parallel would ask for over four gigabytes at
/// once and spend the difference in swap — which showed up as tests apparently hanging
/// rather than as an out-of-memory error. Serialising costs a few seconds of wall clock and
/// makes the suite deterministic.
static FIXTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// An isolated Keel installation for one test.
struct Fixture {
    dir: tempfile::TempDir,
    socket: PathBuf,
    vault: PathBuf,
    passphrase_file: PathBuf,
    /// Held for the fixture's lifetime. `PoisonError` is ignored because a panicking test
    /// has already failed and must not cascade into every later test.
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
        write_passphrase(&passphrase_file, PASSPHRASE);
        Self {
            dir,
            socket,
            vault,
            passphrase_file,
            _guard: guard,
        }
    }

    /// Path to a built binary from the same target directory as the test.
    fn binary(name: &str) -> PathBuf {
        // The test binary lives in target/<profile>/deps, so the products are two levels up.
        let mut path = std::env::current_exe().expect("test binary path");
        path.pop();
        if path.ends_with("deps") {
            path.pop();
        }
        path.join(name)
    }

    fn keel(&self) -> Command {
        let mut command = Command::new(Self::binary("keel"));
        command
            .env("KEEL_AGENT_SOCKET", &self.socket)
            .env("KEEL_VAULT", &self.vault)
            .env("KEEL_AGENT_BINARY", Self::binary("keel-agent"))
            .env("KEEL_PASSPHRASE_FILE", &self.passphrase_file)
            // Retire the agent quickly once the test is done, so the suite does not leave a
            // daemon per test behind.
            .env("KEEL_AGENT_IDLE_EXIT_SECS", "5")
            // Keep a developer's real config out of the picture entirely.
            .env_remove("XDG_RUNTIME_DIR");
        command
    }

    /// Run a command and return its output, asserting nothing.
    fn run(&self, args: &[&str]) -> Output {
        self.keel().args(args).output().expect("run keel")
    }

    /// Run a command that must succeed, returning stdout.
    fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "`keel {}` failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Create and unlock a vault.
    fn init(&self) {
        self.ok(&["init", "--tier", "interactive"]);
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Lock the vault so no agent is left holding keys, then let its idle timeout retire
        // it. Without this the suite would leave one daemon per test running.
        //
        // Only if a socket is actually there: `keel lock` would otherwise *spawn* an agent
        // in order to tell it to lock, which is both absurd and slow — the client's
        // connect-or-spawn behaviour is right for a user at a prompt and wrong here.
        if self.socket.exists() {
            let _ = self.keel().arg("lock").output();
        }
    }
}

fn write_passphrase(path: &Path, value: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, value).expect("write passphrase file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict passphrase file");
}

// ---------------------------------------------------------------------------

#[test]
fn a_vault_can_be_created_and_reports_its_state() {
    let fixture = Fixture::new();

    let before = fixture.ok(&["status"]);
    assert!(before.contains("NoVault"), "got: {before}");

    fixture.init();
    assert!(fixture.vault.is_file(), "the vault file should exist");

    let after = fixture.ok(&["status"]);
    assert!(after.contains("Unlocked"), "got: {after}");
    assert!(after.contains("Entries: 0"));
}

#[test]
fn an_entry_survives_add_lock_unlock_and_read() {
    // The single most important end-to-end property: a password put in comes back out
    // after the keys have been wiped and re-derived from the passphrase.
    let fixture = Fixture::new();
    fixture.init();

    let mut add = fixture.keel();
    add.args(["add", "Old Forum", "--username", "ada", "--password-stdin"]);
    let output = write_stdin(add, "hunter2");
    assert!(output.status.success(), "add failed: {}", stderr(&output));

    fixture.ok(&["lock"]);
    fixture.ok(&["unlock"]);

    let value = fixture.ok(&["get", "Old Forum", "--show"]);
    assert_eq!(value.trim(), "hunter2");
}

#[test]
fn a_generated_password_is_strong_and_never_printed() {
    // The `Generate` path exists so a caller can store a password it never sees. The CLI
    // reports the strength and must not leak the value.
    let fixture = Fixture::new();
    fixture.init();

    let output = fixture.ok(&["add", "Example Bank", "--username", "ada@example.com"]);
    assert!(output.contains("bits of entropy"), "got: {output}");

    // Twenty characters over the default 88-character alphabet.
    let bits: f64 = output
        .split("(")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();
    assert!(bits > 120.0, "expected a strong password, got {bits} bits");

    // The stored value must be readable, and must not have appeared in the add output.
    let stored = fixture.ok(&["get", "Example Bank", "--show"]);
    let stored = stored.trim();
    assert_eq!(stored.chars().count(), 20);
    assert!(
        !output.contains(stored),
        "the generated password leaked into the add output"
    );
}

#[test]
fn locking_makes_reads_fail_with_a_distinct_exit_code() {
    // Scripts branch on these codes, so they are part of the interface.
    let fixture = Fixture::new();
    fixture.init();
    fixture.ok(&["add", "Thing", "--username", "u"]);
    fixture.ok(&["lock"]);

    let output = fixture.run(&["get", "Thing", "--show"]);
    assert_eq!(output.status.code(), Some(2), "locked should exit 2");
    assert!(stderr(&output).contains("locked"));
    assert!(
        stderr(&output).contains("keel unlock"),
        "the error should say what to do next"
    );
}

#[test]
fn a_missing_entry_exits_with_not_found() {
    let fixture = Fixture::new();
    fixture.init();
    let output = fixture.run(&["get", "nothing-like-this", "--show"]);
    assert_eq!(output.status.code(), Some(3), "not found should exit 3");
}

#[test]
fn the_wrong_passphrase_is_refused_without_saying_which_factor_was_wrong() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.ok(&["lock"]);

    let wrong = fixture.path().join("wrong");
    write_passphrase(&wrong, "definitely-not-the-passphrase");
    let output = fixture
        .keel()
        .env("KEEL_PASSPHRASE_FILE", &wrong)
        .arg("unlock")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let message = stderr(&output).to_lowercase();
    assert!(message.contains("could not unlock"), "got: {message}");
    // Must not hint at which factor failed.
    assert!(!message.contains("keyfile is"));
    assert!(!message.contains("passphrase is incorrect"));
}

#[test]
fn a_world_readable_passphrase_file_is_refused() {
    // A passphrase file the whole machine can read defeats the vault entirely, so this
    // refuses rather than warns: a warning in a script's output is a warning nobody reads.
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.init();
    fixture.ok(&["lock"]);

    std::fs::set_permissions(
        &fixture.passphrase_file,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let output = fixture.run(&["unlock"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("readable by other users"),
        "{}",
        stderr(&output)
    );
    assert!(stderr(&output).contains("chmod 600"));
}

#[test]
fn rotation_replaces_the_password_and_keeps_the_old_one() {
    let fixture = Fixture::new();
    fixture.init();

    let mut add = fixture.keel();
    add.args(["add", "Site", "--username", "u", "--password-stdin"]);
    write_stdin(add, "original-password");

    let before = fixture.ok(&["get", "Site", "--show"]);
    assert_eq!(before.trim(), "original-password");

    fixture.ok(&["rotate", "Site"]);
    let after = fixture.ok(&["get", "Site", "--show"]);
    assert_ne!(after.trim(), "original-password");
    assert_eq!(after.trim().chars().count(), 20);

    // The change must survive a lock cycle, which proves it was saved rather than only
    // held in memory.
    fixture.ok(&["lock"]);
    fixture.ok(&["unlock"]);
    assert_eq!(fixture.ok(&["get", "Site", "--show"]).trim(), after.trim());
}

#[test]
fn search_and_list_report_metadata_without_secrets() {
    let fixture = Fixture::new();
    fixture.init();

    let mut add = fixture.keel();
    add.args([
        "add",
        "Example Bank",
        "--username",
        "ada@example.com",
        "--url",
        "https://bank.example.com",
        "--password-stdin",
    ]);
    write_stdin(add, "a-very-distinctive-secret");
    fixture.ok(&["add", "Mail", "--username", "grace@other.test"]);

    let listing = fixture.ok(&["list"]);
    assert!(listing.contains("Example Bank"));
    assert!(listing.contains("ada@example.com"));
    assert!(
        !listing.contains("a-very-distinctive-secret"),
        "listings must not contain secrets"
    );

    let found = fixture.ok(&["search", "bank"]);
    assert!(found.contains("Example Bank"));
    assert!(!found.contains("Mail"));
    assert!(!found.contains("a-very-distinctive-secret"));

    // JSON output is the scripting interface and must be equally clean.
    let json = fixture.ok(&["--json", "list"]);
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert!(parsed["entries"].is_array());
    assert!(!json.contains("a-very-distinctive-secret"));
}

#[test]
fn json_output_is_machine_readable_for_every_read_command() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.ok(&["add", "Thing", "--username", "u"]);

    for args in [
        vec!["--json", "status"],
        vec!["--json", "list"],
        vec!["--json", "search", "Thing"],
        vec!["--json", "generate"],
    ] {
        let out = fixture.ok(&args);
        serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
            panic!(
                "`keel {}` produced invalid JSON: {e}\n{out}",
                args.join(" ")
            )
        });
    }
}

#[test]
fn generate_works_without_a_vault_at_all() {
    // Generation needs no vault access, so it must work before `init` and while locked.
    let fixture = Fixture::new();
    let output = fixture.ok(&["generate", "--words", "7"]);
    assert_eq!(output.trim().split('-').count(), 7);

    let chars = fixture.ok(&["generate", "--length", "32"]);
    assert_eq!(chars.trim().chars().count(), 32);
}

#[test]
fn getting_without_show_does_not_print_the_secret() {
    // The default path applies the secret rather than printing it. Without a desktop app
    // connected that fails — but it must fail *without* having printed anything.
    let fixture = Fixture::new();
    fixture.init();
    let mut add = fixture.keel();
    add.args(["add", "Site", "--username", "u", "--password-stdin"]);
    write_stdin(add, "must-not-be-printed");

    let output = fixture.run(&["get", "Site"]);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
    assert!(
        !combined.contains("must-not-be-printed"),
        "the secret was printed without --show: {combined}"
    );
}

#[test]
fn trashing_an_entry_removes_it_from_listings() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.ok(&["add", "Doomed", "--username", "u"]);
    fixture.ok(&["add", "Keeper", "--username", "u"]);

    fixture.ok(&["rm", "Doomed", "--yes"]);

    let listing = fixture.ok(&["list"]);
    assert!(!listing.contains("Doomed"));
    assert!(listing.contains("Keeper"));

    // And it stays gone across a lock cycle, so the change was persisted.
    fixture.ok(&["lock"]);
    fixture.ok(&["unlock"]);
    assert!(!fixture.ok(&["list"]).contains("Doomed"));
}

#[test]
fn an_ambiguous_name_is_refused_rather_than_guessed() {
    // Acting on the wrong entry could rotate a password the user did not mean to touch.
    let fixture = Fixture::new();
    fixture.init();
    fixture.ok(&["add", "Bank One", "--username", "u"]);
    fixture.ok(&["add", "Bank Two", "--username", "u"]);

    let output = fixture.run(&["get", "Bank", "--show"]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(message.contains("matches 2 entries"), "got: {message}");
    assert!(message.contains("be more specific"));
}

#[test]
fn creating_a_vault_twice_is_refused() {
    // Overwriting a vault would be unrecoverable.
    let fixture = Fixture::new();
    fixture.init();
    let output = fixture.run(&["init", "--tier", "interactive"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("already exists"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn no_secret_appears_in_the_agent_audit_log() {
    // The audit log is written next to the vault and describes secret access. It must
    // record what happened without recording the secrets themselves.
    let fixture = Fixture::new();
    fixture.init();
    let mut add = fixture.keel();
    add.args(["add", "Site", "--username", "u", "--password-stdin"]);
    write_stdin(add, "audit-canary-value");
    fixture.ok(&["get", "Site", "--show"]);

    let audit = fixture.path().join("vault.keel.audit");
    if audit.is_file() {
        let bytes = std::fs::read(&audit).unwrap();
        assert!(
            !bytes
                .windows(b"audit-canary-value".len())
                .any(|w| w == b"audit-canary-value"),
            "the audit log contains a secret"
        );
        // Nor should it contain the entry title in plaintext.
        assert!(
            !bytes.windows(4).any(|w| w == b"Site"),
            "the audit log contains an entry title in plaintext"
        );
    }
}

#[test]
fn the_vault_file_is_not_readable_by_other_users() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.init();
    let mode = std::fs::metadata(&fixture.vault)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode & 0o077, 0, "vault mode is {mode:o}");
}

#[test]
fn a_secret_never_appears_in_the_vault_file() {
    // The whole point. If a password is findable in the ciphertext, encryption failed.
    let fixture = Fixture::new();
    fixture.init();
    let mut add = fixture.keel();
    add.args(["add", "Site", "--username", "u", "--password-stdin"]);
    write_stdin(add, "plaintext-canary-98765");

    let bytes = std::fs::read(&fixture.vault).unwrap();
    let needle = b"plaintext-canary-98765";
    assert!(
        !bytes.windows(needle.len()).any(|w| w == needle),
        "the password appears in plaintext in the vault file"
    );
    // The entry title is metadata, and metadata is encrypted too.
    assert!(
        !bytes.windows(4).any(|w| w == b"Site"),
        "the entry title appears in plaintext in the vault file"
    );
}

// ---------------------------------------------------------------------------

fn write_stdin(mut command: Command, input: &str) -> Output {
    use std::io::Write as _;
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn keel");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait for keel")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn the_health_report_finds_reuse_and_weakness_without_printing_a_password() {
    // Exercises the whole chain: the CLI asks, the agent decrypts every record, the
    // assessment groups by keyed hash, and only statistics come back. The canary is
    // the point — this is the operation with the widest exposure to plaintext, so the
    // test asserts on what came out, not only on what was found.
    const SHARED: &str = "canary-shared-Zq7-mV4xKp";
    let fixture = Fixture::new();
    fixture.init();

    for title in ["Old Forum", "Old Wiki"] {
        let mut add = fixture.keel();
        add.args(["add", title, "--username", "ada", "--password-stdin"]);
        let output = write_stdin(add, SHARED);
        assert!(output.status.success(), "add failed: {}", stderr(&output));
    }
    let mut add = fixture.keel();
    add.args(["add", "Router", "--username", "admin", "--password-stdin"]);
    let output = write_stdin(add, "123456");
    assert!(output.status.success(), "add failed: {}", stderr(&output));
    // One entry with a generated password, which must not be flagged.
    fixture.ok(&["add", "Bank", "--username", "ada"]);

    let report = fixture.ok(&["audit"]);

    // The reuse group is the finding that matters most.
    assert!(
        report.contains("Reused passwords"),
        "should report reuse: {report}"
    );
    assert!(report.contains("Old Forum") && report.contains("Old Wiki"));
    // The weak one is found too.
    assert!(report.contains("Router"), "should flag 123456: {report}");
    // The generated password is not flagged.
    assert!(
        !report.contains("Bank"),
        "a generated password should not be flagged: {report}"
    );
    assert!(
        report.contains("3 of 4 entries need attention"),
        "got: {report}"
    );

    // And the thing that would make all of the above worthless.
    assert!(
        !report.contains(SHARED) && !report.contains("canary") && !report.contains("123456"),
        "the health report printed a password value: {report}"
    );
}

#[test]
fn the_health_report_is_machine_readable_and_carries_no_password_field() {
    const SHARED: &str = "canary-shared-Zq7-mV4xKp";
    let fixture = Fixture::new();
    fixture.init();
    for title in ["A", "B"] {
        let mut add = fixture.keel();
        add.args(["add", title, "--username", "ada", "--password-stdin"]);
        let output = write_stdin(add, SHARED);
        assert!(output.status.success(), "add failed: {}", stderr(&output));
    }

    let json = fixture.ok(&["audit", "--json"]);
    assert!(!json.contains("canary"), "JSON leaked the password: {json}");
    // A `password` key must never appear. Checked as a string rather than by parsing,
    // so it catches the value appearing anywhere at any nesting depth.
    assert!(
        !json.contains("\"password\""),
        "the health report grew a password field: {json}"
    );
    assert!(json.contains("\"reused\""), "got: {json}");
    assert!(json.contains("\"examined\": 2"), "got: {json}");
}
