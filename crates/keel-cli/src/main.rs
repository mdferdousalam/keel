//! The `keel` command.
//!
//! # Secret handling rules
//!
//! These are not conveniences; each one closes a specific hole:
//!
//! * **No secret is ever accepted in `argv`.** There is deliberately no `--password VALUE`
//!   flag anywhere. Arguments are visible to every process on the machine via `ps`, and
//!   they land in shell history where they outlive the session. Secrets come from an
//!   interactive prompt, from stdin, or from a file the user controls.
//! * **`get` copies rather than prints by default.** A password on a terminal ends up in
//!   scrollback, in a screen recording, and over the shoulder of whoever is walking past.
//!   Printing requires `--show`, and piping requires being explicit about the field.
//! * **Exit codes are stable** and defined in `keel-proto`, so scripts can branch on
//!   "locked" versus "not found" without parsing prose.

// This binary's entire purpose is writing to a terminal. The workspace forbids printing so
// that *library* code cannot reach one — above all so a secret cannot arrive there by
// accident — which is a rule about libraries, not about the program that exists to produce
// output. Every print site here was written deliberately, and `get` requires an explicit
// `--show` before a secret is ever among them.
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code may panic to keep failures readable; the lints protect library code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

mod verify;

use clap::{Parser, Subcommand};
use keel_client::{Client, Error as ClientError};
use keel_proto::{
    ClientKind, EntryInput, EntryRef, ErrorCode, Field, Request, Response, SecretAction,
    SecretSource,
};

/// Client identifier reported to the agent.
const CLIENT_ID: &str = "keel-cli";

#[derive(Parser)]
#[command(
    name = "keel",
    version,
    about = "A local-first password manager",
    long_about = "Keel keeps your passwords in one encrypted file on this machine.\n\
                  There is no server, no account, and no telemetry.\n\n\
                  Passphrases are never accepted as command-line arguments, because \
                  arguments are visible to every process via `ps` and persist in shell \
                  history. For automation, point KEEL_PASSPHRASE_FILE at a file with mode \
                  600, or pipe the passphrase on standard input."
)]
struct Cli {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault.
    Init {
        /// Key-derivation cost: interactive, balanced, or paranoid.
        #[arg(long, default_value = "balanced")]
        tier: String,
    },

    /// Unlock the vault for this session.
    Unlock {
        /// Proceed even if the vault looks older than the last version this device saw.
        ///
        /// Only pass this if you know you restored a backup. See `keel status`.
        #[arg(long)]
        accept_rollback: bool,
    },

    /// Lock the vault and wipe keys from memory.
    Lock,

    /// Show lock state and session information.
    Status,

    /// List entries.
    List {
        /// Maximum entries to show.
        #[arg(long, default_value_t = 25)]
        limit: u32,
    },

    /// Search entries by title, username, or origin.
    Search {
        /// What to look for. At least two characters.
        query: String,
    },

    /// Add an entry.
    ///
    /// The password is generated unless --password-stdin is given. There is deliberately no
    /// flag that takes a password as an argument.
    Add {
        /// Entry title.
        title: String,
        /// Username or account identifier.
        #[arg(long, short)]
        username: Option<String>,
        /// Site or application origin, repeatable.
        #[arg(long)]
        url: Vec<String>,
        /// Tag, repeatable.
        #[arg(long)]
        tag: Vec<String>,
        /// Read the password from standard input instead of generating one.
        #[arg(long)]
        password_stdin: bool,
        /// Generated password length.
        #[arg(long, default_value_t = 20)]
        length: u32,
        /// Generate a passphrase of this many words instead of a character password.
        #[arg(long)]
        words: Option<u32>,
    },

    /// Retrieve an entry's secret.
    ///
    /// Copies to the clipboard by default; printing requires --show.
    Get {
        /// Entry title or reference.
        name: String,
        /// Which field to retrieve.
        #[arg(long, value_parser = parse_field, default_value = "password")]
        field: Field,
        /// Print the value to standard output.
        ///
        /// Off by default: a password on a terminal ends up in scrollback and in screen
        /// recordings.
        #[arg(long)]
        show: bool,
    },

    /// Replace an entry's password, keeping the old one in history.
    Rotate {
        /// Entry title or reference.
        name: String,
        /// Generated password length.
        #[arg(long, default_value_t = 20)]
        length: u32,
        /// Generate a passphrase of this many words instead.
        #[arg(long)]
        words: Option<u32>,
    },

    /// Move an entry to the trash. It can be restored until purged.
    Rm {
        /// Entry title or reference.
        name: String,
        /// Do not ask for confirmation.
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Generate a password without storing it.
    Generate {
        /// Length in characters.
        #[arg(long, default_value_t = 20)]
        length: u32,
        /// Generate a passphrase of this many words instead.
        #[arg(long)]
        words: Option<u32>,
    },

    /// Save pending changes to disk.
    Save,

    /// Import passwords from a CSV exported by another password manager or browser.
    ///
    /// The file format is detected automatically. Chrome, Firefox, Safari, Bitwarden,
    /// 1Password, LastPass, and KeePass exports are all recognised.
    Import {
        /// Path to the exported CSV.
        file: std::path::PathBuf,
        /// Show what would be imported without changing the vault.
        #[arg(long)]
        dry_run: bool,
        /// Overwrite and delete the CSV after a successful import.
        ///
        /// Best effort: on an SSD or a copy-on-write filesystem this does not reliably destroy
        /// the old contents. Full-disk encryption is what actually protects them.
        #[arg(long)]
        shred: bool,
    },

    /// Grant an AI agent or browser extension access to the vault.
    ///
    /// Agents start with no access at all. This is how a human authorises one, and it is
    /// deliberately a separate, explicit act.
    Grant {
        /// Client identifier, as the agent reports it. For the MCP server this is
        /// KEEL_MCP_CLIENT_ID, defaulting to "keel-mcp".
        client_id: String,
        /// Capability to grant, repeatable: metadata, use, reveal, write, totp, audit.
        ///
        /// `use` lets the agent apply a password without seeing it, and is what you want for
        /// "log me in". `reveal` hands over plaintext and still requires you to approve every
        /// request.
        #[arg(long = "scope", short = 's', required = true)]
        scopes: Vec<String>,
        /// Lifetime in minutes. Defaults to 15.
        #[arg(long, default_value_t = 15)]
        minutes: u64,
        /// Restrict to entries carrying a tag matching this pattern, for example "work/*".
        #[arg(long)]
        tag: Option<String>,
        /// Grant access to every entry.
        ///
        /// Required explicitly when no --tag is given: "all my passwords" should not be a
        /// default.
        #[arg(long)]
        all_entries: bool,
    },

    /// List the access grants currently in force.
    Grants,

    /// Report which stored passwords are reused, weak, or old.
    ///
    /// Decrypts every record to do it, so it is available only here and in the desktop
    /// app — never to an AI agent or the browser extension, whatever they have been
    /// granted. No password value is printed.
    Audit,

    /// Revoke every grant held by a client.
    Revoke {
        /// Client identifier.
        client_id: String,
    },

    /// Verify the signatures and checksums of a downloaded release.
    ///
    /// Requires both the Ed25519 and the ML-DSA signature to pass. Needs no vault and no
    /// agent.
    VerifyRelease {
        /// Directory containing the downloaded release files.
        directory: std::path::PathBuf,
    },
}

fn parse_field(value: &str) -> Result<Field, String> {
    match value.to_ascii_lowercase().as_str() {
        "password" | "pass" => Ok(Field::Password),
        "username" | "user" => Ok(Field::Username),
        "totp" | "otp" => Ok(Field::Totp),
        "notes" | "note" => Ok(Field::Notes),
        other => Err(format!(
            "unknown field {other:?}; expected password, username, totp, or notes"
        )),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error);
            ExitCode::from(error.exit_code())
        }
    }
}

/// Print an error, with a hint where one is actionable.
fn report(error: &ClientError) {
    eprintln!("keel: {error}");
    match error.code() {
        Some(ErrorCode::Locked) => eprintln!("hint: run `keel unlock` first."),
        Some(ErrorCode::NoVault) => eprintln!("hint: run `keel init` to create a vault."),
        Some(ErrorCode::Conflict) => {
            eprintln!("hint: another Keel instance changed the vault. Retry the command.");
        }
        _ => {}
    }
}

fn run(cli: &Cli) -> Result<(), ClientError> {
    // Verification needs no vault and no agent: it checks bytes on disk. Connecting first
    // would mean a user cannot check a download without starting a daemon.
    if let Command::VerifyRelease { directory } = &cli.command {
        return verify_release(directory, cli.json);
    }

    let mut client = Client::connect(ClientKind::Cli, CLIENT_ID)?;
    match &cli.command {
        Command::Init { tier } => init(&mut client, tier, cli.json),
        Command::Unlock { accept_rollback } => unlock(&mut client, *accept_rollback, cli.json),
        Command::Lock => {
            client.request(&Request::Lock)?;
            emit(cli.json, "Locked.", &serde_json::json!({"locked": true}));
            Ok(())
        }
        Command::Status => status(&mut client, cli.json),
        Command::List { limit } => list(&mut client, *limit, cli.json),
        Command::Search { query } => search(&mut client, query, cli.json),
        Command::Add {
            title,
            username,
            url,
            tag,
            password_stdin,
            length,
            words,
        } => add(
            &mut client,
            title,
            username.as_deref(),
            url,
            tag,
            *password_stdin,
            *length,
            *words,
            cli.json,
        ),
        Command::Get { name, field, show } => get(&mut client, name, *field, *show, cli.json),
        Command::Rotate {
            name,
            length,
            words,
        } => rotate(&mut client, name, *length, *words, cli.json),
        Command::Rm { name, yes } => remove(&mut client, name, *yes, cli.json),
        Command::Generate { length, words } => generate(&mut client, *length, *words, cli.json),
        Command::Save => {
            client.request(&Request::Save)?;
            emit(cli.json, "Saved.", &serde_json::json!({"saved": true}));
            Ok(())
        }
        Command::Grant {
            client_id,
            scopes,
            minutes,
            tag,
            all_entries,
        } => grant(
            &mut client,
            client_id,
            scopes,
            *minutes,
            tag.as_deref(),
            *all_entries,
            cli.json,
        ),
        Command::Import {
            file,
            dry_run,
            shred,
        } => import(&mut client, file, *dry_run, *shred, cli.json),
        Command::Grants => grants(&mut client, cli.json),
        Command::Audit => audit(&mut client, cli.json),
        Command::Revoke { client_id } => {
            client.request(&Request::RevokeAccess {
                client_id: client_id.clone(),
            })?;
            emit(
                cli.json,
                &format!("Revoked all access for {client_id}."),
                &serde_json::json!({"revoked": client_id}),
            );
            Ok(())
        }
        Command::VerifyRelease { .. } => unreachable!("handled before connecting"),
    }
}

/// Import a CSV export.
fn import(
    client: &mut Client,
    file: &std::path::Path,
    dry_run: bool,
    shred_after: bool,
    json: bool,
) -> Result<(), ClientError> {
    let report = keel_import::read_csv(file).map_err(|error| ClientError::Agent {
        code: ErrorCode::BadRequest,
        message: error.to_string(),
    })?;

    if !json {
        println!("{}", report.summary());
    }

    if dry_run {
        // Titles only. Printing usernames for a whole vault would put them all in scrollback,
        // and a dry run is about "is this the right file", not about reviewing every field.
        if json {
            print_json(&serde_json::json!({
                "source": report.source.name(),
                "entries": report.entries.len(),
                "skipped_without_password": report.skipped_without_password,
                "skipped_malformed": report.skipped_malformed,
                "titles": report.entries.iter().map(|e| &e.title).collect::<Vec<_>>(),
            }));
        } else {
            println!("\nWould import:");
            for entry in &report.entries {
                println!("  {}", entry.title);
            }
            println!("\nNothing was changed. Run without --dry-run to import.");
        }
        return Ok(());
    }

    let mut imported = 0usize;
    let mut failed = 0usize;
    for entry in &report.entries {
        let request = Request::CreateEntry {
            input: EntryInput {
                title: entry.title.clone(),
                username: entry.username.clone(),
                origins: if entry.url.is_empty() {
                    Vec::new()
                } else {
                    vec![entry.url.clone()]
                },
                tags: vec!["imported".to_owned()],
                notes: entry.notes.to_string(),
            },
            // The imported password, not a generated one: the point of an import is to keep
            // the credentials that already work.
            secret: SecretSource::Provided {
                value: entry.password.to_string(),
            },
        };
        match client.request(&request) {
            Ok(_) => imported += 1,
            Err(error) => {
                failed += 1;
                // Name the entry, never the reason's payload, and keep going: one bad row must
                // not abandon an import half done.
                eprintln!("keel: could not import {:?}: {error}", entry.title);
            }
        }
    }

    // One save for the whole import, so it lands as a single atomic write rather than several
    // hundred.
    client.request(&Request::Save)?;

    if json {
        print_json(&serde_json::json!({
            "source": report.source.name(),
            "imported": imported,
            "failed": failed,
            "skipped_without_password": report.skipped_without_password,
        }));
    } else {
        println!("\nImported {imported} entries, tagged \"imported\".");
        if failed > 0 {
            println!("{failed} entries could not be imported; see the messages above.");
        }
    }

    if shred_after {
        match keel_import::shred(file) {
            Ok(()) => {
                if !json {
                    println!(
                        "\nDeleted {}. Note that on an SSD or a copy-on-write filesystem this \
                         does not reliably destroy the old contents.",
                        file.display()
                    );
                }
            }
            Err(error) => eprintln!("keel: could not delete the import file: {error}"),
        }
    } else if !json {
        // The file is now the most dangerous thing on the disk. Say so.
        println!("\n{}", keel_import::EXPORT_WARNING);
    }

    Ok(())
}

/// Grant a client access.
#[allow(clippy::too_many_arguments)]
fn grant(
    client: &mut Client,
    client_id: &str,
    scopes: &[String],
    minutes: u64,
    tag: Option<&str>,
    all_entries: bool,
    json: bool,
) -> Result<(), ClientError> {
    // Requiring --all-entries when no tag is given makes "every password I own" a deliberate
    // choice rather than what happens when a flag is forgotten.
    if tag.is_none() && !all_entries {
        return Err(ClientError::Agent {
            code: ErrorCode::BadRequest,
            message: "specify --tag to limit the grant, or --all-entries to cover every entry"
                .to_owned(),
        });
    }

    let reveal_requested = scopes
        .iter()
        .any(|s| matches!(s.to_ascii_lowercase().as_str(), "reveal" | "secret_reveal"));

    let response = client.request(&Request::GrantAccess {
        client_id: client_id.to_owned(),
        scopes: scopes.to_vec(),
        ttl_secs: Some(minutes.saturating_mul(60)),
        tag_filter: tag.map(str::to_owned),
    })?;

    let Response::Grants { grants } = response else {
        return Err(ClientError::Unexpected("expected a grants response".into()));
    };

    if json {
        print_json(&serde_json::json!({"granted": grants}));
        return Ok(());
    }

    println!(
        "Granted {client_id}: {} for {minutes} minutes{}.",
        scopes.join(", "),
        tag.map_or_else(String::new, |t| format!(" (entries tagged {t})"))
    );
    if reveal_requested {
        // Say what "reveal" actually means, at the moment the user is choosing it, rather than
        // leaving them to find out later.
        println!(
            "\nNote: `reveal` lets the agent ask for plaintext passwords. Each request still \
             needs your approval in the Keel window, and reveal is disabled for AI agents \
             unless you have turned it on in settings. For logging in, `use` is safer and \
             sufficient."
        );
    }
    Ok(())
}

/// List grants.
/// Print the vault health report.
///
/// Ordered by what the user should fix first: reuse, then weakness, then age. That is
/// deliberate — reuse is the finding that turns someone else's breach into your problem,
/// and it is the one a strength meter cannot tell you about.
fn audit(client: &mut Client, json: bool) -> Result<(), ClientError> {
    let response = client.request(&Request::VaultHealth)?;
    let Response::Health {
        examined,
        without_password,
        unreadable,
        reused,
        weak,
        stale,
        flagged,
    } = response
    else {
        return Err(ClientError::Unexpected("expected a health response".into()));
    };

    if json {
        print_json(&serde_json::json!({
            "examined": examined,
            "without_password": without_password,
            "unreadable": unreadable,
            "flagged": flagged,
            "reused": reused,
            "weak": weak,
            "stale": stale,
        }));
        return Ok(());
    }

    println!("Examined {examined} entr{}.", plural(examined));
    if without_password > 0 {
        println!("{without_password} store no password (a note, or a federated sign-in).");
    }
    if unreadable > 0 {
        // Loud, because a clean-looking report over a partly unreadable vault would be
        // actively misleading.
        println!(
            "\n  WARNING: {unreadable} record{} could not be decrypted and {} left out of \
             this report.\n  The vault may be damaged; a backup may be available alongside it.",
            if unreadable == 1 { "" } else { "s" },
            if unreadable == 1 { "was" } else { "were" },
        );
    }

    if !reused.is_empty() {
        println!(
            "\nReused passwords ({} group{}):",
            reused.len(),
            plural_s(reused.len())
        );
        println!("  A password shared between accounts turns any one site's breach into a");
        println!("  compromise of all of them. Fix these first.");
        for group in &reused {
            println!();
            for entry in group {
                println!("    {}  ({})", entry.title, entry.username);
            }
        }
    }

    if !weak.is_empty() {
        println!("\nWeak passwords ({}):", weak.len());
        for entry in &weak {
            println!(
                "    {:<28}  ~{} bits  [{}]",
                truncate(&entry.title, 28),
                entry.bits,
                entry.strength
            );
        }
        println!("\n  \"~bits\" is a lower bound from the password's structure, not a guarantee.");
    }

    if !stale.is_empty() {
        println!("\nUnchanged for over a year ({}):", stale.len());
        for entry in &stale {
            println!(
                "    {:<28}  {} days",
                truncate(&entry.title, 28),
                entry.age_days
            );
        }
        println!("\n  Age alone is not a problem. It matters most for passwords that are also");
        println!("  weak or reused, and for accounts that predate your use of a manager.");
    }

    if flagged == 0 {
        println!("\nNothing needs attention.");
    } else {
        println!(
            "\n{flagged} of {examined} entr{} need attention.",
            plural(flagged)
        );
        println!("Rotate one with:  keel rotate <name>");
    }

    Ok(())
}

/// "y" or "ies", for "entry"/"entries".
const fn plural(n: usize) -> &'static str {
    if n == 1 {
        "y"
    } else {
        "ies"
    }
}

/// "" or "s".
const fn plural_s(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// Shorten a title to fit a column, with an ellipsis when cut.
fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_owned();
    }
    let keep = width.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
}

fn grants(client: &mut Client, json: bool) -> Result<(), ClientError> {
    let Response::Grants { grants } = client.request(&Request::ListGrants)? else {
        return Err(ClientError::Unexpected("expected a grants response".into()));
    };
    if json {
        print_json(&serde_json::json!({"grants": grants}));
        return Ok(());
    }
    if grants.is_empty() {
        println!("No access has been granted to any client.");
        return Ok(());
    }
    for grant in &grants {
        println!(
            "{}  {}{}",
            grant.client_id,
            grant.scopes.join(", "),
            grant
                .tag_filter
                .as_ref()
                .map_or_else(String::new, |t| format!("  (tagged {t})"))
        );
    }
    Ok(())
}

/// Check a downloaded release.
fn verify_release(directory: &std::path::Path, json: bool) -> Result<(), ClientError> {
    match verify::verify_release(directory) {
        Ok(report) => {
            if json {
                print_json(&serde_json::json!({
                    "trusted": report.is_trusted(),
                    "ed25519": report.ed25519,
                    "ml_dsa": report.ml_dsa,
                    "files": report.files,
                }));
            } else {
                println!("Both signatures verified (Ed25519 and ML-DSA-65).");
                for file in &report.files {
                    println!("  ok  {file}");
                }
                println!("{} files verified.", report.files.len());
            }
            Ok(())
        }
        Err(error) => Err(ClientError::Agent {
            code: ErrorCode::BadRequest,
            message: error.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn init(client: &mut Client, tier: &str, json: bool) -> Result<(), ClientError> {
    let passphrase = prompt_new_passphrase()?;
    client.request(&Request::CreateVault {
        passphrase,
        tier: Some(tier.to_owned()),
    })?;
    emit(
        json,
        "Vault created and unlocked.",
        &serde_json::json!({"created": true}),
    );
    Ok(())
}

fn unlock(client: &mut Client, accept_rollback: bool, json: bool) -> Result<(), ClientError> {
    let passphrase = prompt_passphrase("Master passphrase: ")?;
    client.request(&Request::Unlock {
        passphrase,
        keyfile: None,
        accept_rollback,
    })?;
    emit(json, "Unlocked.", &serde_json::json!({"unlocked": true}));
    Ok(())
}

fn status(client: &mut Client, json: bool) -> Result<(), ClientError> {
    let Response::Status(info) = client.request(&Request::Status)? else {
        return Err(ClientError::Unexpected("expected a status response".into()));
    };
    if json {
        print_json(&serde_json::to_value(&*info).unwrap_or_default());
        return Ok(());
    }
    println!("State:   {:?}", info.state);
    println!("Vault:   {}", info.vault_path);
    if let Some(count) = &info.entry_count {
        println!("Entries: {count}");
    }
    if let Some(seconds) = info.locks_in {
        println!("Locks:   in {seconds}s");
    }
    println!("Agent:   {}", info.agent_version);
    println!(
        "Hardened: {}",
        if info.hardened { "yes" } else { "partially" }
    );
    for warning in &info.warnings {
        println!("Warning: {warning}");
    }
    Ok(())
}

fn list(client: &mut Client, limit: u32, json: bool) -> Result<(), ClientError> {
    let response = client.request(&Request::List {
        limit: Some(limit),
        offset: None,
    })?;
    print_entries(&response, json)
}

fn search(client: &mut Client, query: &str, json: bool) -> Result<(), ClientError> {
    let response = client.request(&Request::Search {
        query: query.to_owned(),
        limit: None,
    })?;
    print_entries(&response, json)
}

#[allow(clippy::too_many_arguments)]
fn add(
    client: &mut Client,
    title: &str,
    username: Option<&str>,
    urls: &[String],
    tags: &[String],
    password_stdin: bool,
    length: u32,
    words: Option<u32>,
    json: bool,
) -> Result<(), ClientError> {
    let secret = if password_stdin {
        SecretSource::Provided {
            value: read_stdin_secret()?,
        }
    } else {
        SecretSource::Generate {
            length: Some(length),
            words,
        }
    };

    let response = client.request(&Request::CreateEntry {
        input: EntryInput {
            title: title.to_owned(),
            username: username.unwrap_or_default().to_owned(),
            origins: urls.to_vec(),
            tags: tags.to_vec(),
            notes: String::new(),
        },
        secret,
    })?;
    client.request(&Request::Save)?;

    let Response::Created {
        reference,
        entropy_bits,
    } = response
    else {
        return Err(ClientError::Unexpected(
            "expected a created response".into(),
        ));
    };
    if json {
        print_json(&serde_json::json!({
            "reference": reference.0,
            "entropy_bits": entropy_bits,
        }));
    } else {
        // Report the strength but never the value: a generated password the caller never
        // saw is the point of the Generate path.
        match entropy_bits {
            Some(bits) => println!("Added {title} ({bits:.0} bits of entropy)."),
            None => println!("Added {title}."),
        }
    }
    Ok(())
}

fn get(
    client: &mut Client,
    name: &str,
    field: Field,
    show: bool,
    json: bool,
) -> Result<(), ClientError> {
    let reference = resolve(client, name)?;

    // Printing is opt-in when a human is watching. When output is piped the caller has
    // asked for the value on purpose, but they still have to say --show, so a stray `keel
    // get x > file` cannot silently write a password.
    if !show {
        let response = client.request(&Request::UseSecret {
            reference,
            field,
            action: SecretAction::Clipboard,
        })?;
        let Response::Applied { description } = response else {
            return Err(ClientError::Unexpected(
                "expected an applied response".into(),
            ));
        };
        emit(
            json,
            &description,
            &serde_json::json!({"applied": description}),
        );
        return Ok(());
    }

    if std::io::stdout().is_terminal() {
        eprintln!("keel: printing a secret to a terminal; it will remain in scrollback.");
    }
    let response = client.request(&Request::Reveal {
        reference,
        field,
        reason: Some("requested at the command line".to_owned()),
    })?;
    let Response::Secret { value, .. } = response else {
        return Err(ClientError::Unexpected("expected a secret response".into()));
    };
    if json {
        print_json(&serde_json::json!({"value": value}));
    } else {
        // No trailing newline handling beyond the usual: scripts expect one line.
        println!("{value}");
    }
    Ok(())
}

fn rotate(
    client: &mut Client,
    name: &str,
    length: u32,
    words: Option<u32>,
    json: bool,
) -> Result<(), ClientError> {
    let reference = resolve(client, name)?;
    let response = client.request(&Request::RotateSecret {
        reference,
        secret: SecretSource::Generate {
            length: Some(length),
            words,
        },
    })?;
    client.request(&Request::Save)?;
    let Response::Created { entropy_bits, .. } = response else {
        return Err(ClientError::Unexpected(
            "expected a created response".into(),
        ));
    };
    if json {
        print_json(&serde_json::json!({"rotated": true, "entropy_bits": entropy_bits}));
    } else {
        println!("Rotated. The previous password is kept in history.");
    }
    Ok(())
}

fn remove(client: &mut Client, name: &str, yes: bool, json: bool) -> Result<(), ClientError> {
    if !yes && std::io::stdin().is_terminal() {
        eprint!("Move {name} to the trash? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err()
            || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
        {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }
    let reference = resolve(client, name)?;
    client.request(&Request::TrashEntry { reference })?;
    client.request(&Request::Save)?;
    emit(
        json,
        "Moved to the trash. It can be restored until purged.",
        &serde_json::json!({"trashed": true}),
    );
    Ok(())
}

fn generate(
    client: &mut Client,
    length: u32,
    words: Option<u32>,
    json: bool,
) -> Result<(), ClientError> {
    let response = client.request(&Request::GeneratePassword {
        length: Some(length),
        words,
    })?;
    let Response::Generated {
        value,
        entropy_bits,
    } = response
    else {
        return Err(ClientError::Unexpected(
            "expected a generated response".into(),
        ));
    };
    if json {
        print_json(&serde_json::json!({"value": value, "entropy_bits": entropy_bits}));
    } else {
        println!("{value}");
        eprintln!("({entropy_bits:.0} bits of entropy)");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find an entry by name, or accept a reference directly.
fn resolve(client: &mut Client, name: &str) -> Result<EntryRef, ClientError> {
    let response = client.request(&Request::Search {
        query: name.to_owned(),
        limit: Some(10),
    })?;
    let Response::Entries { entries, .. } = response else {
        return Err(ClientError::Unexpected(
            "expected an entries response".into(),
        ));
    };

    match entries.len() {
        0 => Err(ClientError::Agent {
            code: ErrorCode::NotFound,
            message: format!("no entry matching {name:?}"),
        }),
        1 => Ok(entries
            .into_iter()
            .next()
            .map(|e| e.reference)
            .unwrap_or(EntryRef(String::new()))),
        _ => {
            // Refuse rather than guessing. Acting on the wrong entry could rotate a
            // password the user did not mean to touch.
            let exact: Vec<_> = entries
                .iter()
                .filter(|e| e.title.eq_ignore_ascii_case(name))
                .collect();
            if let [only] = exact.as_slice() {
                return Ok(only.reference.clone());
            }
            let titles: Vec<&str> = entries.iter().map(|e| e.title.as_str()).collect();
            Err(ClientError::Agent {
                code: ErrorCode::BadRequest,
                message: format!(
                    "{name:?} matches {} entries ({}); be more specific",
                    entries.len(),
                    titles.join(", ")
                ),
            })
        }
    }
}

fn print_entries(response: &Response, json: bool) -> Result<(), ClientError> {
    let Response::Entries { entries, truncated } = response else {
        return Err(ClientError::Unexpected(
            "expected an entries response".into(),
        ));
    };
    if json {
        print_json(&serde_json::json!({
            "entries": entries,
            "truncated": truncated,
        }));
        return Ok(());
    }
    if entries.is_empty() {
        println!("No entries.");
        return Ok(());
    }
    let width = entries.iter().map(|e| e.title.len()).max().unwrap_or(0);
    for entry in entries {
        let totp = if entry.has_totp { " [totp]" } else { "" };
        println!(
            "{:width$}  {}{}",
            entry.title,
            entry.username,
            totp,
            width = width
        );
    }
    if *truncated {
        println!("(more entries; raise --limit to see them)");
    }
    Ok(())
}

/// Environment variable naming a file that holds the master passphrase.
///
/// The supported way to run Keel non-interactively. A file is used rather than an
/// environment variable holding the passphrase itself, because environment variables are
/// readable through `/proc/<pid>/environ` by anything running as the same user, are
/// inherited by every child process, and end up verbatim in CI logs. A file at least has
/// permissions.
const PASSPHRASE_FILE_ENV: &str = "KEEL_PASSPHRASE_FILE";

/// Where a passphrase should come from.
enum PassphraseSource {
    /// A file named by [`PASSPHRASE_FILE_ENV`].
    File(std::path::PathBuf),
    /// Standard input, because it is not a terminal.
    Stdin,
    /// An interactive prompt.
    Terminal,
}

/// Decide where to read the passphrase from.
///
/// Precedence is explicit-file, then piped stdin, then an interactive prompt. Falling back
/// to stdin when it is not a terminal is what makes `keel` usable in a script without
/// tempting anyone to add a `--passphrase` flag.
fn passphrase_source() -> PassphraseSource {
    if let Ok(path) = std::env::var(PASSPHRASE_FILE_ENV) {
        if !path.is_empty() {
            return PassphraseSource::File(std::path::PathBuf::from(path));
        }
    }
    if std::io::stdin().is_terminal() {
        PassphraseSource::Terminal
    } else {
        PassphraseSource::Stdin
    }
}

/// Read a passphrase from a file, refusing one others can read.
fn read_passphrase_file(path: &std::path::Path) -> Result<String, ClientError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).map_err(|e| ClientError::Io {
            context: "reading the passphrase file",
            source: e,
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            // Refuse rather than warn. A passphrase file the whole machine can read defeats
            // the entire vault, and a warning in a script's output is a warning nobody sees.
            return Err(ClientError::Agent {
                code: ErrorCode::BadRequest,
                message: format!(
                    "{} is readable by other users (mode {mode:o}); run `chmod 600` on it \
                     before using it",
                    path.display()
                ),
            });
        }
    }
    let contents = std::fs::read_to_string(path).map_err(|e| ClientError::Io {
        context: "reading the passphrase file",
        source: e,
    })?;
    let trimmed = contents.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return Err(ClientError::Agent {
            code: ErrorCode::BadRequest,
            message: format!("{} is empty", path.display()),
        });
    }
    Ok(trimmed.to_owned())
}

/// Read one line from standard input.
fn read_passphrase_line() -> Result<String, ClientError> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| ClientError::Io {
            context: "reading the passphrase from standard input",
            source: e,
        })?;
    let trimmed = line.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return Err(ClientError::Agent {
            code: ErrorCode::BadRequest,
            message: "no passphrase was provided on standard input".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

/// Read an existing passphrase from wherever is appropriate.
fn prompt_passphrase(prompt: &str) -> Result<String, ClientError> {
    match passphrase_source() {
        PassphraseSource::File(path) => read_passphrase_file(&path),
        PassphraseSource::Stdin => read_passphrase_line(),
        PassphraseSource::Terminal => {
            rpassword::prompt_password(prompt).map_err(|e| ClientError::Io {
                context: "reading the passphrase",
                source: e,
            })
        }
    }
}

/// Read a new passphrase, confirming it when a human is present.
///
/// Confirmation matters more here than anywhere else in the program: a mistyped passphrase
/// on an existing vault is an error message, but a mistyped passphrase on a *new* vault
/// locks the user out of everything they subsequently store, permanently and silently.
///
/// It is skipped in non-interactive mode, where a script has supplied a single value and
/// asking twice would just mean reading the same file or pipe again.
fn prompt_new_passphrase() -> Result<String, ClientError> {
    match passphrase_source() {
        PassphraseSource::File(path) => read_passphrase_file(&path),
        PassphraseSource::Stdin => read_passphrase_line(),
        PassphraseSource::Terminal => {
            let first = rpassword::prompt_password("New master passphrase: ").map_err(|e| {
                ClientError::Io {
                    context: "reading the passphrase",
                    source: e,
                }
            })?;
            let second =
                rpassword::prompt_password("Confirm master passphrase: ").map_err(|e| {
                    ClientError::Io {
                        context: "reading the passphrase",
                        source: e,
                    }
                })?;
            if first != second {
                return Err(ClientError::Agent {
                    code: ErrorCode::BadRequest,
                    message: "the passphrases did not match; nothing was created".to_owned(),
                });
            }
            Ok(first)
        }
    }
}

/// Read a secret from standard input.
///
/// The only way to supply an existing password, because a `--password` flag would put it in
/// `ps` output and in shell history.
fn read_stdin_secret() -> Result<String, ClientError> {
    let mut value = String::new();
    std::io::stdin()
        .read_to_string(&mut value)
        .map_err(|e| ClientError::Io {
            context: "reading the password from standard input",
            source: e,
        })?;
    // Trim only the trailing newline a shell or `echo` adds; leading and interior
    // whitespace could legitimately be part of a password.
    let trimmed = value.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return Err(ClientError::Agent {
            code: ErrorCode::BadRequest,
            message: "no password was provided on standard input".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

/// Print either a human message or a JSON object.
fn emit(json: bool, human: &str, value: &serde_json::Value) {
    if json {
        print_json(value);
    } else {
        println!("{human}");
    }
}

fn print_json(value: &serde_json::Value) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(error) => eprintln!("keel: could not render JSON: {error}"),
    }
}
