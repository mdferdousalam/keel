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

    /// Show recent vault activity from the tamper-evident audit log.
    ///
    /// Every request any client makes is recorded in a hash-chained log encrypted under a
    /// subkey of the vault key. Editing or removing a record breaks the chain, and this
    /// command says so.
    Log {
        /// How many records to show, most recent last.
        #[arg(long, default_value = "50")]
        limit: u32,
    },

    /// Write every password out as plaintext.
    ///
    /// The most dangerous command here: it produces, in one file, exactly what an attacker
    /// wants. It exists because a password manager you cannot leave is a trap. Requires the
    /// master passphrase again even though the vault is unlocked.
    Export {
        /// Output format.
        #[arg(long, default_value = "json", value_parser = ["json", "csv"])]
        format: String,

        /// Write to this file (created 0600) instead of standard output.
        #[arg(long)]
        output: Option<std::path::PathBuf>,

        /// Skip the "are you sure" prompt. For scripts that already know.
        #[arg(long)]
        yes: bool,
    },

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
        Command::Log { limit } => log(&mut client, *limit, cli.json),
        Command::Export {
            format,
            output,
            yes,
        } => export(&mut client, format, output.as_deref(), *yes, cli.json),
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
/// Write every secret out in the clear.
///
/// Three things are deliberate here.
///
/// The warning comes *before* the passphrase prompt, so a user who did not realise what
/// this command does can stop without having typed their master passphrase into something
/// they then abandon.
///
/// A file is created 0600 and, on Unix, opened with `O_EXCL` so an existing file is never
/// overwritten and a symlink planted at the path is never followed. Writing the entire
/// vault in plaintext through somebody else's symlink would be a memorable bug.
///
/// Standard output is allowed but nudged away from, because `keel export > file` creates
/// the file with the shell's umask — commonly world-readable — before Keel sees it.
fn export(
    client: &mut Client,
    format: &str,
    output: Option<&std::path::Path>,
    yes: bool,
    json: bool,
) -> Result<(), ClientError> {
    if !yes {
        eprintln!(
            "This writes every password in your vault to {} as readable text.\n\
             \n\
             Anything that can read that output has all of your passwords: another user on\n\
             this machine, a backup service, a cloud-synced folder, your shell history if\n\
             you redirect it somewhere odd, and your terminal's scrollback if you do not\n\
             redirect it at all.\n\
             \n\
             Delete it as soon as you have imported it elsewhere, and know that on an SSD\n\
             deleting a file does not reliably destroy its contents — full-disk encryption\n\
             is what actually protects it.\n",
            output.map_or_else(
                || "this terminal".to_owned(),
                |p| format!("{}", p.display())
            )
        );
        if std::io::stdin().is_terminal() {
            eprint!("Type 'export' to continue, or anything else to stop: ");
            use std::io::Write as _;
            let _ = std::io::stderr().flush();
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .map_err(|e| ClientError::Io {
                    context: "reading the confirmation",
                    source: e,
                })?;
            if answer.trim() != "export" {
                eprintln!("Nothing was exported.");
                return Ok(());
            }
        }
    }

    // Asked for after the warning, on purpose.
    let passphrase = prompt_passphrase("Master passphrase, to confirm it is you: ")?;
    let response = client.request(&Request::Export { passphrase })?;
    let Response::Exported { entries } = response else {
        return Err(ClientError::Unexpected(
            "expected an export response".into(),
        ));
    };

    let body = match format {
        "csv" => render_export_csv(&entries),
        // clap restricts the value, so anything else is unreachable; JSON is the safer
        // default because it round-trips notes containing newlines and commas.
        _ => serde_json::to_string_pretty(&serde_json::json!({"entries": entries}))
            .unwrap_or_default(),
    };

    match output {
        Some(path) => {
            write_private_file(path, body.as_bytes())?;
            let message = format!(
                "Wrote {} entr{} to {} with owner-only permissions.",
                entries.len(),
                plural(entries.len()),
                path.display()
            );
            emit(
                json,
                &message,
                &serde_json::json!({"exported": entries.len(), "path": path}),
            );
        }
        None => {
            // Straight to stdout, no `emit`: wrapping plaintext secrets in a status
            // message would corrupt the data the user asked for.
            print!("{body}");
            eprintln!(
                "\n{} entr{} exported. Nothing was written to disk by Keel.",
                entries.len(),
                plural(entries.len())
            );
        }
    }
    Ok(())
}

/// Render entries as CSV in the dialect the importers accept.
///
/// Hand-rolled rather than pulling in a writer, because the escaping rule is one function
/// and the crate already has a `csv` dependency only in the import path, which does not
/// link here.
fn render_export_csv(entries: &[keel_proto::ExportedEntry]) -> String {
    fn field(value: &str) -> String {
        // Quote whenever the value could otherwise change the shape of the row, and double
        // any embedded quote. A note containing a newline is the common case that breaks
        // naive writers.
        if value.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", value.replace('"', "\"\""))
        } else {
            value.to_owned()
        }
    }
    let mut out = String::from("title,username,password,totp_secret,notes,origins,tags\n");
    for e in entries {
        out.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            field(&e.title),
            field(&e.username),
            field(&e.password),
            field(e.totp_secret.as_deref().unwrap_or_default()),
            field(&e.notes),
            field(&e.origins.join(" ")),
            field(&e.tags.join(" ")),
        ));
    }
    out
}

/// Create a file only the owner can read, refusing to overwrite or follow a symlink.
fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), ClientError> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    // `create_new` is what makes this safe: it fails if anything already exists at the
    // path, including a symlink, so plaintext can never be written through one.
    let mut file = options.open(path).map_err(|e| ClientError::Io {
        context: if e.kind() == std::io::ErrorKind::AlreadyExists {
            "creating the export file: something already exists at that path, and Keel \
             will not overwrite it"
        } else {
            "creating the export file"
        },
        source: e,
    })?;
    file.write_all(bytes).map_err(|e| ClientError::Io {
        context: "writing the export file",
        source: e,
    })?;
    file.sync_all().map_err(|e| ClientError::Io {
        context: "flushing the export file",
        source: e,
    })
}

/// Print recent activity from the audit log.
fn log(client: &mut Client, limit: u32, json: bool) -> Result<(), ClientError> {
    let Response::Audit {
        records,
        chain,
        total,
    } = client.request(&Request::AuditTail { limit: Some(limit) })?
    else {
        return Err(ClientError::Unexpected("expected an audit response".into()));
    };

    if json {
        print_json(&serde_json::json!({
            "records": records,
            "chain": chain,
            "total": total,
        }));
        return Ok(());
    }

    // The chain verdict goes first when something is wrong. A user scanning the output
    // should not have to reach the bottom to find out the log cannot be trusted.
    match chain {
        keel_proto::ChainState::BrokenAt { seq } => {
            println!(
                "  WARNING: the audit chain fails to verify at record {seq}.\n  \
                 A record has been edited or removed. The {} record{} shown below \
                 precede the break and still verify.\n",
                records.len(),
                if records.len() == 1 { "" } else { "s" }
            );
        }
        keel_proto::ChainState::TruncatedAfter { seq } => {
            println!(
                "  Note: the log ends mid-record after {seq}. Appends are not atomic, so \
                 this is\n  usually an interrupted write rather than interference.\n"
            );
        }
        keel_proto::ChainState::TailAltered {
            expected_seq,
            found_seq,
        } => {
            // Two different attacks reach this state, and telling the user which one it
            // was matters: "records are missing" and "records were rewritten" call for
            // different responses.
            let what = if found_seq < expected_seq {
                format!(
                    "{} record{} been removed from the end of the log",
                    expected_seq - found_seq,
                    if expected_seq - found_seq == 1 {
                        " has"
                    } else {
                        "s have"
                    }
                )
            } else {
                format!(
                    "the last record{} of the log {} been rewritten",
                    if expected_seq == 1 { "" } else { "s" },
                    if expected_seq == 1 { "has" } else { "have" }
                )
            };
            println!(
                "  WARNING: {what}.\n  The vault committed to {expected_seq} record{} at its \
                 last save; {found_seq} now verify, and the chain\n  does not end where the \
                 vault says it should.\n\n  A hash chain cannot catch this alone — any prefix \
                 of a chain, and any freshly\n  rebuilt chain, verifies perfectly well. The \
                 vault's own committed count is what\n  caught it. An interrupted write would \
                 leave a partial record, not a clean one, so\n  this is interference rather \
                 than an accident.\n",
                if expected_seq == 1 { "" } else { "s" },
            );
        }
        keel_proto::ChainState::Intact => {}
    }

    if records.is_empty() {
        println!("Nothing has been recorded yet.");
        return Ok(());
    }

    for record in &records {
        let entry = record.entry.as_deref().map_or_else(String::new, |id| {
            // Entry ids are recorded, not titles: the log must stay readable even after an
            // entry is deleted, and a title in a log is a secret-adjacent thing to store.
            format!("  entry {}", &id[..id.len().min(8)])
        });
        println!(
            "{:>6}  {}  {:<18}  {:<16}  {}{}",
            record.seq,
            format_timestamp(record.timestamp),
            truncate(&record.client_id, 18),
            record.operation,
            record.outcome,
            entry
        );
    }

    if total > records.len() as u64 {
        println!(
            "\nShowing the last {} of {total} records. Use --limit to see more.",
            records.len()
        );
    }
    if matches!(chain, keel_proto::ChainState::Intact) {
        println!("\nThe hash chain verifies over all {total} records.");
    }
    Ok(())
}

/// Render a Unix timestamp as UTC, without pulling in a date library.
///
/// `time` and `chrono` are both larger than this needs to be, and this runs in a client
/// that deliberately holds no vault code — keeping its dependency list short is the point.
/// Implements the civil-from-days algorithm, which is exact for all values we can hold.
//
// Truncating division is the algorithm, not an accident: every `/` here is a deliberate
// floor over day, era, and year-of-era counts, and rounding any of them would move dates.
// The lint is right to ask in general and wrong here, so it is silenced narrowly with the
// reason rather than crate-wide.
#[allow(
    clippy::integer_division,
    reason = "calendar arithmetic is defined in terms of floor division"
)]
fn format_timestamp(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs_of_day = unix % 86_400;
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );

    // Howard Hinnant's civil_from_days, shifted to an era starting 0000-03-01.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}Z")
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_render_as_utc() {
        // Hand-checked values. Calendar arithmetic is the kind of code that looks right
        // and is wrong at boundaries, so the cases are chosen to sit on them: epoch,
        // a leap day, the day after a leap day, century non-leap and quadricentennial
        // leap years, and a year boundary.
        let cases = [
            (0u64, "1970-01-01 00:00:00Z"),
            (1, "1970-01-01 00:00:01Z"),
            (86_399, "1970-01-01 23:59:59Z"),
            (86_400, "1970-01-02 00:00:00Z"),
            // 2000-02-29: a leap year because it is divisible by 400.
            (951_782_400, "2000-02-29 00:00:00Z"),
            (951_868_800, "2000-03-01 00:00:00Z"),
            // 2100 is NOT a leap year (divisible by 100, not by 400), so 28 February is
            // followed directly by 1 March. Getting this wrong is the classic calendar
            // bug, and the naive "divisible by 4" rule fails exactly here.
            (4_107_456_000, "2100-02-28 00:00:00Z"),
            (4_107_542_400, "2100-03-01 00:00:00Z"),
            // Year boundary.
            (1_735_689_599, "2024-12-31 23:59:59Z"),
            (1_735_689_600, "2025-01-01 00:00:00Z"),
            // A leap day in an ordinary leap year.
            (1_709_164_800, "2024-02-29 00:00:00Z"),
        ];
        for (unix, expected) in cases {
            assert_eq!(format_timestamp(unix), expected, "for {unix}");
        }
    }

    #[test]
    fn timestamp_rendering_does_not_panic_on_extremes() {
        // The value comes off the wire, so it can be anything a u64 holds.
        for unix in [u64::MAX, u64::MAX - 1, 1 << 62, 1 << 40] {
            let _ = format_timestamp(unix);
        }
    }

    #[test]
    fn titles_are_truncated_on_character_boundaries() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactlyten", 10), "exactlyten");
        assert_eq!(truncate("this is far too long", 10), "this is f…");
        // Multi-byte characters must not be split, which byte slicing would do.
        assert_eq!(truncate("日本語のパスワード帳です", 5), "日本語の…");
        assert_eq!(truncate("🔐🔐🔐🔐🔐🔐", 3), "🔐🔐…");
    }

    #[test]
    fn plurals_read_correctly() {
        assert_eq!(plural(1), "y");
        assert_eq!(plural(0), "ies");
        assert_eq!(plural(2), "ies");
        assert_eq!(plural_s(1), "");
        assert_eq!(plural_s(2), "s");
    }
}
