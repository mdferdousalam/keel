//! Talking to the Keel agent.
//!
//! This crate deliberately depends on **nothing but `keel-proto`**. It has no access to
//! `keel-crypto`, `keel-format`, or `keel-core`, and `cargo xtask check-layering` fails the
//! build if that ever changes. That absence is the point: it is what makes "the CLI, the
//! MCP server, the browser bridge, and the desktop shell hold no key material" a checkable
//! fact rather than an intention.
//!
//! # Connect or spawn
//!
//! [`Client::connect`] tries the socket and starts an agent if nothing is listening, so a
//! user typing `keel get github` never has to know a daemon exists. The *first* command of
//! a session pays for the agent's startup, which is why the spawn path waits for the socket
//! rather than failing fast.
//!
//! [`Client::connect_existing`] deliberately does not spawn. The browser bridge uses it:
//! silently starting the agent and prompting for a passphrase in response to something a
//! web page triggered is a phishing vector, so the extension asks the user to open Keel
//! instead.

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

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use keel_proto::{
    decode_frame, encode_frame, ClientKind, ErrorCode, FrameError, Request, Response,
    MAX_FRAME_LEN, PROTOCOL_VERSION,
};

/// Environment variable that overrides the socket path.
pub const SOCKET_ENV: &str = "KEEL_AGENT_SOCKET";

/// Environment variable naming the agent binary, for tests and unusual installs.
pub const AGENT_BINARY_ENV: &str = "KEEL_AGENT_BINARY";

/// How long to wait for a spawned agent's socket to appear.
const SPAWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Client errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No agent is running and one could not be started.
    #[error("could not reach the Keel agent: {0}")]
    Unreachable(String),

    /// An I/O failure while talking to the agent.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: &'static str,
        /// Underlying error.
        #[source]
        source: io::Error,
    },

    /// A framing or encoding failure.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// The agent refused the request.
    #[error("{message}")]
    Agent {
        /// Machine-readable code.
        code: ErrorCode,
        /// Explanation from the agent.
        message: String,
    },

    /// The agent answered something unexpected.
    ///
    /// Almost always a version mismatch, so the message says so rather than leaving the
    /// user to guess.
    #[error("unexpected response from the agent (is it a different version?): {0}")]
    Unexpected(String),

    /// This platform is not supported yet.
    #[error("{0}")]
    Unsupported(&'static str),

    /// The caller asked for something the current state does not allow.
    ///
    /// Distinct from [`Self::Unexpected`], whose message blames a version mismatch. Reusing
    /// that for a plain refusal tells the user to go looking for a bug that is not there.
    #[error("{0}")]
    Refused(String),
}

impl Error {
    fn io(context: &'static str, source: io::Error) -> Self {
        Self::Io { context, source }
    }

    /// The error code, if the agent supplied one.
    #[must_use]
    pub const fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Agent { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// Suggested process exit code.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Agent { code, .. } => code.exit_code(),
            _ => 1,
        }
    }
}

/// Result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Where the agent socket lives.
///
/// Must agree with the agent's own resolution. The logic is duplicated deliberately rather
/// than shared: `keel-client` cannot depend on `keel-agent` without inverting the layering
/// and pulling the vault core into every client.
#[must_use]
pub fn socket_path() -> PathBuf {
    if let Ok(explicit) = std::env::var(SOCKET_ENV) {
        return PathBuf::from(explicit);
    }
    #[cfg(unix)]
    {
        if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
            if !runtime.is_empty() {
                return PathBuf::from(runtime).join("keel").join("agent.sock");
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("dev.keel")
                .join("agent.sock");
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("keel")
                .join("agent.sock");
        }
    }
    std::env::temp_dir().join("keel").join("agent.sock")
}

/// A connection to the agent.
pub struct Client {
    stream: PlatformStream,
    buffer: Vec<u8>,
}

#[cfg(unix)]
type PlatformStream = std::os::unix::net::UnixStream;

#[cfg(not(unix))]
type PlatformStream = std::net::TcpStream;

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Client")
    }
}

impl Client {
    /// Connect to a running agent, starting one if necessary.
    pub fn connect(kind: ClientKind, client_id: &str) -> Result<Self> {
        Self::connect_for_vault(kind, client_id, None)
    }

    /// Connect, naming the vault a freshly spawned agent should open.
    ///
    /// The path is passed as an argument to the agent rather than through the environment,
    /// because mutating a process's environment to influence a child is both `unsafe` in this
    /// edition and a side effect on everything else that reads it afterwards.
    ///
    /// It has no effect on an agent that is **already** running: that agent chose its vault
    /// when it started. Callers who care must compare the vault path in a status response and
    /// decide what to do about a mismatch, because the right answer depends on who else might
    /// be using the running agent.
    pub fn connect_for_vault(
        kind: ClientKind,
        client_id: &str,
        vault: Option<&Path>,
    ) -> Result<Self> {
        let path = socket_path();
        match Self::attach(&path, kind, client_id) {
            Ok(client) => Ok(client),
            Err(_) => {
                spawn_agent(vault)?;
                wait_for_socket(&path)?;
                Self::attach(&path, kind, client_id)
            }
        }
    }

    /// Connect to an agent that must already be running.
    ///
    /// See the module documentation for why the browser bridge uses this rather than
    /// [`Client::connect`].
    pub fn connect_existing(kind: ClientKind, client_id: &str) -> Result<Self> {
        Self::attach(&socket_path(), kind, client_id)
    }

    #[cfg(unix)]
    fn attach(path: &Path, kind: ClientKind, client_id: &str) -> Result<Self> {
        let stream = std::os::unix::net::UnixStream::connect(path).map_err(|e| {
            Error::Unreachable(format!("no agent is listening on {} ({e})", path.display()))
        })?;
        let mut client = Self {
            stream,
            buffer: Vec::new(),
        };
        client.handshake(kind, client_id)?;
        Ok(client)
    }

    #[cfg(not(unix))]
    fn attach(_path: &Path, _kind: ClientKind, _client_id: &str) -> Result<Self> {
        Err(Error::Unsupported(
            "the Keel client does not yet support this platform",
        ))
    }

    /// Negotiate the protocol version.
    ///
    /// First message on every connection: an old client and a new agent would otherwise
    /// misinterpret each other's messages rather than failing with something legible.
    ///
    /// Unreachable on platforms without a transport — the only caller is `attach`, which is
    /// `cfg(unix)` — so the dead-code warning is silenced there rather than everywhere. Keeping
    /// the crate compiling on Windows is deliberate: it means the portable code is already
    /// known-good when the named-pipe transport lands, instead of a pile of accumulated
    /// breakage to clear first.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn handshake(&mut self, kind: ClientKind, client_id: &str) -> Result<()> {
        let response = self.request(&Request::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_kind: kind,
            client_id: client_id.to_owned(),
            client_version: VERSION.to_owned(),
        })?;
        match response {
            Response::Hello { .. } => Ok(()),
            other => Err(Error::Unexpected(format!("{other:?}"))),
        }
    }

    /// Send a request and read the response, converting an agent error into `Err`.
    pub fn request(&mut self, request: &Request) -> Result<Response> {
        let frame = encode_frame(request)?;
        self.stream
            .write_all(&frame)
            .map_err(|e| Error::io("sending a request to the agent", e))?;
        self.stream
            .flush()
            .map_err(|e| Error::io("flushing a request to the agent", e))?;

        match self.receive()? {
            Response::Error { code, message } => Err(Error::Agent { code, message }),
            other => Ok(other),
        }
    }

    fn receive(&mut self) -> Result<Response> {
        loop {
            match decode_frame::<Response>(&self.buffer) {
                Ok((value, consumed)) => {
                    self.buffer.drain(..consumed);
                    return Ok(value);
                }
                Err(FrameError::Incomplete { .. }) => {}
                Err(other) => return Err(other.into()),
            }
            if self.buffer.len() > MAX_FRAME_LEN + 4 {
                return Err(Error::Frame(FrameError::TooLarge {
                    found: self.buffer.len() as u64,
                }));
            }
            let mut chunk = [0u8; 8192];
            let read = self
                .stream
                .read(&mut chunk)
                .map_err(|e| Error::io("reading a response from the agent", e))?;
            if read == 0 {
                return Err(Error::Unreachable(
                    "the agent closed the connection".to_owned(),
                ));
            }
            self.buffer
                .extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
    }
}

/// Start the agent as a detached background process.
fn spawn_agent(vault: Option<&Path>) -> Result<()> {
    let binary = agent_binary();
    let mut command = std::process::Command::new(&binary);
    if let Some(vault) = vault {
        // `keel-agent` takes the vault path as its first argument, falling back to
        // `KEEL_VAULT`. Passing it here leaves this process's environment untouched.
        command.arg(vault);
    }
    command
        // Detach the standard streams: the agent outlives the command that started it, and
        // inheriting a terminal would make it die with that terminal.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            Error::Unreachable(format!(
                "could not start the agent at {}: {e}",
                binary.display()
            ))
        })?;
    Ok(())
}

/// Locate the agent binary.
///
/// Looks beside our own executable first, so an installed Keel uses its own agent rather
/// than whichever happens to be on `PATH`. That matters when two versions are installed:
/// mixing them means a protocol mismatch, and the version the user invoked is the one they
/// meant.
fn agent_binary() -> PathBuf {
    if let Ok(explicit) = std::env::var(AGENT_BINARY_ENV) {
        return PathBuf::from(explicit);
    }
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let candidate = dir.join(if cfg!(windows) {
                "keel-agent.exe"
            } else {
                "keel-agent"
            });
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("keel-agent")
}

/// Whether something is actually listening at `path`.
///
/// A successful connect is closed immediately; the agent tolerates a peer that hangs up
/// before saying anything, since that is also what a port scanner or a crashed client does.
#[cfg(unix)]
fn can_connect(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(not(unix))]
fn can_connect(path: &Path) -> bool {
    // No named-pipe transport yet, so there is nothing to connect to. Falling back to
    // existence would reintroduce the stale-socket bug on the platform least able to
    // diagnose it.
    let _ = path;
    false
}

/// Wait for a spawned agent's socket to appear.
///
/// Polls rather than failing immediately: the first command of a session pays for the
/// agent's startup, and reporting "no agent" while one is still binding would be a
/// confusing race.
fn wait_for_socket(path: &Path) -> Result<()> {
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    while Instant::now() < deadline {
        // Waiting for the file to *exist* is not enough, and getting that wrong produced a
        // bug worth remembering: after an agent is killed its socket file remains, so
        // `exists()` returned true instantly, the connect that followed was refused, and
        // every command failed until the user deleted the file by hand. Connecting is the
        // only check that distinguishes a live listener from a leftover inode.
        if can_connect(path) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(Error::Unreachable(format!(
        "the agent did not start within {} seconds (expected a socket at {})",
        SPAWN_TIMEOUT.as_secs(),
        path.display()
    )))
}

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_socket_path_wins() {
        let previous = std::env::var(SOCKET_ENV).ok();
        std::env::set_var(SOCKET_ENV, "/tmp/keel-client-test.sock");
        assert_eq!(socket_path(), PathBuf::from("/tmp/keel-client-test.sock"));
        match previous {
            Some(v) => std::env::set_var(SOCKET_ENV, v),
            None => std::env::remove_var(SOCKET_ENV),
        }
    }

    #[test]
    fn agent_errors_carry_their_exit_code() {
        let error = Error::Agent {
            code: ErrorCode::Locked,
            message: "locked".to_owned(),
        };
        assert_eq!(error.code(), Some(ErrorCode::Locked));
        assert_eq!(error.exit_code(), 2);

        let other = Error::Unsupported("nope");
        assert_eq!(other.code(), None);
        assert_eq!(other.exit_code(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn connecting_with_nothing_listening_names_the_path() {
        // "Connection refused" with no path is one of the least useful errors a program can
        // produce.
        let result = Client::attach(
            Path::new("/tmp/keel-definitely-not-listening.sock"),
            ClientKind::Cli,
            "test",
        );
        match result {
            Err(Error::Unreachable(message)) => {
                assert!(
                    message.contains("keel-definitely-not-listening"),
                    "{message}"
                );
            }
            other => panic!("expected an unreachable error, got {other:?}"),
        }
    }
}
