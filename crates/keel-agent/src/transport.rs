//! Local IPC transport, and who is allowed to use it.
//!
//! # The socket
//!
//! A Unix domain socket in a `0700` directory under the user's runtime directory. Not a
//! TCP port on loopback, which every other local user and every browser page's
//! `fetch("http://127.0.0.1:...")` can reach.
//!
//! # Peer credentials, and what they actually prove
//!
//! Every connection's peer UID is checked against our own and mismatches are refused.
//! That is worth stating precisely, because it is easy to overclaim:
//!
//! * **It does prove** the peer is the same OS user. Cross-user access is impossible, and
//!   so is remote access — a Unix socket has no network presence at all.
//! * **It does not prove** which program is on the other end. Reading `/proc` or calling
//!   `LOCAL_PEERPID` gives a pid, and a pid can be looked up to an executable path, but
//!   that lookup is time-of-check/time-of-use racy and the path can be a copy of a
//!   trusted binary. So the executable path is collected as *evidence for the approval
//!   dialog*, never as an authorization decision.
//!
//! Per T3 and T13 in the threat model, same-user malware is not something this boundary
//! stops. What stops it mattering is that sensitive operations need a human, and that the
//! vault is locked most of the time.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use keel_proto::{decode_frame, encode_frame, FrameError, MAX_FRAME_LEN};

/// Environment variable that overrides the socket path.
///
/// Exists for tests, which must not fight over one well-known path, and for users running
/// two vaults side by side.
pub const SOCKET_ENV: &str = "KEEL_AGENT_SOCKET";

/// Transport errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// An I/O failure.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: &'static str,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// The peer is not the same user.
    #[error("connection refused: the peer is not the same user (uid {peer}, expected {ours})")]
    ForeignUser {
        /// Peer's uid.
        peer: u32,
        /// Our uid.
        ours: u32,
    },
    /// A frame was malformed or oversized.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The peer closed the connection.
    #[error("the peer closed the connection")]
    Closed,
    /// This platform is not supported yet.
    #[error("{0}")]
    Unsupported(&'static str),
}

impl TransportError {
    fn io(context: &'static str, source: io::Error) -> Self {
        Self::Io { context, source }
    }
}

/// Result alias.
pub type Result<T> = core::result::Result<T, TransportError>;

/// Where the agent listens.
///
/// Uses `$XDG_RUNTIME_DIR` when available: it is `0700`, user-owned, and cleared on
/// logout, which is exactly right for a socket that should not outlive the session. Falls
/// back to the platform data directory, and finally to the temp directory with the uid in
/// the name so two users never collide.
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
        if let Some(dirs) = directories_data_dir() {
            return dirs.join("agent.sock");
        }
        std::env::temp_dir()
            .join(format!("keel-{}", current_uid()))
            .join("agent.sock")
    }
    #[cfg(not(unix))]
    {
        directories_data_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("agent.sock")
    }
}

/// Platform data directory for the agent's runtime files.
fn directories_data_dir() -> Option<PathBuf> {
    // Resolved without the `directories` crate to keep this crate's dependency list
    // short; the agent is the process where that matters most.
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME").ok().map(|home| {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("dev.keel")
        })
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_DATA_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".local").join("share"))
            })
            .map(|base| base.join("keel"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|base| PathBuf::from(base).join("keel"))
    }
}

/// This process's effective user id.
///
/// Delegated to `keel-hardening`, which is the one crate permitted `unsafe` and therefore
/// the only place a raw `geteuid` belongs.
#[must_use]
pub fn current_uid() -> u32 {
    keel_hardening::platform::current_uid()
}

/// Identity of a connected peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Peer's user id.
    pub uid: u32,
    /// Peer's process id, if the platform reports it.
    pub pid: Option<u32>,
    /// Peer's executable path, if it could be resolved.
    ///
    /// **Evidence, not authorization.** Shown in approval dialogs so a process claiming to
    /// be `keel-mcp` from an unexpected location is visible to a human. The lookup is
    /// time-of-check/time-of-use racy, so no decision may depend on it.
    pub executable: Option<String>,
}

/// A framed connection to a peer.
#[derive(Debug)]
pub struct Connection {
    stream: PlatformStream,
    peer: PeerIdentity,
    buffer: Vec<u8>,
}

#[cfg(unix)]
type PlatformStream = std::os::unix::net::UnixStream;

#[cfg(not(unix))]
type PlatformStream = std::net::TcpStream;

impl Connection {
    /// The peer's identity.
    #[must_use]
    pub const fn peer(&self) -> &PeerIdentity {
        &self.peer
    }

    /// Send a message.
    pub fn send<T: serde::Serialize>(&mut self, value: &T) -> Result<()> {
        let frame = encode_frame(value)?;
        self.stream
            .write_all(&frame)
            .map_err(|e| TransportError::io("writing to the peer", e))?;
        self.stream
            .flush()
            .map_err(|e| TransportError::io("flushing to the peer", e))
    }

    /// Receive one message, blocking until a whole frame arrives.
    ///
    /// Frames are accumulated in an internal buffer, so a peer that writes a frame in
    /// several small chunks is handled correctly — and a peer that sends a huge length
    /// prefix is rejected by [`decode_frame`] before the buffer can grow to match.
    pub fn receive<T: for<'de> serde::Deserialize<'de>>(&mut self) -> Result<T> {
        loop {
            match decode_frame::<T>(&self.buffer) {
                Ok((value, consumed)) => {
                    self.buffer.drain(..consumed);
                    return Ok(value);
                }
                Err(FrameError::Incomplete { .. }) => {}
                Err(other) => return Err(other.into()),
            }

            // Cap the buffer independently of the frame check, so a peer that never
            // completes a frame cannot make us grow without bound.
            if self.buffer.len() > MAX_FRAME_LEN + 4 {
                return Err(TransportError::Frame(FrameError::TooLarge {
                    found: self.buffer.len() as u64,
                }));
            }

            let mut chunk = [0u8; 8192];
            let read = self
                .stream
                .read(&mut chunk)
                .map_err(|e| TransportError::io("reading from the peer", e))?;
            if read == 0 {
                return Err(TransportError::Closed);
            }
            self.buffer
                .extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
    }
}

/// A listening agent socket.
#[derive(Debug)]
pub struct Listener {
    #[cfg(unix)]
    inner: std::os::unix::net::UnixListener,
    path: PathBuf,
}

impl Listener {
    /// Bind the agent socket, creating its directory with restrictive permissions.
    ///
    /// A stale socket file from a crashed agent is removed first. That is safe because the
    /// vault lock, not the socket, is what prevents two agents from writing at once —
    /// removing a socket a live agent is using would only make that agent unreachable, and
    /// the lock would still refuse the second writer.
    #[cfg(unix)]
    pub fn bind(path: &Path) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| TransportError::io("creating the socket directory", e))?;
            // 0700: nobody else may even list the directory, let alone connect.
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| TransportError::io("restricting the socket directory", e))?;
        }
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }

        let inner = std::os::unix::net::UnixListener::bind(path)
            .map_err(|e| TransportError::io("binding the agent socket", e))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| TransportError::io("restricting the agent socket", e))?;

        Ok(Self {
            inner,
            path: path.to_path_buf(),
        })
    }

    /// Windows named pipes are not implemented yet.
    #[cfg(not(unix))]
    pub fn bind(_path: &Path) -> Result<Self> {
        Err(TransportError::Unsupported(
            "the Keel agent does not yet support this platform; a Windows named-pipe \
             transport with a current-user-only DACL is required and is not implemented",
        ))
    }

    /// The socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept the next connection, refusing peers belonging to another user.
    #[cfg(unix)]
    pub fn accept(&self) -> Result<Connection> {
        let (stream, _) = self
            .inner
            .accept()
            .map_err(|e| TransportError::io("accepting a connection", e))?;

        let peer = keel_hardening::platform::peer_credentials(&stream)
            .map(|(uid, pid)| PeerIdentity {
                uid,
                pid,
                executable: pid.and_then(executable_for_pid),
            })
            .unwrap_or(PeerIdentity {
                // If credentials cannot be read at all, treat the peer as foreign rather
                // than assuming it is us. Failing closed is the only safe default when
                // the check itself is unavailable.
                uid: u32::MAX,
                pid: None,
                executable: None,
            });

        let ours = current_uid();
        if peer.uid != ours {
            return Err(TransportError::ForeignUser {
                peer: peer.uid,
                ours,
            });
        }

        Ok(Connection {
            stream,
            peer,
            buffer: Vec::new(),
        })
    }

    /// Accept the next connection.
    #[cfg(not(unix))]
    pub fn accept(&self) -> Result<Connection> {
        Err(TransportError::Unsupported("unsupported platform"))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // Leave no stale socket behind for the next start to trip over.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Connect to a running agent.
#[cfg(unix)]
pub fn connect(path: &Path) -> Result<Connection> {
    let stream = std::os::unix::net::UnixStream::connect(path)
        .map_err(|e| TransportError::io("connecting to the agent", e))?;
    let peer = PeerIdentity {
        uid: current_uid(),
        pid: None,
        executable: None,
    };
    Ok(Connection {
        stream,
        peer,
        buffer: Vec::new(),
    })
}

/// Connect to a running agent.
#[cfg(not(unix))]
pub fn connect(_path: &Path) -> Result<Connection> {
    Err(TransportError::Unsupported("unsupported platform"))
}

/// Resolve a pid to an executable path, best effort.
fn executable_for_pid(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS needs `proc_pidpath`, which is a platform call; it belongs in
        // keel-hardening and is not implemented yet. The approval dialog copes with
        // `None` by saying the path is unknown, which is more honest than guessing.
        let _ = pid;
        None
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use keel_proto::{Request, Response};

    fn temp_socket() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("agent.sock");
        (dir, path)
    }

    #[test]
    fn a_request_and_response_round_trip() {
        let (_dir, path) = temp_socket();
        let listener = Listener::bind(&path).unwrap();
        let server_path = path.clone();

        let server = std::thread::spawn(move || {
            let mut conn = listener.accept().unwrap();
            let request: Request = conn.receive().unwrap();
            assert_eq!(request, Request::Status);
            conn.send(&Response::Ok).unwrap();
            drop(server_path);
        });

        let mut client = connect(&path).unwrap();
        client.send(&Request::Status).unwrap();
        let response: Response = client.receive().unwrap();
        assert_eq!(response, Response::Ok);
        server.join().unwrap();
    }

    #[test]
    fn the_socket_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = temp_socket();
        let _listener = Listener::bind(&path).unwrap();

        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "the socket directory must not be listable");

        let sock_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            sock_mode, 0o600,
            "the socket must not be connectable by others"
        );
    }

    #[test]
    fn a_stale_socket_file_does_not_prevent_binding() {
        // A crashed agent leaves its socket behind; the next start must not be blocked.
        let (_dir, path) = temp_socket();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"stale").unwrap();
        let listener = Listener::bind(&path).unwrap();
        assert_eq!(listener.path(), path.as_path());
    }

    #[test]
    fn dropping_the_listener_removes_the_socket() {
        let (_dir, path) = temp_socket();
        {
            let _listener = Listener::bind(&path).unwrap();
            assert!(path.exists());
        }
        assert!(!path.exists(), "a stale socket must not be left behind");
    }

    #[test]
    fn the_peer_is_reported_as_the_same_user() {
        let (_dir, path) = temp_socket();
        let listener = Listener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let conn = listener.accept().unwrap();
            conn.peer().uid
        });
        let _client = connect(&path).unwrap();
        assert_eq!(server.join().unwrap(), current_uid());
    }

    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        // A peer may write a frame in pieces; the receiver must not treat a partial read
        // as a malformed message.
        let (_dir, path) = temp_socket();
        let listener = Listener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let mut conn = listener.accept().unwrap();
            conn.receive::<Request>().unwrap()
        });

        let mut client = connect(&path).unwrap();
        let frame = encode_frame(&Request::Lock).unwrap();
        // Write one byte at a time.
        for byte in &frame {
            std::io::Write::write_all(&mut client.stream, &[*byte]).unwrap();
        }
        std::io::Write::flush(&mut client.stream).unwrap();

        assert_eq!(server.join().unwrap(), Request::Lock);
    }

    #[test]
    fn an_oversized_length_prefix_is_refused() {
        let (_dir, path) = temp_socket();
        let listener = Listener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let mut conn = listener.accept().unwrap();
            conn.receive::<Request>()
        });

        let mut client = connect(&path).unwrap();
        // Claim a frame far larger than the limit, then send nothing more.
        let header = (MAX_FRAME_LEN as u64 + 1_000_000) as u32;
        std::io::Write::write_all(&mut client.stream, &header.to_le_bytes()).unwrap();
        std::io::Write::flush(&mut client.stream).unwrap();

        let result = server.join().unwrap();
        assert!(matches!(
            result,
            Err(TransportError::Frame(FrameError::TooLarge { .. }))
        ));
    }

    #[test]
    fn a_closed_connection_is_reported_as_closed() {
        let (_dir, path) = temp_socket();
        let listener = Listener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let mut conn = listener.accept().unwrap();
            conn.receive::<Request>()
        });
        {
            let _client = connect(&path).unwrap();
        }
        assert!(matches!(
            server.join().unwrap(),
            Err(TransportError::Closed)
        ));
    }

    #[test]
    fn the_socket_path_can_be_overridden_for_tests_and_multiple_vaults() {
        // Tests must not fight over one well-known path, and a user may run two vaults.
        let previous = std::env::var(SOCKET_ENV).ok();
        std::env::set_var(SOCKET_ENV, "/tmp/keel-override-test.sock");
        assert_eq!(socket_path(), PathBuf::from("/tmp/keel-override-test.sock"));
        match previous {
            Some(v) => std::env::set_var(SOCKET_ENV, v),
            None => std::env::remove_var(SOCKET_ENV),
        }
    }
}
