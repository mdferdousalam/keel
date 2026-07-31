// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Verifying a downloaded release.
//!
//! # Why this exists, and why it requires two signatures
//!
//! This is the point at which a user actually places trust. Everything else in Keel protects
//! a vault; this protects the *program*, and a backdoored program makes every other
//! protection irrelevant.
//!
//! The design constraint is that **a compromise of the GitHub repository or its build
//! pipeline must not be able to produce a release that verifies.** So the signing key lives
//! offline on maintainer hardware and never enters CI. CI can therefore publish artifacts,
//! but it cannot sign them; an attacker who owns the pipeline gets an *unsigned* release,
//! which this command rejects.
//!
//! Two signatures are required, and **both** must pass:
//!
//! * **Ed25519**, in minisign format — fast, well understood, widely implemented.
//! * **ML-DSA-65** (FIPS 204) — post-quantum.
//!
//! Requiring both rather than either is the whole point of a hybrid. A release signature has
//! to resist forgery for as long as the software is trusted, which is years; an attacker must
//! break *both* schemes, so the construction is at least as strong as the stronger one. If
//! only one were required, breaking the weaker would be enough.
//!
//! Note the asymmetry with the vault itself: the vault needs no post-quantum work because it
//! contains no public-key cryptography at all (see the README). Signing is where the
//! post-quantum question is real.
//!
//! # What this command cannot do
//!
//! It cannot tell you the *source* was honest — only that the bytes you have are the bytes
//! the maintainer signed. For the stronger claim, rebuild from source and compare hashes; see
//! `docs/REPRODUCE.md`. Reproducibility and signatures answer different questions, and the
//! project needs both.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Name of the checksum manifest inside a release.
pub(crate) const CHECKSUM_FILE: &str = "SHA256SUMS";

/// Name of the Ed25519 (minisign) signature over the checksum manifest.
pub(crate) const MINISIGN_FILE: &str = "SHA256SUMS.minisig";

/// Name of the ML-DSA-65 signature over the checksum manifest.
pub(crate) const MLDSA_FILE: &str = "SHA256SUMS.mldsa.sig";

/// The maintainer's Ed25519 (minisign) public key.
///
/// Compiled in so that verification does not depend on fetching a key from the same place the
/// artifacts came from — which would make the whole exercise circular.
///
/// **Placeholder.** No release has been signed yet. The real key is generated offline and
/// published in three independent locations (this repository, the project site, and the first
/// release announcement) so that substituting it requires compromising all three. Until then
/// [`verify_release`] refuses rather than pretending to check anything.
const MINISIGN_PUBLIC_KEY: Option<&str> = None;

/// The maintainer's ML-DSA-65 public key, hex-encoded. Placeholder; see above.
const MLDSA_PUBLIC_KEY_HEX: Option<&str> = None;

/// Why verification failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VerifyError {
    /// No signing keys are compiled into this build.
    #[error(
        "this build of Keel has no release signing keys compiled in, so it cannot verify a \
         release. This is expected before the first signed release; see docs/VERIFY.md."
    )]
    NoKeys,

    /// A required file is missing from the release directory.
    #[error("{0} is missing from the release directory")]
    Missing(&'static str),

    /// A signature did not verify.
    ///
    /// Named per scheme, because "one of two signatures failed" is a materially different
    /// situation from "both failed" when diagnosing.
    #[error("the {scheme} signature over {CHECKSUM_FILE} did not verify: {detail}")]
    BadSignature {
        /// Which scheme.
        scheme: &'static str,
        /// What went wrong.
        detail: String,
    },

    /// A file's hash did not match the manifest.
    #[error("{file} does not match its recorded checksum")]
    ChecksumMismatch {
        /// The file concerned.
        file: String,
    },

    /// A file listed in the manifest is absent.
    #[error("{file} is listed in {CHECKSUM_FILE} but is not present")]
    FileMissing {
        /// The file concerned.
        file: String,
    },

    /// The checksum manifest could not be parsed.
    #[error("{CHECKSUM_FILE} is malformed on line {line}")]
    MalformedManifest {
        /// One-based line number.
        line: usize,
    },

    /// An I/O failure.
    #[error("{context} {path}: {source}")]
    Io {
        /// What was being attempted.
        context: &'static str,
        /// Which file.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// What was verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedRelease {
    /// Files whose checksums matched, in manifest order.
    pub(crate) files: Vec<String>,
    /// Whether the Ed25519 signature verified.
    pub(crate) ed25519: bool,
    /// Whether the ML-DSA signature verified.
    pub(crate) ml_dsa: bool,
}

impl VerifiedRelease {
    /// Whether the release is fully trustworthy.
    ///
    /// Both signatures, no exceptions. A convenience accessor rather than an inline `&&` so
    /// that no caller can accidentally accept one.
    #[must_use]
    pub(crate) const fn is_trusted(&self) -> bool {
        self.ed25519 && self.ml_dsa
    }
}

/// Verify every artifact in a release directory.
///
/// Order matters: the signatures over the checksum manifest are checked **first**, and a
/// failure stops everything. Checking file hashes against an unauthenticated manifest would
/// be theatre — an attacker who replaced an artifact would simply update the manifest to
/// match.
pub(crate) fn verify_release(dir: &Path) -> Result<VerifiedRelease, VerifyError> {
    let (Some(minisign_key), Some(mldsa_key_hex)) = (MINISIGN_PUBLIC_KEY, MLDSA_PUBLIC_KEY_HEX)
    else {
        return Err(VerifyError::NoKeys);
    };

    let manifest_path = dir.join(CHECKSUM_FILE);
    let manifest = read(&manifest_path, "reading")?;

    // --- signatures over the manifest, before anything else ---
    let minisig = read(&dir.join(MINISIGN_FILE), "reading")
        .map_err(|_| VerifyError::Missing(MINISIGN_FILE))?;
    verify_minisign(minisign_key, &minisig, &manifest)?;

    let mldsa_sig =
        read(&dir.join(MLDSA_FILE), "reading").map_err(|_| VerifyError::Missing(MLDSA_FILE))?;
    verify_mldsa(mldsa_key_hex, &mldsa_sig, &manifest)?;

    // --- now the manifest can be trusted ---
    let entries = parse_manifest(&manifest)?;
    let mut verified = Vec::with_capacity(entries.len());
    for (file, expected) in &entries {
        let path = dir.join(file);
        let bytes =
            read(&path, "reading").map_err(|_| VerifyError::FileMissing { file: file.clone() })?;
        let actual = Sha256::digest(&bytes);
        if actual.as_slice() != expected.as_slice() {
            return Err(VerifyError::ChecksumMismatch { file: file.clone() });
        }
        verified.push(file.clone());
    }

    Ok(VerifiedRelease {
        files: verified,
        ed25519: true,
        ml_dsa: true,
    })
}

fn read(path: &Path, context: &'static str) -> Result<Vec<u8>, VerifyError> {
    std::fs::read(path).map_err(|source| VerifyError::Io {
        context,
        path: path.to_path_buf(),
        source,
    })
}

/// Verify a minisign signature.
fn verify_minisign(public_key: &str, signature: &[u8], message: &[u8]) -> Result<(), VerifyError> {
    let key =
        minisign_verify::PublicKey::decode(public_key).map_err(|e| VerifyError::BadSignature {
            scheme: "Ed25519",
            detail: format!("the compiled-in public key is unusable: {e}"),
        })?;
    let signature_text =
        core::str::from_utf8(signature).map_err(|_| VerifyError::BadSignature {
            scheme: "Ed25519",
            detail: "the signature file is not valid UTF-8".to_owned(),
        })?;
    let signature = minisign_verify::Signature::decode(signature_text).map_err(|e| {
        VerifyError::BadSignature {
            scheme: "Ed25519",
            detail: e.to_string(),
        }
    })?;
    key.verify(message, &signature, false)
        .map_err(|e| VerifyError::BadSignature {
            scheme: "Ed25519",
            detail: e.to_string(),
        })
}

/// Verify an ML-DSA-65 signature.
fn verify_mldsa(public_key_hex: &str, signature: &[u8], message: &[u8]) -> Result<(), VerifyError> {
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes as _, Verifier as _};

    let key_bytes = decode_hex(public_key_hex).ok_or_else(|| VerifyError::BadSignature {
        scheme: "ML-DSA-65",
        detail: "the compiled-in public key is not valid hex".to_owned(),
    })?;
    let key_array: [u8; ml_dsa_65::PK_LEN] =
        key_bytes
            .try_into()
            .map_err(|_| VerifyError::BadSignature {
                scheme: "ML-DSA-65",
                detail: format!("the public key must be {} bytes", ml_dsa_65::PK_LEN),
            })?;
    let key =
        ml_dsa_65::PublicKey::try_from_bytes(key_array).map_err(|e| VerifyError::BadSignature {
            scheme: "ML-DSA-65",
            detail: format!("the public key is unusable: {e}"),
        })?;

    let sig_array: [u8; ml_dsa_65::SIG_LEN] =
        signature
            .to_vec()
            .try_into()
            .map_err(|_| VerifyError::BadSignature {
                scheme: "ML-DSA-65",
                detail: format!("the signature must be {} bytes", ml_dsa_65::SIG_LEN),
            })?;

    if key.verify(message, &sig_array, &[]) {
        Ok(())
    } else {
        Err(VerifyError::BadSignature {
            scheme: "ML-DSA-65",
            detail: "the signature does not match".to_owned(),
        })
    }
}

/// Parse a `sha256sum`-format manifest.
///
/// Accepts the standard `<hex>  <filename>` form. Paths containing a separator are rejected:
/// a manifest entry naming `../../etc/something` must not send the verifier walking outside
/// the release directory.
fn parse_manifest(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, VerifyError> {
    let text =
        core::str::from_utf8(bytes).map_err(|_| VerifyError::MalformedManifest { line: 0 })?;
    let mut out = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index + 1;
        let (hex, name) = line
            .split_once(char::is_whitespace)
            .ok_or(VerifyError::MalformedManifest { line: number })?;
        let digest =
            decode_hex(hex.trim()).ok_or(VerifyError::MalformedManifest { line: number })?;
        if digest.len() != 32 {
            return Err(VerifyError::MalformedManifest { line: number });
        }
        // `sha256sum` writes a leading `*` for binary mode.
        let name = name.trim().trim_start_matches('*').trim();
        if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(VerifyError::MalformedManifest { line: number });
        }
        out.insert(name.to_owned(), digest);
    }
    if out.is_empty() {
        return Err(VerifyError::MalformedManifest { line: 0 });
    }
    Ok(out)
}

/// Decode a hex string.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    // Truncation is impossible: the length was just checked to be even.
    #[allow(clippy::integer_division)]
    let capacity = text.len() / 2;
    let mut out = Vec::with_capacity(capacity);
    for pair in bytes.chunks(2) {
        let hi = (*pair.first()? as char).to_digit(16)?;
        let lo = (*pair.get(1)? as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_rubbish() {
        assert_eq!(decode_hex("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(decode_hex(""), Some(vec![]));
        assert_eq!(decode_hex("f"), None, "odd length");
        assert_eq!(decode_hex("zz"), None, "not hex");
    }

    #[test]
    fn a_well_formed_manifest_parses() {
        let manifest = format!(
            "{}  keel-linux-x86_64.tar.gz\n{}  keel-macos-arm64.dmg\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        let parsed = parse_manifest(manifest.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains_key("keel-linux-x86_64.tar.gz"));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let manifest = format!("# a comment\n\n{}  file\n", "c".repeat(64));
        assert_eq!(parse_manifest(manifest.as_bytes()).unwrap().len(), 1);
    }

    #[test]
    fn binary_mode_markers_are_accepted() {
        // `sha256sum -b` writes a leading asterisk.
        let manifest = format!("{} *file\n", "d".repeat(64));
        let parsed = parse_manifest(manifest.as_bytes()).unwrap();
        assert!(parsed.contains_key("file"));
    }

    #[test]
    fn a_manifest_entry_cannot_escape_the_release_directory() {
        // Without this, a crafted manifest could point the verifier at an arbitrary file and
        // report a "verified release" based on something the maintainer never signed.
        for hostile in ["../etc/passwd", "sub/dir/file", "..\\windows\\file", ".."] {
            let manifest = format!("{}  {hostile}\n", "e".repeat(64));
            assert!(
                parse_manifest(manifest.as_bytes()).is_err(),
                "accepted a path traversal: {hostile}"
            );
        }
    }

    #[test]
    fn a_malformed_manifest_reports_the_line() {
        let manifest = format!("{}  ok\nnot-a-checksum-line\n", "f".repeat(64));
        match parse_manifest(manifest.as_bytes()) {
            Err(VerifyError::MalformedManifest { line }) => assert_eq!(line, 2),
            other => panic!("expected a malformed-manifest error, got {other:?}"),
        }
    }

    #[test]
    fn a_short_digest_is_rejected() {
        let manifest = "abcd  file\n";
        assert!(parse_manifest(manifest.as_bytes()).is_err());
    }

    #[test]
    fn an_empty_manifest_is_rejected() {
        // Otherwise a release with no files listed would "verify" trivially.
        assert!(parse_manifest(b"").is_err());
        assert!(parse_manifest(b"# only a comment\n").is_err());
    }

    #[test]
    fn verification_refuses_rather_than_pretending_when_no_keys_are_compiled_in() {
        // Before the first signed release there is nothing to check against. Reporting
        // success would be far worse than reporting that it cannot be done.
        let dir = tempfile::tempdir().unwrap();
        match verify_release(dir.path()) {
            Err(VerifyError::NoKeys) => {}
            other => panic!("expected NoKeys, got {other:?}"),
        }
    }

    #[test]
    fn both_signatures_are_required_for_trust() {
        // A hybrid where either signature sufficed would be only as strong as the weaker
        // scheme, which defeats the reason for having two.
        let one = VerifiedRelease {
            files: vec!["f".to_owned()],
            ed25519: true,
            ml_dsa: false,
        };
        assert!(!one.is_trusted());

        let other = VerifiedRelease {
            files: vec!["f".to_owned()],
            ed25519: false,
            ml_dsa: true,
        };
        assert!(!other.is_trusted());

        let both = VerifiedRelease {
            files: vec!["f".to_owned()],
            ed25519: true,
            ml_dsa: true,
        };
        assert!(both.is_trusted());
    }
}
