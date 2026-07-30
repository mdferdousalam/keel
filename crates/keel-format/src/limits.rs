//! Size limits applied to anything read from a vault file.
//!
//! **Every one of these is checked before an allocation is made.** That ordering
//! is the whole point. A vault file is attacker-controlled input — someone can mail
//! you one, or drop one in a synced folder — so a header claiming a 64 GiB manifest
//! must be rejected at the length field, not after `Vec::with_capacity` has invited
//! the OOM killer. A crash on malformed input is a denial-of-service bug, and
//! `SECURITY.md` treats it as such.
//!
//! The numbers are chosen to be generous for real vaults and hostile to absurd
//! ones. A 100,000-entry vault with attachments fits comfortably inside them.

/// Maximum total header size, in bytes.
///
/// The header is a fixed layout plus a small factor TLV section. 64 KiB is orders
/// of magnitude more than it can legitimately need, so this bound costs nothing
/// while capping the work a malformed file can cause.
pub const MAX_HEADER_LEN: usize = 64 * 1024;

/// Maximum encrypted manifest size, in bytes.
///
/// The manifest holds metadata for every entry — title, username, origins, tags —
/// but no secrets. At roughly 300 bytes per entry, 64 MiB allows well over
/// 200,000 entries.
pub const MAX_MANIFEST_LEN: usize = 64 * 1024 * 1024;

/// Maximum total size of the records section, in bytes.
pub const MAX_RECORDS_LEN: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum size of one encrypted record, in bytes.
///
/// A record holds one entry's secrets plus its password history. 16 MiB is far
/// beyond any legitimate use; large data belongs in an attachment.
pub const MAX_RECORD_LEN: usize = 16 * 1024 * 1024;

/// Maximum number of entries in a vault.
pub const MAX_ENTRIES: usize = 500_000;

/// Maximum number of wrapped master keys in the header.
///
/// More than one exists only during a lazy key rotation, where records under the
/// old and new epochs coexist until compaction finishes. Four is ample; an
/// unbounded array would be an allocation lever for a hostile file.
pub const MAX_WRAPPED_KEYS: usize = 4;

/// Maximum length of a FIDO2 credential id, in bytes.
///
/// The CTAP2 specification requires authenticators to accept at least 64 bytes and
/// they are typically well under 256.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1024;

/// Maximum length of any single string field in the manifest, in bytes.
///
/// Applies to titles, usernames, origins, tags, and folder names. Long enough for
/// any real value; short enough that 500,000 of them cannot be used to exhaust
/// memory.
pub const MAX_STRING_LEN: usize = 4096;

/// Maximum length of a notes field, in bytes.
pub const MAX_NOTES_LEN: usize = 64 * 1024;

/// Maximum number of origins, tags, or custom fields attached to one entry.
pub const MAX_COLLECTION_LEN: usize = 256;

/// Maximum number of password-history items retained per entry.
pub const MAX_HISTORY_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Compile-time invariants
//
// These are `const` assertions rather than tests: a limit that is set
// inconsistently should fail the build, not wait for someone to run the suite.
// Nesting is what makes the checks in the parser sound — a record cannot be
// permitted to be larger than the section that must contain it.
// ---------------------------------------------------------------------------

const _: () = assert!(
    MAX_HEADER_LEN < MAX_RECORD_LEN,
    "a header must not be allowed to exceed a record"
);
const _: () = assert!(
    MAX_RECORD_LEN < MAX_MANIFEST_LEN,
    "one record must not be allowed to exceed the whole manifest"
);
const _: () = assert!(
    (MAX_MANIFEST_LEN as u64) < MAX_RECORDS_LEN,
    "the manifest must not be allowed to exceed the records section"
);
const _: () = assert!(
    MAX_STRING_LEN < MAX_NOTES_LEN,
    "notes are expected to be longer than an ordinary field"
);

// A vault of 100,000 entries at a generous 400 bytes of metadata each must fit
// comfortably. These limits exist to reject hostile files, not real ones — a limit
// that a legitimate power user can hit is a bug.
const _: () = assert!(
    MAX_MANIFEST_LEN > 100_000 * 400,
    "manifest limit would reject a realistically large vault"
);
const _: () = assert!(
    MAX_ENTRIES >= 100_000,
    "entry limit would reject a realistically large vault"
);
