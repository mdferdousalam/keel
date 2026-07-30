# Keel vault format, version 1

This is the normative description of the `.keel` file format. It exists so the format
can be independently implemented and independently reviewed, and so that a future
change has to be a deliberate, versioned decision.

**Status: not yet frozen.** Version 1 is complete and implemented, but until the first
tagged release the layout may still change. From 1.0.0 onward, any change to the bytes
described here requires a `format_version` bump and a migration path.

All integers are **little-endian**. All offsets are absolute from the start of the file.

## File layout

```
┌──────────────┬───────────────────┬────────────────────┬──────────┐
│    header    │      records      │  sealed manifest   │  footer  │
│  plaintext,  │  each record      │  nonce ‖ ct ‖ tag  │  48 B    │
│authenticated │  independently    │                    │          │
│              │    encrypted      │                    │          │
└──────────────┴───────────────────┴────────────────────┴──────────┘
```

### Why records come before the manifest

The intuitive layout puts the manifest immediately after the header so metadata can be
read without seeking. That does not work, and the reason should be understood before
anyone changes it.

The manifest stores each record's absolute file offset, and `postcard` varint-encodes
integers — so a larger offset can occupy more bytes. The manifest's length therefore
depends on the offsets, which depend on the manifest's length. Resolving that cycle
would need either fixed-width offsets (wasteful) or iteration to a fixed point
(fragile, and a bug that would only appear at particular vault sizes).

Putting records first eliminates the cycle: the records section starts immediately
after the header, whose length depends only on which unlock factors are configured.
Nothing is lost, because the header records the manifest's offset, so reading it is
still a single seek.

## Header

Plaintext, because it holds the parameters needed to derive the key that decrypts
everything else. Its integrity comes from the binding hash described below.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `magic` | `4B 45 45 4C 56 4C 54 01` (`"KEELVLT\x01"`) |
| 8 | 2 | `format_version` | 1 |
| 10 | 4 | `header_len` | Total header size in bytes, ≤ 65536 |
| 14 | 4 | `flags` | Bit 0 compressed records, bit 1 quick-unlock enrolled. Unknown bits rejected. |
| 18 | 16 | `vault_uuid` | Immutable; also the HKDF salt for every subkey |
| 34 | 8 | `created_at` | Unix seconds |
| 42 | 1 | `kdf_id` | 1 = Argon2id v0x13. Value 2 reserved. |
| 43 | 4 | `argon2_m_cost` | KiB. Accepted range 8192 … 4194304 |
| 47 | 4 | `argon2_t_cost` | 1 … 64 |
| 51 | 4 | `argon2_p_cost` | 1 … 16 |
| 55 | 1 | `kdf_salt_len` | Must be 32 |
| 56 | 32 | `kdf_salt` | |
| 88 | 4 | `measured_kdf_ms` | Informational only |
| 92 | 1 | `factor_flags` | Bit 0 keyfile, bit 1 YubiKey, bit 2 FIDO2. Unknown bits rejected. |
| 93 | var | `factor_tlv` | Present factors in ascending bit order; see below |
| … | 1 | `aead_id` | 1 = XChaCha20-Poly1305. Value 2 reserved for AES-256-GCM. |
| … | 4 | `vmk_epoch_current` | Epoch new records are written under |
| … | 1 | `wrapped_key_count` | 1 … 4 |
| **← end of binding prefix** | | | |
| … | 76 × n | `wrapped_keys` | `epoch:4 ‖ nonce:24 ‖ ciphertext+tag:48` |
| … | 8 | `write_counter` | Strictly monotonic across saves |
| … | 8 | `records_offset` | Must equal `header_len` |
| … | 8 | `records_len` | ≤ 4 GiB |
| … | 8 | `manifest_offset` | Must be ≥ `records_offset + records_len` |
| … | 8 | `manifest_len` | ≤ 64 MiB, ≥ 40 |
| … | 32 | `reserved` | Must be all zero |

### Factor TLV

Encoded in ascending flag-bit order, so encoder and decoder cannot drift:

| Factor | Encoding |
|---|---|
| Keyfile | `commitment:32` — BLAKE3 hash of the keyfile contents |
| YubiKey | `slot:1 ‖ challenge:64` |
| FIDO2 | `rp_id_hash:32 ‖ salt:32 ‖ cred_id_len:4 ‖ cred_id` (id ≤ 1024 bytes) |

## The binding hash

```
H = BLAKE3-256(header bytes from offset 0 through wrapped_key_count inclusive)
```

with `header_len` treated as zero when computing it.

`H` covers the format version, flags, vault id, creation time, KDF identifier and cost
parameters, salt, required factors, AEAD identifier, current epoch, and key count — in
short, every field an attacker would want to weaken. It is mixed into the associated
data of the wrapped key, the manifest, and every record, so any change to a covered
field makes decryption fail rather than succeed cheaply.

**The attack this prevents.** Without it, someone with write access to your vault file
rewrites the header to say `m_cost = 8 KiB`, returns the file, and lets your own client
perform a cheap key derivation they can then brute-force. The parameters are not
secret — there is nothing to hide — but they must be impossible to change undetected.

`header_len` is excluded so that adding a field after the binding prefix cannot
invalidate existing vaults. It is validated separately against the bytes actually
consumed.

## Associated data

```
A_wrap     = "keel/v1/wrap"     ‖ vault_uuid ‖ H ‖ epoch:4
A_manifest = "keel/v1/manifest" ‖ vault_uuid ‖ H ‖ write_counter:8 ‖ format_version:2
A_record   = "keel/v1/record"   ‖ vault_uuid ‖ H ‖ record_id:16 ‖ key_epoch:4
```

`A_manifest` includes the write counter, so replaying an old manifest under a newer
header fails, and rolling the format version backwards fails.

**`A_record` deliberately omits the write counter.** Including it would bind each record
to one specific save, but it would also mean every save re-encrypts every record —
turning a one-entry edit into a full vault rewrite. The record *set* is bound by the
manifest instead, which stores a hash of every record blob. That catches deletion,
duplication, reordering, and splicing from another version of the file, which is what
the write counter would have caught, without the cost.

## Records

Each record is an independent blob:

```
record_id:16 ‖ key_epoch:4 ‖ nonce:24 ‖ ct_len:4 ‖ ciphertext+tag
```

The plaintext is `postcard(RecordBody)` padded to a multiple of **256 bytes**. Padding
is `plaintext ‖ zero filler ‖ original_len:4`.

`RecordBody` holds the username, password, optional TOTP secret, notes, custom fields,
attachment references, and password history. It is the only part of a vault that
contains secrets, and it is decrypted **only** when a specific entry is requested —
never at unlock.

Records are encrypted under `record_key = HKDF-SHA-512(VMK, salt = vault_uuid, info =
"keel/v1/record/" ‖ record_id ‖ key_epoch)`. Deriving rather than storing a wrapped key
per record saves 60+ bytes and a failure mode per entry, and means reading one password
decrypts exactly one record.

## Manifest

`postcard(Manifest)` padded to a multiple of **4096 bytes**, then sealed under
`index_key = HKDF-SHA-512(VMK, salt = vault_uuid, info = "keel/v1/index")` with
`A_manifest`.

The manifest holds, per entry: record id, key epoch, blob hash, blob offset, blob
length, title, username, origins, tags, folder, timestamps, and whether a TOTP secret
exists. It also holds folders, trashed entries, vault settings, paired clients,
persisted grants, and free-space ranges.

`blob_hash` is BLAKE3-256 of the **entire** record blob — id, epoch, nonce, ciphertext,
and tag — not just the ciphertext, so tampering with a record's declared id or epoch is
caught as well.

The manifest contains **no secrets**. It is nonetheless fully encrypted, because
metadata identifies accounts: knowing someone holds a login at a particular bank or
forum can matter as much as the password.

### Structural rules

Enforced on load, after authentication:

- No duplicate record ids.
- No two entries with overlapping blob extents.
- Every declared extent inside the records section.
- Every string within its length limit.

## Footer

| Offset from end | Size | Field |
|---|---|---|
| −48 | 8 | `total_len` — must equal the real file length |
| −40 | 32 | `BLAKE3-256` of all preceding bytes, including `total_len` |
| −8 | 8 | `magic_end` — `"KEELEND\x01"` |

**The footer is a corruption check, not an authentication check.** The hash is unkeyed,
so anyone who edits the file can recompute it. It detects truncation, partial writes,
and bit rot. All authentication comes from the AEAD tags. Treating the footer as
authentication would be a serious mistake, and the code says so in a comment for the
same reason.

## Parse limits

Every limit is checked **before** the value is used to size an allocation. A vault file
is attacker-controlled input, so a header claiming a 64 GiB manifest must be rejected at
the length field rather than after `Vec::with_capacity` invites the OOM killer.

| Limit | Value |
|---|---|
| Header | 64 KiB |
| Manifest | 64 MiB |
| Records section | 4 GiB |
| One record | 16 MiB |
| Entries | 500,000 |
| Wrapped keys | 4 |
| FIDO2 credential id | 1024 B |
| Any string | 4 KiB |
| Notes | 64 KiB |
| Origins / tags / custom fields per entry | 256 |
| Password history per entry | 64 |

Argon2 cost parameters are bounded separately: memory 8 MiB … 4 GiB, time 1 … 64,
parallelism 1 … 16. A caller may additionally reject parameters exceeding the host's
available memory, which returns a distinct error so the UI can prompt rather than fail.

## Reading a vault

1. Check the file is at least 48 bytes.
2. Read the footer; verify `magic_end`, `total_len` against the real length, and the hash.
3. Decode and validate the header, rejecting out-of-range cost parameters before
   allocating.
4. Bounds-check both sections against the real file length.
5. Derive `KEK` from the user's factors and the header parameters; unwrap the VMK for
   `vmk_epoch_current` using `A_wrap`. Failure here is reported as a generic unlock
   failure that does not distinguish which factor was wrong.
6. Derive `index_key`; decrypt the manifest with `A_manifest`.
7. Verify every entry's `blob_hash` against the bytes on disk.
8. On demand, per entry: derive `record_key`, decrypt with `A_record`, unpad, deserialize.

## Writing a vault

1. Encode the header once to learn `header_len`.
2. Lay records out from `header_len`, recording each offset, length, and blob hash.
3. Write those into the corresponding manifest entries.
4. Seal the manifest.
5. Write the real offsets into the header and re-encode; the length must be unchanged.
6. Concatenate header, records, manifest, footer.
7. Persist atomically: write to a temporary file in the same directory, `fsync`, rotate
   backups, rename, then `fsync` the directory.

## Rollback detection

`write_counter` increases by at least one on every save. A reader compares it against
the last value it saw, stored in both a `vault.state` sidecar and the OS keychain. A
regression is **not** silently accepted: the user is shown both counter values and told
that this happens after restoring a backup or a cloud-sync conflict, and that it can
also mean an attacker is rolling them back to an old password. Proceeding requires
explicit confirmation and is recorded in the audit log.

## Companion files

| File | Contents |
|---|---|
| `vault.keel` | The vault |
| `vault.keel.bak.{1,2,3}` | Rotated backups, each tagged with its write counter |
| `vault.audit` | Hash-chained audit log, encrypted under `audit_key` |
| `vault.state` | Last-seen write counter and hashes |
| `vault.keel.lock` | Advisory lock held during a write transaction |

## Test vectors and conformance

`crates/keel-format/tests/` holds round-trip and property tests; `fuzz/` holds the
parser fuzz targets and their seed corpora. From 1.0.0, fixed test vectors in
`crates/keel-format/tests/vectors/` become a compatibility contract: if a change breaks
them, it has changed the format and needs a version bump and a migration, not an updated
vector.
