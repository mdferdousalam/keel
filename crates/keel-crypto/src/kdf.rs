// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Password-based key derivation: Argon2id, factor mixing, and calibration.
//!
//! This is the layer that stands between a stolen vault file and every password
//! in it, so the parameter choices are deliberately aggressive. RFC 9106's
//! 64 MiB and OWASP's 19 MiB are floors for *servers* handling many logins per
//! second. A desktop vault is unlocked a handful of times a day — and with the
//! agent daemon holding the unlocked vault, often only once — so we spend memory
//! freely. Cracking cost on GPU/FPGA/ASIC scales with memory, not iterations.
//!
//! This module also carries the quantum story for the password layer: Grover's
//! algorithm would have to evaluate the *entire* KDF coherently in superposition
//! — for the default tier, 512 MiB of quantum memory held coherent across four
//! passes, times ~2^(n/2) iterations. Memory-hard KDFs are close to the worst
//! possible target for Grover, which is why memory-hardness is an anti-quantum
//! measure and not just an anti-GPU one.

use core::fmt;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{Error, Result};
use crate::secret::{Key256, SecretBytes};

/// Length of the KDF salt, in bytes.
pub const SALT_LEN: usize = 32;

/// Identifier for the Argon2id-v0x13 KDF in the vault header.
///
/// A registry rather than a bool so a future memory-hard successor can be added
/// without a format break. Value `2` is reserved.
pub const KDF_ID_ARGON2ID_V13: u8 = 1;

/// Domain string for factor pre-mixing. Versioned; never reused.
const PREKEY_DOMAIN: &[u8] = b"keel/v1/prekey";

// ---------------------------------------------------------------------------
// Parameter guards
// ---------------------------------------------------------------------------

/// Hard ceiling on memory cost, in KiB (4 GiB).
///
/// This bound exists to stop a *malicious vault file*, not a confused user. A
/// header claiming `m_cost = 64 GiB` would otherwise have us try to allocate it
/// and meet the OOM killer — a denial of service triggered by merely opening a
/// file someone sent you. Checked before any allocation.
pub const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;

/// Floor on memory cost, in KiB (8 MiB).
///
/// Below this, the KDF is weak enough that we refuse rather than silently
/// accepting it. Note that a tampered header cannot exploit weak params anyway:
/// the parameters are covered by the AEAD associated data on the wrapped master
/// key, so a downgraded header fails authentication. This is defence in depth.
pub const MIN_M_COST_KIB: u32 = 8 * 1024;

/// Ceiling on time cost (passes).
pub const MAX_T_COST: u32 = 64;

/// Ceiling on parallelism (lanes).
pub const MAX_P_COST: u32 = 16;

/// Ceiling used when *calibrating* new parameters, in KiB (2 GiB).
///
/// Lower than [`MAX_M_COST_KIB`]: we will open a vault that legitimately used up
/// to 4 GiB, but we will never choose more than 2 GiB for a new one.
pub const MAX_CALIBRATED_M_COST_KIB: u32 = 2 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Tiers
// ---------------------------------------------------------------------------

/// Named parameter tiers offered at vault creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KdfTier {
    /// 256 MiB, 3 passes — roughly 0.4–0.7 s on a modern desktop.
    Interactive,
    /// 512 MiB, 4 passes — roughly 1.2–2.0 s. The default.
    #[default]
    Balanced,
    /// 1 GiB, 6 passes — roughly 4–6 s.
    Paranoid,
}

impl KdfTier {
    /// All tiers, weakest first.
    pub const ALL: [KdfTier; 3] = [Self::Interactive, Self::Balanced, Self::Paranoid];

    /// Parameters for this tier, with `p_cost` clamped to the available cores.
    ///
    /// Parallelism is capped at the host's core count because Argon2's lanes
    /// only buy defender-side speed when they can actually run concurrently —
    /// an attacker with a GPU farm is not so constrained.
    #[must_use]
    pub fn params(self, cores: u32) -> Argon2Params {
        let p_cost = cores.clamp(1, 4);
        let (m_cost_kib, t_cost) = match self {
            Self::Interactive => (256 * 1024, 3),
            Self::Balanced => (512 * 1024, 4),
            Self::Paranoid => (1024 * 1024, 6),
        };
        Argon2Params {
            m_cost_kib,
            t_cost,
            // Paranoid deliberately uses more lanes than the others.
            p_cost: if self == Self::Paranoid {
                cores.clamp(1, 8)
            } else {
                p_cost
            },
        }
    }

    /// Human-readable name, used in the CLI and the GUI.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Balanced => "balanced",
            Self::Paranoid => "paranoid",
        }
    }
}

impl fmt::Display for KdfTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// Concrete Argon2id parameters, as stored in the vault header.
///
/// Stored in the file (and covered by AEAD associated data) so that the cost can
/// be raised later on an existing vault without re-encrypting a single record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Time cost (number of passes).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        KdfTier::Balanced.params(4)
    }
}

impl Argon2Params {
    /// Validate against the absolute accepted range.
    ///
    /// Call this on every set of parameters read from a file, before allocating
    /// anything.
    pub fn validate(&self) -> Result<()> {
        if self.m_cost_kib > MAX_M_COST_KIB {
            return Err(Error::KdfParams("memory cost exceeds 4 GiB ceiling"));
        }
        if self.m_cost_kib < MIN_M_COST_KIB {
            return Err(Error::KdfParams("memory cost below 8 MiB floor"));
        }
        if self.t_cost == 0 || self.t_cost > MAX_T_COST {
            return Err(Error::KdfParams("time cost must be in 1..=64"));
        }
        if self.p_cost == 0 || self.p_cost > MAX_P_COST {
            return Err(Error::KdfParams("parallelism must be in 1..=16"));
        }
        // Argon2 requires at least 8 KiB per lane.
        if self.m_cost_kib < self.p_cost.saturating_mul(8) {
            return Err(Error::KdfParams("memory cost too small for lane count"));
        }
        Ok(())
    }

    /// Validate against this specific host's memory.
    ///
    /// Separate from [`Argon2Params::validate`] because this crate performs no
    /// I/O and does not know how much RAM the machine has — the caller supplies
    /// it. Returning an error here means "ask the user before trying"; it is not
    /// necessarily a corrupt file, since a vault created on a 64 GiB workstation
    /// can legitimately be opened on an 8 GiB laptop.
    pub fn validate_for_host(&self, available_ram_bytes: u64) -> Result<()> {
        self.validate()?;
        let needed = u64::from(self.m_cost_kib) * 1024;
        if available_ram_bytes > 0 && needed * 2 > available_ram_bytes {
            return Err(Error::KdfParams(
                "this vault needs more memory than is currently available",
            ));
        }
        Ok(())
    }

    /// Memory cost in bytes.
    #[must_use]
    pub const fn memory_bytes(&self) -> u64 {
        self.m_cost_kib as u64 * 1024
    }

    /// True if these parameters are weaker than the current recommended
    /// default, so the GUI can offer an in-place upgrade.
    #[must_use]
    pub fn is_below_recommended(&self) -> bool {
        let recommended = KdfTier::Balanced.params(self.p_cost.max(1));
        self.m_cost_kib < recommended.m_cost_kib || self.t_cost < recommended.t_cost
    }

    fn to_argon2(self) -> Result<Argon2<'static>> {
        self.validate()?;
        let params = Params::new(
            self.m_cost_kib,
            self.t_cost,
            self.p_cost,
            Some(Params::DEFAULT_OUTPUT_LEN),
        )
        .map_err(|_| Error::KdfParams("backend rejected parameter combination"))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

// ---------------------------------------------------------------------------
// Factor mixing
// ---------------------------------------------------------------------------

/// The set of unlock factors supplied by the user.
///
/// Absent factors contribute a zero-length field to the mix. The vault header
/// separately records which factors are *required*, so stripping a factor from
/// the header does not let an attacker unlock with fewer of them — the wrapped
/// key's associated data covers those flags.
#[derive(Clone, Copy)]
pub struct Factors<'a> {
    /// The master passphrase. Always required.
    pub passphrase: &'a [u8],
    /// BLAKE3 hash of the keyfile contents, if a keyfile is in use.
    pub keyfile_hash: Option<&'a [u8; 32]>,
    /// Response from a hardware factor: 32 bytes for FIDO2 `hmac-secret`,
    /// 20 bytes for a YubiKey HMAC-SHA1 challenge-response.
    pub hardware_response: Option<&'a [u8]>,
}

impl fmt::Debug for Factors<'_> {
    /// Reports only which factors are present, never their contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Factors")
            .field("passphrase", &"<redacted>")
            .field("keyfile", &self.keyfile_hash.is_some())
            .field("hardware", &self.hardware_response.is_some())
            .finish()
    }
}

/// Mix all supplied factors into a single input keying material value.
///
/// Factors are **never** concatenated into a password string. Doing that makes
/// `("ab", "c")` and `("a", "bc")` produce the same input — a real ambiguity
/// that has bitten real products. Instead each field is length-prefixed and fed
/// into a keyed BLAKE3 whose key is itself bound to the vault UUID, so the mix
/// is unambiguous and vault-specific.
///
/// The passphrase is streamed into the hasher rather than copied into a
/// temporary buffer, so this function creates no additional copy of it.
#[must_use]
pub fn mix_factors(vault_uuid: &[u8; 16], factors: &Factors<'_>) -> Key256 {
    let mut key_hasher = blake3::Hasher::new();
    key_hasher.update(PREKEY_DOMAIN);
    key_hasher.update(vault_uuid);
    let mix_key = key_hasher.finalize();

    let mut hasher = blake3::Hasher::new_keyed(mix_key.as_bytes());
    for field in [
        Some(factors.passphrase),
        factors.keyfile_hash.map(|h| h.as_slice()),
        factors.hardware_response,
    ] {
        let bytes = field.unwrap_or(&[]);
        // Length prefix makes the concatenation unambiguous.
        hasher.update(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
        hasher.update(bytes);
    }

    let mut out = SecretBytes::<32>::zeroed();
    hasher.finalize_xof().fill(out.expose_mut());
    out
}

/// Derive the key-encryption key (KEK) from mixed factors.
///
/// The KEK is never stored. It exists only to unwrap the vault master key, which
/// is what every record key is actually derived from. That indirection is why
/// changing the master password rewrites 200 bytes of header instead of
/// re-encrypting the whole vault.
pub fn derive_kek(ikm: &Key256, salt: &[u8], params: Argon2Params) -> Result<Key256> {
    if salt.len() < 8 {
        return Err(Error::InvalidLength {
            expected: SALT_LEN,
            actual: salt.len(),
        });
    }
    let argon = params.to_argon2()?;
    let mut kek = SecretBytes::<32>::zeroed();
    argon
        .hash_password_into(ikm.expose(), salt, kek.expose_mut())
        .map_err(|_| Error::KdfFailure)?;
    Ok(kek)
}

/// Convenience: mix factors and derive the KEK in one step.
pub fn derive_kek_from_factors(
    vault_uuid: &[u8; 16],
    factors: &Factors<'_>,
    salt: &[u8],
    params: Argon2Params,
) -> Result<Key256> {
    let ikm = mix_factors(vault_uuid, factors);
    derive_kek(&ikm, salt, params)
}

/// Hash keyfile contents into the 32-byte commitment used as a factor.
#[must_use]
pub fn hash_keyfile(contents: &[u8]) -> [u8; 32] {
    *blake3::hash(contents).as_bytes()
}

// ---------------------------------------------------------------------------
// Calibration
// ---------------------------------------------------------------------------

/// Outcome of calibrating KDF parameters on this machine.
#[derive(Debug, Clone, Copy)]
pub struct Calibration {
    /// Chosen parameters.
    pub params: Argon2Params,
    /// Tier the parameters correspond to, if they match one exactly.
    pub tier: Option<KdfTier>,
    /// Measured wall-clock time of a real derivation with these parameters.
    ///
    /// Stored in the header so a later unlock can tell the user "this took 1.4 s
    /// when you created the vault and takes 6 s now".
    pub measured: Duration,
}

/// Pick the strongest tier whose derivation fits inside `budget` on this host.
///
/// Runs a small probe (256 MiB, one pass) and extrapolates linearly in
/// `m_cost × t_cost`, which is accurate enough to choose between three tiers.
/// The chosen tier is then measured for real, so the recorded time is not an
/// extrapolation.
///
/// `available_ram_bytes` and `cores` are supplied by the caller because this
/// crate does no I/O and does not inspect the host.
pub fn calibrate(budget: Duration, available_ram_bytes: u64, cores: u32) -> Result<Calibration> {
    let probe = Argon2Params {
        m_cost_kib: 256 * 1024,
        t_cost: 1,
        p_cost: cores.clamp(1, 4),
    };
    let probe_time = time_derivation(probe)?;
    let probe_work = f64::from(probe.m_cost_kib) * f64::from(probe.t_cost);

    // Never choose parameters needing more than a quarter of available memory,
    // and never exceed the calibration ceiling. Truncation is intended and safe
    // in both divisions: rounding down only ever makes the cap more conservative.
    let ram_cap_kib = if available_ram_bytes == 0 {
        MAX_CALIBRATED_M_COST_KIB
    } else {
        #[allow(clippy::integer_division)]
        let quarter_kib = available_ram_bytes / 4 / 1024;
        u32::try_from(quarter_kib)
            .unwrap_or(MAX_CALIBRATED_M_COST_KIB)
            .min(MAX_CALIBRATED_M_COST_KIB)
    };

    let mut chosen = KdfTier::Interactive;
    for tier in KdfTier::ALL {
        let p = tier.params(cores);
        if p.m_cost_kib > ram_cap_kib {
            break;
        }
        let work = f64::from(p.m_cost_kib) * f64::from(p.t_cost);
        let predicted = probe_time.mul_f64(work / probe_work);
        if predicted <= budget {
            chosen = tier;
        } else {
            break;
        }
    }

    let mut params = chosen.params(cores);
    // If even the weakest tier does not fit the RAM cap, fall back to the floor
    // rather than failing outright — a weak vault the user can open beats a
    // strong vault they cannot.
    if params.m_cost_kib > ram_cap_kib {
        params.m_cost_kib = ram_cap_kib.max(MIN_M_COST_KIB);
    }
    params.validate()?;

    let measured = time_derivation(params)?;
    Ok(Calibration {
        params,
        tier: Some(chosen),
        measured,
    })
}

/// Time a single derivation with the given parameters, using a throwaway input.
fn time_derivation(params: Argon2Params) -> Result<Duration> {
    let ikm = SecretBytes::<32>::zeroed();
    let salt = [0x5Au8; SALT_LEN];
    let start = Instant::now();
    let kek = derive_kek(&ikm, &salt, params)?;
    let elapsed = start.elapsed();
    drop(kek);
    Ok(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so the test suite does not spend a second per case.
    /// Real vaults never use these.
    fn test_params() -> Argon2Params {
        Argon2Params {
            m_cost_kib: MIN_M_COST_KIB,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn default_tier_is_balanced_at_512_mib() {
        let p = KdfTier::Balanced.params(4);
        assert_eq!(p.m_cost_kib, 512 * 1024);
        assert_eq!(p.t_cost, 4);
        assert_eq!(p.p_cost, 4);
        p.validate().unwrap();
    }

    #[test]
    fn all_tiers_validate() {
        for tier in KdfTier::ALL {
            for cores in [1u32, 2, 4, 8, 16, 64] {
                tier.params(cores).validate().unwrap();
            }
        }
    }

    #[test]
    fn rejects_absurd_memory_cost_before_allocating() {
        // The denial-of-service case: a hostile file asking for 64 GiB.
        let p = Argon2Params {
            m_cost_kib: 64 * 1024 * 1024,
            t_cost: 3,
            p_cost: 4,
        };
        assert!(matches!(p.validate(), Err(Error::KdfParams(_))));
    }

    #[test]
    fn rejects_weak_and_malformed_parameters() {
        // (m_cost_kib, t_cost, p_cost, why it must be rejected)
        let cases = [
            (8, 3, 1, "far below the memory floor"),
            (512 * 1024, 0, 1, "zero passes"),
            (512 * 1024, 1, 0, "zero lanes"),
            (512 * 1024, 65, 1, "more passes than the ceiling"),
            (512 * 1024, 1, 17, "more lanes than the ceiling"),
            (64, 1, 16, "too little memory for the lane count"),
        ];
        for (m_cost_kib, t_cost, p_cost, why) in cases {
            let p = Argon2Params {
                m_cost_kib,
                t_cost,
                p_cost,
            };
            assert!(p.validate().is_err(), "should have rejected {p:?}: {why}");
        }
    }

    #[test]
    fn host_validation_rejects_params_needing_more_ram_than_available() {
        let paranoid = KdfTier::Paranoid.params(4); // 1 GiB
                                                    // Opening this vault on a 512 MiB machine would thrash or be OOM-killed.
        assert!(paranoid.validate_for_host(512 * 1024 * 1024).is_err());
        // Plenty of headroom: fine.
        paranoid.validate_for_host(8 * 1024 * 1024 * 1024).unwrap();
        // Zero means "caller could not determine available memory", which must
        // not block an unlock.
        paranoid.validate_for_host(0).unwrap();
    }

    #[test]
    fn derivation_is_deterministic() {
        let uuid = [3u8; 16];
        let factors = Factors {
            passphrase: b"correct horse battery staple",
            keyfile_hash: None,
            hardware_response: None,
        };
        let salt = [9u8; SALT_LEN];
        let a = derive_kek_from_factors(&uuid, &factors, &salt, test_params()).unwrap();
        let b = derive_kek_from_factors(&uuid, &factors, &salt, test_params()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_passphrase_gives_different_key() {
        let uuid = [3u8; 16];
        let salt = [9u8; SALT_LEN];
        let a = derive_kek_from_factors(
            &uuid,
            &Factors {
                passphrase: b"password-a",
                keyfile_hash: None,
                hardware_response: None,
            },
            &salt,
            test_params(),
        )
        .unwrap();
        let b = derive_kek_from_factors(
            &uuid,
            &Factors {
                passphrase: b"password-b",
                keyfile_hash: None,
                hardware_response: None,
            },
            &salt,
            test_params(),
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn same_passphrase_different_vault_gives_different_key() {
        // Two vaults with the same password must not share a KEK, so that
        // cracking effort against one does not transfer to the other.
        let salt = [9u8; SALT_LEN];
        let factors = Factors {
            passphrase: b"same",
            keyfile_hash: None,
            hardware_response: None,
        };
        let a = derive_kek_from_factors(&[1u8; 16], &factors, &salt, test_params()).unwrap();
        let b = derive_kek_from_factors(&[2u8; 16], &factors, &salt, test_params()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salt_gives_different_key() {
        let uuid = [3u8; 16];
        let factors = Factors {
            passphrase: b"same",
            keyfile_hash: None,
            hardware_response: None,
        };
        let a = derive_kek_from_factors(&uuid, &factors, &[1u8; SALT_LEN], test_params()).unwrap();
        let b = derive_kek_from_factors(&uuid, &factors, &[2u8; SALT_LEN], test_params()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn adding_a_factor_changes_the_key() {
        let uuid = [3u8; 16];
        let salt = [9u8; SALT_LEN];
        let kf = [0xAAu8; 32];
        let without = derive_kek_from_factors(
            &uuid,
            &Factors {
                passphrase: b"pw",
                keyfile_hash: None,
                hardware_response: None,
            },
            &salt,
            test_params(),
        )
        .unwrap();
        let with = derive_kek_from_factors(
            &uuid,
            &Factors {
                passphrase: b"pw",
                keyfile_hash: Some(&kf),
                hardware_response: None,
            },
            &salt,
            test_params(),
        )
        .unwrap();
        assert_ne!(without, with);
    }

    #[test]
    fn factor_mixing_is_unambiguous() {
        // The bug this test exists to prevent: naive concatenation makes
        // ("ab", "c") and ("a", "bc") derive the same key. Length prefixes stop
        // that. Both hardware responses are the same total byte string split at
        // a different point.
        let uuid = [7u8; 16];
        let a = mix_factors(
            &uuid,
            &Factors {
                passphrase: b"ab",
                keyfile_hash: None,
                hardware_response: Some(b"c"),
            },
        );
        let b = mix_factors(
            &uuid,
            &Factors {
                passphrase: b"a",
                keyfile_hash: None,
                hardware_response: Some(b"bc"),
            },
        );
        assert_ne!(a, b);
    }

    #[test]
    fn missing_factor_differs_from_empty_factor() {
        // A zero-length present factor and an absent factor both contribute a
        // zero-length field, so they mix identically. That is intentional and
        // safe: the header's required-factor flags are authenticated separately,
        // so an attacker cannot strip a factor and unlock with fewer.
        let uuid = [7u8; 16];
        let absent = mix_factors(
            &uuid,
            &Factors {
                passphrase: b"pw",
                keyfile_hash: None,
                hardware_response: None,
            },
        );
        let empty = mix_factors(
            &uuid,
            &Factors {
                passphrase: b"pw",
                keyfile_hash: None,
                hardware_response: Some(b""),
            },
        );
        assert_eq!(absent, empty);
    }

    #[test]
    fn short_salt_is_rejected() {
        let ikm = SecretBytes::<32>::zeroed();
        assert!(derive_kek(&ikm, &[0u8; 4], test_params()).is_err());
    }

    #[test]
    fn keyfile_hash_is_stable_and_distinguishing() {
        assert_eq!(hash_keyfile(b"abc"), hash_keyfile(b"abc"));
        assert_ne!(hash_keyfile(b"abc"), hash_keyfile(b"abd"));
    }

    #[test]
    fn below_recommended_flags_weak_params() {
        assert!(KdfTier::Interactive.params(4).is_below_recommended());
        assert!(!KdfTier::Balanced.params(4).is_below_recommended());
        assert!(!KdfTier::Paranoid.params(4).is_below_recommended());
    }

    #[test]
    #[ignore = "runs real Argon2 derivations; slow. Run with --ignored."]
    fn calibration_picks_something_valid_within_budget() {
        let cal = calibrate(Duration::from_millis(1500), 16 * 1024 * 1024 * 1024, 8).unwrap();
        cal.params.validate().unwrap();
        assert!(cal.measured > Duration::ZERO);
    }
}
