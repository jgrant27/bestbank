//! Password hashing using Argon2id with a random per-password salt.
//!
//! Hashes are stored as self-describing PHC strings
//! (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`), so the algorithm
//! parameters and salt travel with the hash.

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};

/// Hash `password` with Argon2id (default parameters) and a fresh random salt.
///
/// # Panics
/// Only if the OS random number generator is unavailable.
pub fn hash_password(password: &str) -> String {
    Argon2::default()
        .hash_password(password.as_bytes())
        .expect("argon2 hashing with default params should not fail")
        .to_string()
}

/// Verify `password` against a stored PHC hash string. Returns `false` for
/// a mismatch or an unparseable hash.
pub fn verify_password(password: &str, phc_hash: &str) -> bool {
    PasswordHash::new(phc_hash).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip_and_salted() {
        let a = hash_password("admin");
        let b = hash_password("admin");
        assert!(a.starts_with("$argon2id$"));
        assert_ne!(a, b, "each hash must use a unique salt");
        assert!(verify_password("admin", &a));
        assert!(!verify_password("wrong", &a));
        assert!(!verify_password("admin", "not-a-hash"));
    }
}
