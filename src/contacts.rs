//! Persistent contact list with identity-key pinning (trust-on-first-use).
//!
//! kiss_chat authenticates every session with the out-of-band **safety words**, but
//! on its own the handshake cannot tell you whether the peer at a given address is
//! the *same* one you verified last time: a rotated — or spoofed — identity key
//! still produces a perfectly valid (differently-worded) handshake. This module
//! closes that gap.
//!
//! When you `/accept` a peer, we pin their long-term ML-DSA identity key against
//! their iroh address (their [`EndpointId`], as text). On a later connection from
//! the same address we compare the presented key to the pinned one and report a
//! [`PinStatus`]:
//!
//!   - [`PinStatus::New`] — this address has never been accepted before;
//!   - [`PinStatus::Known`] — the identity key matches the pin (previously verified);
//!   - [`PinStatus::Changed`] — the identity key *differs* from the pin, which
//!     warrants a careful re-check of the safety words before trusting the peer.
//!
//! The store is a small, non-secret text file (`contacts`) in the config directory,
//! one `"<address> <fingerprint>"` line per peer. The fingerprint is a SHA-256 of
//! the encoded ML-DSA verifying key — enough to detect any change without keeping
//! the multi-kilobyte key itself around.
//!
//! [`EndpointId`]: iroh::EndpointId

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::identity::config_dir;

/// Filename of the pinned contact list inside the config directory.
const CONTACTS_FILE: &str = "contacts";

/// How a connecting peer's identity key compares to what we have pinned for their
/// iroh address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    /// No pin for this address yet — the first time we've been asked to trust it.
    New,
    /// A pin exists and the presented identity key matches it.
    Known,
    /// A pin exists but the presented identity key differs from it.
    Changed,
}

/// Compare a connecting peer's identity key against the pinned contact list.
pub fn status(address: &str, identity_key: &[u8]) -> Result<PinStatus> {
    Ok(status_in(&load(&config_dir()?)?, address, identity_key))
}

/// Pin (or re-pin) a peer's identity key against their iroh address.
///
/// Called when the user `/accept`s a peer: it records the presented key as the
/// trusted one, overwriting any previous pin for that address — so accepting after
/// a [`PinStatus::Changed`] warning adopts the new key deliberately.
pub fn remember(address: &str, identity_key: &[u8]) -> Result<()> {
    let dir = config_dir()?;
    let mut contacts = load(&dir)?;
    contacts.insert(address.to_string(), fingerprint(identity_key));
    save(&dir, &contacts)
}

/// The SHA-256 fingerprint (lowercase hex) of an encoded ML-DSA verifying key.
fn fingerprint(identity_key: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(identity_key)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Classify `identity_key` for `address` against an already-loaded contact list.
fn status_in(
    contacts: &BTreeMap<String, String>,
    address: &str,
    identity_key: &[u8],
) -> PinStatus {
    match contacts.get(address) {
        None => PinStatus::New,
        Some(pinned) if *pinned == fingerprint(identity_key) => PinStatus::Known,
        Some(_) => PinStatus::Changed,
    }
}

/// Load the contact list from `dir`, treating a missing file as empty.
fn load(dir: &Path) -> Result<BTreeMap<String, String>> {
    let path = contacts_path(dir);
    match std::fs::read_to_string(&path) {
        Ok(contents) => Ok(parse(&contents)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read contacts at {}", path.display()))
        }
    }
}

/// Parse the `"<address> <fingerprint>"` lines into a map, skipping blank or
/// malformed lines rather than failing the whole load.
fn parse(contents: &str) -> BTreeMap<String, String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            (!line.is_empty())
                .then(|| line.split_once(char::is_whitespace))
                .flatten()
                .map(|(addr, fp)| (addr.trim().to_string(), fp.trim().to_string()))
        })
        .collect()
}

/// Write the contact list to `dir`, creating the directory if needed.
///
/// The file holds only public keys and public addresses, so — unlike the secret
/// keys next to it — it is written with default (not owner-only) permissions.
fn save(dir: &Path, contacts: &BTreeMap<String, String>) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let mut out = String::new();
    for (address, fingerprint) in contacts {
        out.push_str(address);
        out.push(' ');
        out.push_str(fingerprint);
        out.push('\n');
    }
    let path = contacts_path(dir);
    std::fs::write(&path, out)
        .with_context(|| format!("failed to write contacts to {}", path.display()))
}

/// The path of the contacts file inside `dir`.
fn contacts_path(dir: &Path) -> PathBuf {
    dir.join(CONTACTS_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_address_is_new() {
        let contacts = BTreeMap::new();
        assert_eq!(status_in(&contacts, "addr", b"key"), PinStatus::New);
    }

    #[test]
    fn matching_key_is_known_and_a_mismatch_is_changed() {
        let mut contacts = BTreeMap::new();
        contacts.insert("addr".to_string(), fingerprint(b"key-one"));
        assert_eq!(status_in(&contacts, "addr", b"key-one"), PinStatus::Known);
        assert_eq!(status_in(&contacts, "addr", b"key-two"), PinStatus::Changed);
        // A different address with the same key is still unrecognised.
        assert_eq!(status_in(&contacts, "other", b"key-one"), PinStatus::New);
    }

    #[test]
    fn fingerprint_is_stable_64_char_hex_that_distinguishes_keys() {
        assert_eq!(fingerprint(b"k"), fingerprint(b"k"));
        assert_ne!(fingerprint(b"k"), fingerprint(b"j"));
        assert_eq!(fingerprint(b"k").len(), 64);
        assert!(fingerprint(b"k").chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn parse_skips_blank_and_malformed_lines() {
        let map = parse("addr1 fp1\n\n   \ngarbage-no-space\naddr2   fp2\n");
        assert_eq!(map.get("addr1").map(String::as_str), Some("fp1"));
        assert_eq!(map.get("addr2").map(String::as_str), Some("fp2"));
        assert_eq!(map.len(), 2);
    }

    // A throwaway directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir()
                .join(format!("kiss_chat_contacts_{}_{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_file_loads_as_empty() {
        let dir = TempDir::new();
        assert!(load(&dir.0).unwrap().is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = TempDir::new();
        let mut contacts = BTreeMap::new();
        contacts.insert("addr1".to_string(), fingerprint(b"one"));
        contacts.insert("addr2".to_string(), fingerprint(b"two"));
        save(&dir.0, &contacts).unwrap();
        assert_eq!(load(&dir.0).unwrap(), contacts);
    }

    #[test]
    fn re_pinning_overwrites_the_previous_key() {
        let dir = TempDir::new();

        let mut contacts = load(&dir.0).unwrap();
        contacts.insert("addr".to_string(), fingerprint(b"old-key"));
        save(&dir.0, &contacts).unwrap();

        // A second pin for the same address replaces, rather than duplicates, the first.
        let mut contacts = load(&dir.0).unwrap();
        contacts.insert("addr".to_string(), fingerprint(b"new-key"));
        save(&dir.0, &contacts).unwrap();

        let loaded = load(&dir.0).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(status_in(&loaded, "addr", b"new-key"), PinStatus::Known);
        assert_eq!(status_in(&loaded, "addr", b"old-key"), PinStatus::Changed);
    }
}
