//! Persistent contact list with identity-key pinning (trust-on-first-use).
//!
//! kiss_chat verifies a peer with the out-of-band **safety words** the first time you
//! meet them, but on its own the handshake cannot tell you whether the peer at a given
//! address is the *same* one you verified last time: a rotated — or spoofed — identity
//! key still produces a perfectly valid (differently-worded) handshake. This module
//! closes that gap, so a peer you've already verified is *recognised* on sight and
//! reconnects with a quick consent step rather than a fresh safety-word comparison.
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
//! Alongside each pin we cache the peer's most recent **display name** (once they
//! share one), purely so a recognised peer can be identified at a glance — via the
//! verify step or `/contacts`. The name is cosmetic and never affects trust, which
//! rests on the safety words and the pinned key.
//!
//! The store is a small, non-secret text file (`contacts`) in the config directory,
//! one `"<address> <fingerprint> [name]"` line per peer. The fingerprint is a
//! SHA-256 of the encoded ML-DSA verifying key — enough to detect any change without
//! keeping the multi-kilobyte key itself around. The address and fingerprint are
//! fixed-width hex with no spaces, so the name (which may contain spaces but, being
//! sanitised, never a newline) is simply the remainder of the line.
//!
//! [`EndpointId`]: iroh::EndpointId

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::identity::config_dir;
use crate::message::sanitize_name;

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

/// What we know about a connecting peer from the contact list: how their key
/// compares to any pin, plus the display name we last cached for them (if any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recognition {
    pub status: PinStatus,
    pub name: Option<String>,
}

/// A peer we've accepted before, as listed by [`known_peers`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownPeer {
    pub address: String,
    pub name: Option<String>,
}

/// One pinned contact: the fingerprint of its identity key and a cached display name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Contact {
    fingerprint: String,
    name: Option<String>,
}

/// Look a connecting peer up in the contact list: classify its identity key and
/// return the display name we last cached for that address.
///
/// # Errors
///
/// Fails if the config directory can't be located or the contacts file exists but
/// can't be read.
pub fn recognize(address: &str, identity_key: &[u8]) -> Result<Recognition> {
    recognize_in(&config_dir()?, address, identity_key)
}

/// Pin (or re-pin) a peer's identity key against their iroh address.
///
/// Called when the user `/accept`s a peer: it records the presented key as the
/// trusted one. A pin for an *unchanged* key keeps its cached display name; a
/// *changed* key adopts the new key and drops the stale name (it belonged to the
/// old identity), to be repopulated when the peer next shares one.
///
/// # Errors
///
/// Fails if the contacts file can't be read, or the config directory can't be
/// created or the file written.
pub fn remember(address: &str, identity_key: &[u8]) -> Result<()> {
    remember_in(&config_dir()?, address, identity_key)
}

/// Cache (or, with `None`, clear) the display name for an already-pinned peer.
///
/// A no-op if the address isn't in the contact list — we only remember names for
/// peers we've accepted — and it only rewrites the file when the name changes.
///
/// # Errors
///
/// Fails if the contacts file can't be read or (when the name changes) written.
pub fn set_name(address: &str, name: Option<&str>) -> Result<()> {
    set_name_in(&config_dir()?, address, name)
}

/// The peers we've accepted before, for `/contacts`: named peers first
/// (case-insensitive alphabetical), then unnamed ones by address.
///
/// # Errors
///
/// Fails if the config directory can't be located or the contacts file exists but
/// can't be read.
pub fn known_peers() -> Result<Vec<KnownPeer>> {
    known_peers_in(&config_dir()?)
}

fn recognize_in(dir: &Path, address: &str, identity_key: &[u8]) -> Result<Recognition> {
    let contacts = load(dir)?;
    Ok(Recognition {
        status: status_in(&contacts, address, identity_key),
        name: contacts.get(address).and_then(|c| c.name.clone()),
    })
}

fn remember_in(dir: &Path, address: &str, identity_key: &[u8]) -> Result<()> {
    let mut contacts = load(dir)?;
    let fingerprint = fingerprint(identity_key);
    let entry = contacts
        .entry(address.to_string())
        .or_insert_with(|| Contact {
            fingerprint: fingerprint.clone(),
            name: None,
        });
    if entry.fingerprint != fingerprint {
        entry.fingerprint = fingerprint;
        entry.name = None;
    }
    save(dir, &contacts)
}

fn set_name_in(dir: &Path, address: &str, name: Option<&str>) -> Result<()> {
    let mut contacts = load(dir)?;
    if let Some(entry) = contacts.get_mut(address) {
        let cleaned = name.and_then(sanitize_name);
        if entry.name != cleaned {
            entry.name = cleaned;
            return save(dir, &contacts);
        }
    }
    Ok(())
}

fn known_peers_in(dir: &Path) -> Result<Vec<KnownPeer>> {
    let mut peers: Vec<KnownPeer> = load(dir)?
        .into_iter()
        .map(|(address, contact)| KnownPeer {
            address,
            name: contact.name,
        })
        .collect();
    peers.sort_by(|a, b| match (&a.name, &b.name) {
        (Some(x), Some(y)) => x
            .to_lowercase()
            .cmp(&y.to_lowercase())
            .then_with(|| a.address.cmp(&b.address)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.address.cmp(&b.address),
    });
    Ok(peers)
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
    contacts: &BTreeMap<String, Contact>,
    address: &str,
    identity_key: &[u8],
) -> PinStatus {
    match contacts.get(address) {
        None => PinStatus::New,
        Some(contact) if contact.fingerprint == fingerprint(identity_key) => PinStatus::Known,
        Some(_) => PinStatus::Changed,
    }
}

/// Load the contact list from `dir`, treating a missing file as empty.
fn load(dir: &Path) -> Result<BTreeMap<String, Contact>> {
    let path = contacts_path(dir);
    match std::fs::read_to_string(&path) {
        Ok(contents) => Ok(parse(&contents)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read contacts at {}", path.display()))
        }
    }
}

/// Parse the contact lines into a map, skipping blank or malformed lines rather
/// than failing the whole load.
fn parse(contents: &str) -> BTreeMap<String, Contact> {
    contents.lines().filter_map(parse_line).collect()
}

/// Parse one `"<address> <fingerprint> [name]"` line. The name, if present, is the
/// (trimmed) remainder after the fingerprint, so it may contain spaces.
fn parse_line(line: &str) -> Option<(String, Contact)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (address, rest) = line.split_once(char::is_whitespace)?;
    let rest = rest.trim_start();
    let (fingerprint, name) = match rest.split_once(char::is_whitespace) {
        Some((fingerprint, name)) => {
            let name = name.trim();
            (fingerprint, (!name.is_empty()).then(|| name.to_string()))
        }
        None => (rest, None),
    };
    if fingerprint.is_empty() {
        return None;
    }
    Some((
        address.to_string(),
        Contact {
            fingerprint: fingerprint.to_string(),
            name,
        },
    ))
}

/// Write the contact list to `dir`, creating the directory if needed.
///
/// The file holds only public keys, public addresses, and self-asserted names, so —
/// unlike the secret keys next to it — it is written with default (not owner-only)
/// permissions.
fn save(dir: &Path, contacts: &BTreeMap<String, Contact>) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let mut out = String::new();
    for (address, contact) in contacts {
        out.push_str(address);
        out.push(' ');
        out.push_str(&contact.fingerprint);
        if let Some(name) = &contact.name {
            out.push(' ');
            out.push_str(name);
        }
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

    fn named(fingerprint: &str, name: &str) -> Contact {
        Contact {
            fingerprint: fingerprint.to_string(),
            name: Some(name.to_string()),
        }
    }

    fn anon(fingerprint: &str) -> Contact {
        Contact {
            fingerprint: fingerprint.to_string(),
            name: None,
        }
    }

    #[test]
    fn unknown_address_is_new() {
        let contacts = BTreeMap::new();
        assert_eq!(status_in(&contacts, "addr", b"key"), PinStatus::New);
    }

    #[test]
    fn matching_key_is_known_and_a_mismatch_is_changed() {
        let mut contacts = BTreeMap::new();
        contacts.insert("addr".to_string(), anon(&fingerprint(b"key-one")));
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
    fn parse_reads_named_and_unnamed_lines_and_skips_junk() {
        let map = parse(concat!(
            "addr1 fp1 Alice\n",
            "addr2 fp2\n",
            "\n   \n",
            "garbage-no-space\n",
            "addr3 fp3 Bob and the spaces\n",
        ));
        assert_eq!(map.get("addr1"), Some(&named("fp1", "Alice")));
        assert_eq!(map.get("addr2"), Some(&anon("fp2")));
        assert_eq!(map.get("addr3"), Some(&named("fp3", "Bob and the spaces")));
        assert_eq!(map.len(), 3);
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
    fn save_then_load_round_trips_names_including_spaces() {
        let dir = TempDir::new();
        let mut contacts = BTreeMap::new();
        contacts.insert(
            "addr1".to_string(),
            named(&fingerprint(b"one"), "Alice Smith"),
        );
        contacts.insert("addr2".to_string(), anon(&fingerprint(b"two")));
        save(&dir.0, &contacts).unwrap();
        assert_eq!(load(&dir.0).unwrap(), contacts);
    }

    #[test]
    fn re_pinning_the_same_key_keeps_the_name_a_changed_key_drops_it() {
        let dir = TempDir::new();

        // A first pin plus a cached name.
        let mut contacts = BTreeMap::new();
        contacts.insert("addr".to_string(), named(&fingerprint(b"old-key"), "Alice"));
        save(&dir.0, &contacts).unwrap();

        // Re-pinning the *same* key must preserve the cached name.
        remember_in(&dir.0, "addr", b"old-key").unwrap();
        assert_eq!(
            load(&dir.0).unwrap().get("addr"),
            Some(&named(&fingerprint(b"old-key"), "Alice"))
        );

        // Re-pinning a *different* key adopts it and drops the now-stale name.
        remember_in(&dir.0, "addr", b"new-key").unwrap();
        assert_eq!(
            load(&dir.0).unwrap().get("addr"),
            Some(&anon(&fingerprint(b"new-key")))
        );
    }

    #[test]
    fn set_name_updates_only_existing_contacts_and_sanitises() {
        let dir = TempDir::new();
        // No pin yet: setting a name is a no-op (we only name accepted peers).
        set_name_in(&dir.0, "addr", Some("Alice")).unwrap();
        assert!(load(&dir.0).unwrap().is_empty());

        remember_in(&dir.0, "addr", b"key").unwrap();
        // A control character (here a newline) is stripped before storage.
        set_name_in(&dir.0, "addr", Some("Al\nice")).unwrap();
        assert_eq!(load(&dir.0).unwrap()["addr"].name.as_deref(), Some("Alice"));

        // Clearing removes just the name, leaving the pin intact.
        set_name_in(&dir.0, "addr", None).unwrap();
        assert_eq!(load(&dir.0).unwrap()["addr"], anon(&fingerprint(b"key")));
    }

    #[test]
    fn known_peers_lists_named_first_then_by_address() {
        let dir = TempDir::new();
        remember_in(&dir.0, "addr-z", b"z").unwrap();
        remember_in(&dir.0, "addr-a", b"a").unwrap();
        remember_in(&dir.0, "addr-1", b"1").unwrap();
        set_name_in(&dir.0, "addr-1", Some("bob")).unwrap();
        remember_in(&dir.0, "addr-2", b"2").unwrap();
        set_name_in(&dir.0, "addr-2", Some("Alice")).unwrap();

        let labels: Vec<String> = known_peers_in(&dir.0)
            .unwrap()
            .into_iter()
            .map(|p| p.name.unwrap_or(p.address))
            .collect();
        assert_eq!(labels, vec!["Alice", "bob", "addr-a", "addr-z"]);
    }

    #[test]
    fn recognize_reports_status_and_cached_name() {
        let dir = TempDir::new();
        assert_eq!(
            recognize_in(&dir.0, "addr", b"key").unwrap(),
            Recognition {
                status: PinStatus::New,
                name: None,
            }
        );

        remember_in(&dir.0, "addr", b"key").unwrap();
        set_name_in(&dir.0, "addr", Some("Alice")).unwrap();
        assert_eq!(
            recognize_in(&dir.0, "addr", b"key").unwrap(),
            Recognition {
                status: PinStatus::Known,
                name: Some("Alice".to_string()),
            }
        );
        assert_eq!(
            recognize_in(&dir.0, "addr", b"different-key")
                .unwrap()
                .status,
            PinStatus::Changed
        );
    }
}
