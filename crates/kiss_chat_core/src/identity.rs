//! Persistent, on-disk identity for kiss_chat.
//!
//! kiss_chat keeps two long-term secrets, both 32 bytes and stored as hex under
//! the user's config directory:
//!
//!   - the **iroh endpoint secret key** (`secret.key`) — your reachable address,
//!     the [`EndpointId`] peers dial; and
//!   - the **ML-DSA authentication seed** (`auth.key`) — your post-quantum signing
//!     identity, which the handshake uses to prove who you are and which peers
//!     verify out-of-band via the session *safety number*.
//!
//! Both are generated once, on first run, and reused thereafter so your identity
//! is stable across restarts.
//!
//! Alongside them sits an optional, non-secret **display name** (`name`): a plain
//! UTF-8 file holding whatever the user set with `/name`. It is absent until set,
//! stored world-readable (it's not a secret), and only ever shared with a peer
//! after a channel is accepted.
//!
//! [`EndpointId`]: iroh::EndpointId

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use iroh::SecretKey;

/// Filename of the iroh endpoint secret key inside the config directory.
const ENDPOINT_KEY_FILE: &str = "secret.key";
/// Filename of the ML-DSA authentication seed inside the config directory.
const AUTH_SEED_FILE: &str = "auth.key";
/// Filename of the optional display name inside the config directory.
const DISPLAY_NAME_FILE: &str = "name";

/// Load the persistent iroh endpoint key, creating one on first run.
///
/// # Errors
///
/// Fails if the config directory can't be located or created, or if an existing
/// `secret.key` can't be read or is malformed.
pub fn load_or_create_endpoint_secret() -> Result<SecretKey> {
    let bytes = load_or_create_key(&config_dir()?, ENDPOINT_KEY_FILE, || {
        SecretKey::generate().to_bytes()
    })?;
    Ok(SecretKey::from_bytes(&bytes))
}

/// Load the persistent 32-byte ML-DSA authentication seed, creating one on first run.
///
/// # Errors
///
/// Fails if the config directory can't be located or created, or if an existing
/// `auth.key` can't be read or is malformed.
pub fn load_or_create_auth_seed() -> Result<[u8; 32]> {
    load_or_create_key(&config_dir()?, AUTH_SEED_FILE, random_seed)
}

/// A fresh 32-byte seed drawn straight from the operating system CSPRNG.
fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("operating system CSPRNG must be available");
    seed
}

/// Load the saved display name, if the user has ever set one.
///
/// Returns the raw stored string (trimmed); the caller sanitises it before use.
/// A missing file is not an error — a display name is optional.
///
/// # Errors
///
/// Fails if the config directory can't be located, or the `name` file exists but
/// can't be read.
pub fn load_display_name() -> Result<Option<String>> {
    load_display_name_in(&config_dir()?)
}

/// Persist (or, with `None`, remove) the display name.
///
/// # Errors
///
/// Fails if the config directory can't be located or created, or the `name` file
/// can't be written or removed.
pub fn save_display_name(name: Option<&str>) -> Result<()> {
    save_display_name_in(&config_dir()?, name)
}

/// Read the display name from `dir`, treating a missing file as "unset".
fn load_display_name_in(dir: &Path) -> Result<Option<String>> {
    let path = dir.join(DISPLAY_NAME_FILE);
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read display name at {}", path.display()))
        }
    }
}

/// Write the display name into `dir`, or delete the file when clearing it.
fn save_display_name_in(dir: &Path, name: Option<&str>) -> Result<()> {
    let path = dir.join(DISPLAY_NAME_FILE);
    match name {
        Some(name) => {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
            std::fs::write(&path, name)
                .with_context(|| format!("failed to write display name to {}", path.display()))
        }
        None => match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err)
                .with_context(|| format!("failed to clear display name at {}", path.display())),
        },
    }
}

/// Read a 32-byte key from `file` in `dir`, or generate, persist, and return a
/// fresh one (via `generate`) if the file does not exist yet.
fn load_or_create_key(
    dir: &Path,
    file: &str,
    generate: impl FnOnce() -> [u8; 32],
) -> Result<[u8; 32]> {
    let path = dir.join(file);

    if path.exists() {
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read key at {}", path.display()))?;
        return decode_hex(&contents)
            .with_context(|| format!("malformed key at {}", path.display()));
    }

    let bytes = generate();
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    write_secret(&path, &bytes)
        .with_context(|| format!("failed to write key to {}", path.display()))?;
    Ok(bytes)
}

/// The directory holding kiss_chat's keys: `$XDG_CONFIG_HOME/kiss_chat`, or
/// `$HOME/.config/kiss_chat` when `XDG_CONFIG_HOME` is unset.
pub(crate) fn config_dir() -> Result<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else {
        let home = std::env::var_os("HOME")
            .context("cannot locate config directory: neither XDG_CONFIG_HOME nor HOME is set")?;
        PathBuf::from(home).join(".config")
    };
    Ok(base.join("kiss_chat"))
}

/// Write 32 secret bytes as hex, restricted to owner-only on unix.
///
/// On non-unix platforms (Windows) we can't set a POSIX mode, so the file
/// inherits the ACLs of its parent directory. In practice these keys live under
/// the user's profile (`%USERPROFILE%`/`$HOME`), which is not readable by other
/// standard users by default — but on a machine with a deliberately world-readable
/// config directory this offers weaker protection than the unix `0o600`.
fn write_secret(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    let hex = encode_hex(bytes);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // Create with mode 0600 up front so the key is never briefly world-readable.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(hex.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, hex)?;
    }
    Ok(())
}

/// Encode 32 bytes as a 64-character lowercase hex string.
fn encode_hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Decode a 64-character hex string (with optional surrounding whitespace) into 32 bytes.
fn decode_hex(text: &str) -> Result<[u8; 32]> {
    let text = text.trim();
    // `text.len()` counts bytes: a multibyte character could satisfy the length
    // check yet make the 2-byte slices below straddle a char boundary and panic.
    // Hex is ASCII, so reject anything else here and fail cleanly instead.
    ensure!(
        text.is_ascii() && text.len() == 64,
        "expected 64 hex characters, got {}",
        text.chars().count()
    );
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .context("key contains non-hex characters")?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
        let encoded = encode_hex(&bytes);
        assert_eq!(encoded.len(), 64);
        assert_eq!(decode_hex(&encoded).unwrap(), bytes);
    }

    #[test]
    fn decode_hex_tolerates_surrounding_whitespace() {
        let encoded = encode_hex(&[0xAB; 32]);
        assert_eq!(decode_hex(&format!("\n  {encoded}\n")).unwrap(), [0xAB; 32]);
    }

    #[test]
    fn decode_hex_rejects_wrong_length() {
        assert!(decode_hex("abcd").is_err());
    }

    #[test]
    fn decode_hex_rejects_non_hex() {
        assert!(decode_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn decode_hex_rejects_multibyte_without_panicking() {
        // A 64-*byte* string can hold a multibyte character; the 2-byte slicing
        // must reject it cleanly rather than panic on a non-char-boundary slice.
        // 'é' is two UTF-8 bytes, so this is 64 bytes but only 63 characters.
        let sneaky = format!("a\u{e9}{}", "0".repeat(61));
        assert_eq!(sneaky.len(), 64);
        assert!(decode_hex(&sneaky).is_err());
    }

    // A throwaway directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir =
                std::env::temp_dir().join(format!("kiss_chat_test_{}_{nanos}", std::process::id()));
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
    fn key_is_created_then_reloaded_unchanged() {
        let dir = TempDir::new();
        let first = load_or_create_key(&dir.0, "k.key", || [0x11; 32]).unwrap();
        assert_eq!(
            first, [0x11; 32],
            "first call returns the freshly generated key"
        );

        // Second call must load from disk and ignore the (different) generator.
        let second = load_or_create_key(&dir.0, "k.key", || [0x22; 32]).unwrap();
        assert_eq!(second, first, "reload must return the persisted key");
    }

    #[test]
    fn a_corrupt_key_file_is_an_error_not_a_silent_reset() {
        let dir = TempDir::new();
        std::fs::write(dir.0.join("k.key"), "not hex").unwrap();
        assert!(load_or_create_key(&dir.0, "k.key", || [0; 32]).is_err());
    }

    #[test]
    fn display_name_is_unset_when_absent() {
        let dir = TempDir::new();
        assert_eq!(load_display_name_in(&dir.0).unwrap(), None);
    }

    #[test]
    fn display_name_round_trips_and_clears() {
        let dir = TempDir::new();
        save_display_name_in(&dir.0, Some("Alice Smith")).unwrap();
        assert_eq!(
            load_display_name_in(&dir.0).unwrap().as_deref(),
            Some("Alice Smith")
        );

        // Clearing removes the file, so the name reads back as unset.
        save_display_name_in(&dir.0, None).unwrap();
        assert_eq!(load_display_name_in(&dir.0).unwrap(), None);
        // Clearing an already-absent name is not an error.
        assert!(save_display_name_in(&dir.0, None).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn persisted_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        load_or_create_key(&dir.0, "k.key", || [0x11; 32]).unwrap();
        let mode = std::fs::metadata(dir.0.join("k.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "secret key must be readable only by its owner"
        );
    }
}
