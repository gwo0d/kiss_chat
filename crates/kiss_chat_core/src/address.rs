//! Human-friendly encodings of an address, and a forgiving parser for all of them.
//!
//! An address is a full 256-bit public key — the iroh [`EndpointId`] peers dial —
//! so no encoding can make it shorter, only easier to move between people and
//! devices. Three interchangeable forms are supported, each suited to a different
//! channel:
//!
//!   - **hex** — the canonical [`EndpointId`] form: 64 hex characters. Compact,
//!     stable, and what every kiss_chat version understands; contacts and the
//!     headless protocol keep using it internally.
//!   - **bech32m** ([`to_bech32`]) — `kiss1…`, ~63 characters. Self-identifying,
//!     built from a charset chosen to avoid look-alike characters, and carrying a
//!     checksum that catches up to four mistyped characters. The best form to
//!     copy/paste or put in a QR code.
//!   - **words** ([`to_words`]) — 24 words from the embedded BIP39 wordlist
//!     (32 bytes of key + an 8-bit SHA-256 checksum = 264 bits = 24 × 11). The
//!     best form to read over a phone call or write on paper: each word carries
//!     redundancy, and the checksum catches a wrong, missing, or swapped word.
//!
//! The word form encodes the *address* and is unrelated to the session **safety
//! words** ([`crate::crypto::Session::safety_number`]): an address is public and
//! freely shareable, while safety words exist only to be compared out-of-band
//! when verifying a peer. They merely share the wordlist.
//!
//! [`parse`] accepts any of the three forms and is deliberately lenient about
//! *transport damage*: terminals wrap long strings, and copying out of a bordered
//! TUI can pick up newlines, indentation, or box-drawing characters. Everything
//! that isn't a letter or digit is treated as a separator and discarded before
//! decoding — the checksums are what guarantee the result is the address that was
//! meant, not the stripping.

use anyhow::{Context, Result, bail, ensure};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use iroh::EndpointId;
use sha2::{Digest, Sha256};

use crate::wordlist;

/// Words in the word form of an address: (256 entropy + 8 checksum) / 11.
pub const ADDRESS_WORDS: usize = 24;

/// The human-readable prefix of the bech32m form: addresses read `kiss1…`.
const HRP: &str = "kiss";

/// Render an address as its `kiss1…` bech32m form (~63 characters, lowercase).
///
/// For a QR code, uppercase the result: the bech32 charset then fits QR
/// alphanumeric mode, which yields a visibly smaller code.
#[must_use]
pub fn to_bech32(id: &EndpointId) -> String {
    let hrp = Hrp::parse(HRP).expect("the kiss hrp is valid");
    bech32::encode::<Bech32m>(hrp, id.as_bytes()).expect("32 bytes fit in one bech32m string")
}

/// Render an address as 24 space-separated words from the embedded wordlist.
#[must_use]
pub fn to_words(id: &EndpointId) -> String {
    // BIP39: entropy ‖ checksum, where the checksum is the first 8 bits of
    // SHA-256(entropy). 32 + 1 bytes = 264 bits = exactly 24 × 11-bit indices.
    let mut data = [0u8; 33];
    data[..32].copy_from_slice(id.as_bytes());
    data[32] = Sha256::digest(id.as_bytes())[0];

    let words = wordlist::words();
    (0..ADDRESS_WORDS)
        .map(|i| words[wordlist::take_bits(&data, i * wordlist::WORD_BITS, wordlist::WORD_BITS)])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse an address in any supported form — hex, `kiss1…` bech32m, or 24 words —
/// tolerating the damage a terminal does to it along the way.
///
/// # Errors
///
/// Fails with a form-specific, human-readable message: a bad checksum, a word
/// that isn't on the wordlist, a wrong word count, or an input that matches no
/// form at all.
pub fn parse(input: &str) -> Result<EndpointId> {
    // Anything that isn't a letter or digit — spaces, newlines, hyphens, TUI
    // border glyphs — is separator noise from wrapping or copying, not signal.
    let tokens: Vec<String> = input
        .to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();
    ensure!(!tokens.is_empty(), "empty address");
    let joined = tokens.concat();

    if joined.starts_with("kiss1") {
        return decode_bech32(&joined);
    }
    // Several all-letter tokens can only be meant as address words; anything with
    // digits in it is a (possibly wrapped, hence re-joined) hex or z-base-32 id.
    if tokens.len() > 1
        && tokens
            .iter()
            .all(|t| t.bytes().all(|b| b.is_ascii_alphabetic()))
    {
        return decode_words(&tokens);
    }
    joined.parse::<EndpointId>().ok().with_context(|| {
        format!("unrecognised address (expected kiss1…, 64 hex characters, or {ADDRESS_WORDS} words): {input:?}")
    })
}

/// Decode the data part of a normalised (lowercase, separator-free) `kiss1…` string.
fn decode_bech32(s: &str) -> Result<EndpointId> {
    let checked = CheckedHrpstring::new::<Bech32m>(s)
        .map_err(|err| anyhow::anyhow!("invalid kiss1… address ({err}) — re-check it for typos"))?;
    ensure!(
        checked.hrp().as_str() == HRP,
        "not a kiss_chat address (prefix {:?})",
        checked.hrp().as_str()
    );
    let bytes: Vec<u8> = checked.byte_iter().collect();
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("kiss1… address has the wrong length"))?;
    EndpointId::from_bytes(&bytes).context("not a valid address")
}

/// Decode 24 normalised (lowercase) word tokens back into an address.
fn decode_words(tokens: &[String]) -> Result<EndpointId> {
    ensure!(
        tokens.len() == ADDRESS_WORDS,
        "an address is {ADDRESS_WORDS} words — got {}",
        tokens.len()
    );
    let mut data = [0u8; 33];
    for (i, word) in tokens.iter().enumerate() {
        let Some(index) = wordlist::index_of(word) else {
            bail!("word {} ({word:?}) is not on the address wordlist", i + 1);
        };
        wordlist::put_bits(
            &mut data,
            i * wordlist::WORD_BITS,
            wordlist::WORD_BITS,
            index,
        );
    }
    let entropy: [u8; 32] = data[..32].try_into().expect("33-byte buffer holds 32");
    ensure!(
        data[32] == Sha256::digest(entropy)[0],
        "the address words don't check out — a word is wrong, missing, or out of order"
    );
    EndpointId::from_bytes(&entropy).context("not a valid address")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn some_id() -> EndpointId {
        // A fixed, valid endpoint id so failures reproduce byte-for-byte.
        "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6"
            .parse()
            .unwrap()
    }

    #[test]
    fn bech32_round_trips_and_is_self_identifying() {
        let id = some_id();
        let encoded = to_bech32(&id);
        assert!(encoded.starts_with("kiss1"));
        assert_eq!(parse(&encoded).unwrap(), id);
    }

    #[test]
    fn words_round_trip() {
        let id = some_id();
        let words = to_words(&id);
        assert_eq!(words.split(' ').count(), ADDRESS_WORDS);
        assert!(
            words.split(' ').all(|w| wordlist::index_of(w).is_some()),
            "every word must come from the wordlist"
        );
        assert_eq!(parse(&words).unwrap(), id);
    }

    #[test]
    fn hex_still_parses() {
        let id = some_id();
        assert_eq!(parse(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn encodings_match_independent_vectors() {
        // Both forms of `some_id`, computed by a from-scratch Python
        // implementation of bech32m (BIP-350) and the BIP39 mnemonic scheme.
        // Round-trip tests can't catch an encode/decode pair that agrees on the
        // wrong format; these vectors pin the formats themselves — a mismatch
        // here would break addresses shared between kiss_chat versions.
        let id = some_id();
        assert_eq!(
            to_bech32(&id),
            "kiss14ev0lzpnysdvstt07as3q3hdv76swtg593vg6qrra9pdnf64q2mqgsggj0"
        );
        assert_eq!(
            to_words(&id),
            "purity side tilt green double goat remember year genre lion robust sorry \
             expire notable expose mention minimum adapt where mad omit pride approve shrug"
        );
    }

    #[test]
    fn parse_survives_terminal_damage() {
        let id = some_id();

        // Hex wrapped by a narrow terminal, complete with a border glyph and the
        // continuation indent — the snaggle this module exists to absorb.
        let hex = id.to_string();
        let (a, b) = hex.split_at(40);
        assert_eq!(parse(&format!("  {a} │\n  {b}\n")).unwrap(), id);

        // Bech32 pasted with grouping spaces, a newline, and mixed case (QR forms
        // are uppercase).
        let bech = to_bech32(&id);
        let grouped: String = bech
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                let sep = (i > 0 && i % 4 == 0).then_some(' ');
                sep.into_iter().chain(std::iter::once(c))
            })
            .collect();
        assert_eq!(parse(&grouped).unwrap(), id);
        assert_eq!(parse(&bech.to_uppercase()).unwrap(), id);

        // Words spread over several lines with uneven whitespace.
        let words = to_words(&id).replace(' ', "\n  ");
        assert_eq!(parse(&words).unwrap(), id);
    }

    #[test]
    fn a_mistyped_bech32_character_is_caught() {
        let mut s = to_bech32(&some_id());
        // Flip one data character to a different charset member.
        let last = s.pop().unwrap();
        s.push(if last == 'q' { 'p' } else { 'q' });
        let err = parse(&s).unwrap_err().to_string();
        assert!(err.contains("kiss1"), "unhelpful error: {err}");
    }

    #[test]
    fn a_swapped_word_is_caught_by_the_checksum() {
        let words = to_words(&some_id());
        let mut tokens: Vec<&str> = words.split(' ').collect();
        // Find two differing neighbours and swap them (identical neighbours would
        // make the swap a no-op).
        let i = (0..tokens.len() - 1)
            .find(|&i| tokens[i] != tokens[i + 1])
            .expect("24 words can't all be identical");
        tokens.swap(i, i + 1);
        let err = parse(&tokens.join(" ")).unwrap_err().to_string();
        assert!(err.contains("check"), "unhelpful error: {err}");
    }

    #[test]
    fn a_wrong_word_is_named_with_its_position() {
        let words = to_words(&some_id());
        let mut tokens: Vec<String> = words.split(' ').map(str::to_string).collect();
        tokens[6] = "buliding".into(); // not on the list
        let err = parse(&tokens.join(" ")).unwrap_err().to_string();
        assert!(
            err.contains("word 7") && err.contains("buliding"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn a_wrong_word_count_is_reported_as_such() {
        let words = to_words(&some_id());
        let short: Vec<&str> = words.split(' ').take(23).collect();
        let err = parse(&short.join(" ")).unwrap_err().to_string();
        assert!(
            err.contains("24 words") && err.contains("23"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn garbage_gets_a_format_overview() {
        let err = parse("n0t4naddr3ss").unwrap_err().to_string();
        assert!(
            err.contains("kiss1") && err.contains("hex"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn an_empty_input_is_rejected() {
        assert!(parse("").is_err());
        assert!(parse(" ─│ \n").is_err());
    }
}
