//! The embedded BIP39 English wordlist, shared by the two word encodings.
//!
//! Two features render 32-byte values as words drawn from this list: the
//! session **safety number** ([`crate::crypto`]) and the word form of an
//! **address** ([`crate::address`]). They must agree on the list — and ship it,
//! since decoding words back into an address needs the exact same entries — so
//! it lives here rather than in either module.

/// Bits one word encodes: the list has 2^11 = 2048 entries.
pub(crate) const WORD_BITS: usize = 11;

/// The BIP39 English wordlist (2048 = 2^11 words), embedded verbatim. It only has
/// to be consistent between two kiss_chat instances — we use it purely to render
/// bytes as memorable words and back — but a vetted, phonetically-distinct list
/// keeps spoken exchange reliable. SHA-256: 2f5eed53…3b24dbda.
const BIP39_ENGLISH: &str = include_str!("bip39-english.txt");

/// The wordlist, one entry per line, in file (= alphabetical) order.
pub(crate) fn words() -> Vec<&'static str> {
    let words: Vec<&str> = BIP39_ENGLISH.lines().collect();
    debug_assert_eq!(words.len(), 1 << WORD_BITS, "wordlist must be 2^11 entries");
    words
}

/// Position of `word` in the list, if it is on it. The list is alphabetically
/// sorted, so this is a binary search.
pub(crate) fn index_of(word: &str) -> Option<usize> {
    words().binary_search(&word).ok()
}

/// Read `n` bits (n ≤ 16) from `bytes` starting at bit `offset`, most-significant
/// bit first, as an integer. Used to slice a byte string into wordlist indices.
pub(crate) fn take_bits(bytes: &[u8], offset: usize, n: usize) -> usize {
    let mut value = 0usize;
    for i in 0..n {
        let bit = offset + i;
        let set = (bytes[bit / 8] >> (7 - (bit % 8))) & 1;
        value = (value << 1) | set as usize;
    }
    value
}

/// Write the low `n` bits (n ≤ 16) of `value` into `bytes` starting at bit
/// `offset`, most-significant bit first. The inverse of [`take_bits`].
pub(crate) fn put_bits(bytes: &mut [u8], offset: usize, n: usize, value: usize) {
    for i in 0..n {
        let bit = offset + i;
        let set = (value >> (n - 1 - i)) & 1;
        bytes[bit / 8] |= (set as u8) << (7 - (bit % 8));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_sorted_and_complete() {
        let words = words();
        assert_eq!(words.len(), 2048);
        assert!(
            words.windows(2).all(|w| w[0] < w[1]),
            "index_of relies on strict alphabetical order"
        );
    }

    #[test]
    fn index_of_finds_every_word_at_its_position() {
        for (i, word) in words().iter().enumerate() {
            assert_eq!(index_of(word), Some(i));
        }
        assert_eq!(index_of("not-a-word"), None);
    }

    #[test]
    fn put_bits_round_trips_through_take_bits() {
        let mut bytes = [0u8; 4];
        put_bits(&mut bytes, 3, 11, 0b101_1100_1101);
        assert_eq!(take_bits(&bytes, 3, 11), 0b101_1100_1101);
        // Neighbouring bits stay untouched.
        assert_eq!(take_bits(&bytes, 0, 3), 0);
        assert_eq!(take_bits(&bytes, 14, 10), 0);
    }
}
