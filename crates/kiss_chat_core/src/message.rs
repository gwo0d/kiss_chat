//! The tiny in-band protocol carried inside each encrypted frame.
//!
//! Every sealed frame begins with a one-byte tag so the peers can tell a chat
//! message apart from a control signal. The control signals are:
//!
//!   - `Accepted`, sent the moment a peer accepts the channel. Because the two
//!     users accept at different times, chat is held until *both* have — see
//!     "Mutual acceptance" below;
//!   - `Bye`, sent when a peer leaves so the other side shows a clean notice
//!     instead of a raw connection error; and
//!   - `Name`, an optional display name a peer chooses to share *after* the
//!     channel has been accepted. It travels in the same sealed frames as chat
//!     text, so it gets the same end-to-end encryption and authentication. An
//!     empty body means "I've cleared my display name".
//!
//! # Mutual acceptance
//!
//! Accepting a channel is a local act — one user comparing safety words and
//! saying yes — but the *peer* needs to know it happened, for two reasons. It
//! tells them the session is genuinely open at both ends, and it stops the
//! window in which one side has accepted and starts talking while the other is
//! still deciding: those messages would otherwise have to be discarded, since a
//! frontend must never paint a peer's chat text onto the verification screen.
//!
//! So the rule is: send [`Outgoing::Accepted`] on accepting, and treat chat as
//! open only once you have accepted *and* received the peer's [`Incoming::Accepted`].
//! A `Text` frame arriving before that is a protocol violation, and the receiver
//! ends the session rather than showing it. Frames all travel on one ordered QUIC
//! stream, so a well-behaved peer's `Accepted` always precedes their first `Text`.
//!
//! # Unknown frames
//!
//! A tag this version doesn't recognise decodes as [`Incoming::Unknown`], which
//! readers **ignore**. Only a genuinely undecodable frame (an empty one) is
//! [`Incoming::Malformed`] and fatal. That distinction is what lets a later
//! version introduce a new frame type without a coordinated break: old peers skip
//! what they don't understand. Ignoring is safe because frames arrive only
//! through the authenticated, replay-protected session — an unknown tag comes
//! from the peer we verified, not from the network.
//!
//! Display names are purely cosmetic and self-asserted: the trust anchor is the
//! handshake's safety number, never the name. So we sanitise received names
//! (strip control *and* invisible/bidirectional formatting characters, cap the
//! length) before showing them, and never let them influence identity
//! verification. Chat text gets the same control-character stripping so a peer
//! can't inject terminal escape sequences.

/// Longest display name we keep, in characters. Anything longer is truncated.
pub const MAX_NAME_CHARS: usize = 32;

/// Longest chat message we send, in characters. The UI refuses longer input with a
/// notice rather than sending it, keeping every sealed frame well within [`crate::proto`]'s
/// 64 KiB cap even after UTF-8 encoding and the AEAD tag — so an oversized paste can
/// never make the *peer's* reader reject the frame and tear the session down.
pub const MAX_MESSAGE_CHARS: usize = 4096;

/// A message the local user sends to the peer.
pub enum Outgoing {
    /// A chat message.
    Text(String),
    /// A "leaving now" signal.
    Bye,
    /// Announce (or, with `None`, clear) our display name.
    Name(Option<String>),
    /// "I have accepted this channel" — sent once, on accepting. See the module
    /// docs on mutual acceptance.
    Accepted,
}

/// A message decoded from a frame received from the peer.
pub enum Incoming {
    Text(String),
    Bye,
    /// The peer's display name (`None` if they cleared it or it sanitised away).
    Name(Option<String>),
    /// The peer accepted the channel. Chat is open once we have accepted too.
    Accepted,
    /// A frame tagged with something this version doesn't know. Readers ignore it,
    /// which is what keeps later additions from breaking older peers.
    Unknown,
    /// A frame that could not be decoded at all. Fatal: the session ends.
    Malformed,
}

const TAG_TEXT: u8 = 0;
const TAG_BYE: u8 = 1;
const TAG_NAME: u8 = 2;
const TAG_ACCEPTED: u8 = 3;

/// Encode an outgoing message into the plaintext that will be sealed.
#[must_use]
pub fn encode(message: &Outgoing) -> Vec<u8> {
    match message {
        Outgoing::Text(text) => {
            let mut buf = Vec::with_capacity(1 + text.len());
            buf.push(TAG_TEXT);
            buf.extend_from_slice(text.as_bytes());
            buf
        }
        Outgoing::Bye => vec![TAG_BYE],
        Outgoing::Accepted => vec![TAG_ACCEPTED],
        Outgoing::Name(name) => {
            let name = name.as_deref().unwrap_or("");
            let mut buf = Vec::with_capacity(1 + name.len());
            buf.push(TAG_NAME);
            buf.extend_from_slice(name.as_bytes());
            buf
        }
    }
}

/// Decode a decrypted plaintext frame received from the peer.
///
/// An unrecognised tag yields [`Incoming::Unknown`] (to be ignored) rather than
/// [`Incoming::Malformed`] (which is fatal), so that a peer running a later
/// version can send frames we don't know about without ending the session.
#[must_use]
pub fn decode(plaintext: &[u8]) -> Incoming {
    match plaintext.split_first() {
        Some((&TAG_TEXT, body)) => Incoming::Text(sanitize_text(&String::from_utf8_lossy(body))),
        Some((&TAG_BYE, _)) => Incoming::Bye,
        Some((&TAG_NAME, body)) => Incoming::Name(sanitize_name(&String::from_utf8_lossy(body))),
        Some((&TAG_ACCEPTED, _)) => Incoming::Accepted,
        // A tag from a future version: skippable, not fatal.
        Some(_) => Incoming::Unknown,
        // No tag byte at all — nothing to interpret.
        None => Incoming::Malformed,
    }
}

/// Invisible and bidirectional formatting characters used in "Trojan Source"-style
/// spoofing. These are *not* caught by [`char::is_control`], so we list them
/// explicitly; stripping them stops a peer from reordering or hiding text in our
/// terminal via a display name.
fn is_bidi_or_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'                 // soft hyphen
        | '\u{061C}'               // Arabic letter mark
        | '\u{200B}'..='\u{200F}'  // zero-width space, (non-)joiners, LRM/RLM
        | '\u{202A}'..='\u{202E}'  // bidi embeddings & overrides
        | '\u{2060}'..='\u{2064}'  // word joiner, invisible operators
        | '\u{2066}'..='\u{2069}'  // bidi isolates
        | '\u{FEFF}'               // zero-width no-break space / BOM
        | '\u{FFF9}'..='\u{FFFB}'  // interlinear annotation marks
    )
}

/// Normalise a display name for storage, sending, and display.
///
/// Strips control characters and the invisible/bidirectional formatting
/// characters above (so a peer can't smuggle newlines, escape sequences, or a
/// right-to-left override into our terminal), trims surrounding whitespace, and
/// caps the length. Returns `None` when nothing usable is left — the caller
/// treats that as "no display name".
#[must_use]
pub fn sanitize_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|&c| !c.is_control() && !is_bidi_or_invisible(c))
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(MAX_NAME_CHARS).collect())
}

/// Strip terminal control characters from peer-supplied chat text so a peer can't
/// inject ANSI escape sequences (screen clears, cursor moves, title rewrites) into
/// our terminal. Printable content — emoji, non-Latin scripts — is preserved, so
/// unlike names we leave bidirectional marks alone (ratatui renders per-cell, and
/// stripping them would corrupt legitimate right-to-left messages).
fn sanitize_text(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips() {
        match decode(&encode(&Outgoing::Text("hello world".into()))) {
            Incoming::Text(text) => assert_eq!(text, "hello world"),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn bye_round_trips() {
        assert!(matches!(decode(&encode(&Outgoing::Bye)), Incoming::Bye));
    }

    #[test]
    fn empty_frame_is_malformed() {
        assert!(matches!(decode(&[]), Incoming::Malformed));
    }

    #[test]
    fn accepted_round_trips() {
        assert!(matches!(
            decode(&encode(&Outgoing::Accepted)),
            Incoming::Accepted
        ));
    }

    #[test]
    fn an_unknown_tag_is_skippable_not_fatal() {
        // A frame from a later version must decode as Unknown (which readers
        // ignore), never as Malformed (which ends the session) — that is what
        // lets new frame types be added without a coordinated break.
        for tag in [4u8, 5, 42, 255] {
            assert!(
                matches!(decode(&[tag]), Incoming::Unknown),
                "tag {tag} should be ignorable"
            );
            // A body the future version attached comes along for the ride.
            assert!(matches!(decode(&[tag, 1, 2, 3]), Incoming::Unknown));
        }
    }

    #[test]
    fn accepted_is_distinct_from_the_other_control_frames() {
        // The tags must not collide: each control frame decodes as itself.
        assert!(matches!(decode(&encode(&Outgoing::Bye)), Incoming::Bye));
        assert!(matches!(
            decode(&encode(&Outgoing::Accepted)),
            Incoming::Accepted
        ));
        assert!(matches!(
            decode(&encode(&Outgoing::Name(None))),
            Incoming::Name(None)
        ));
    }

    #[test]
    fn an_empty_text_message_is_not_mistaken_for_bye() {
        // The tag byte keeps an empty chat line distinct from the Bye control frame.
        assert!(matches!(
            decode(&encode(&Outgoing::Text(String::new()))),
            Incoming::Text(_)
        ));
    }

    #[test]
    fn name_round_trips() {
        match decode(&encode(&Outgoing::Name(Some("Alice Smith".into())))) {
            Incoming::Name(Some(name)) => assert_eq!(name, "Alice Smith"),
            _ => panic!("expected a name"),
        }
    }

    #[test]
    fn a_cleared_name_round_trips_as_none() {
        assert!(matches!(
            decode(&encode(&Outgoing::Name(None))),
            Incoming::Name(None)
        ));
    }

    #[test]
    fn sanitize_strips_control_characters() {
        assert_eq!(sanitize_name("Al\nice\t").as_deref(), Some("Alice"));
    }

    #[test]
    fn sanitize_rejects_whitespace_only_names() {
        assert_eq!(sanitize_name("   "), None);
        assert_eq!(sanitize_name(""), None);
    }

    #[test]
    fn sanitize_caps_the_length() {
        let long = "x".repeat(MAX_NAME_CHARS + 10);
        assert_eq!(
            sanitize_name(&long).unwrap().chars().count(),
            MAX_NAME_CHARS
        );
    }

    #[test]
    fn a_received_name_is_sanitized() {
        // A peer that stuffs a newline into the wire form still can't reach the UI.
        match decode(&encode(&Outgoing::Name(Some("bad\nname".into())))) {
            Incoming::Name(Some(name)) => assert_eq!(name, "badname"),
            _ => panic!("expected a sanitised name"),
        }
    }

    #[test]
    fn sanitize_strips_bidi_and_zero_width() {
        // U+202E (RLO) could visually reverse the label; U+200B is invisible.
        assert_eq!(
            sanitize_name("Al\u{202E}i\u{200B}ce").as_deref(),
            Some("Alice")
        );
    }

    #[test]
    fn a_name_that_is_only_formatting_chars_sanitises_away() {
        assert_eq!(sanitize_name("\u{202E}\u{200B}\u{FEFF}"), None);
    }

    #[test]
    fn text_strips_escape_sequences_but_keeps_printable() {
        // A peer's chat line carrying an ANSI escape must not reach the terminal.
        match decode(&encode(&Outgoing::Text("hi\u{1b}[2Kthere".into()))) {
            Incoming::Text(text) => {
                assert!(!text.contains('\u{1b}'), "escape byte must be stripped");
                assert_eq!(text, "hi[2Kthere");
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn text_preserves_emoji_and_non_latin() {
        match decode(&encode(&Outgoing::Text("héllo 🌍 مرحبا".into()))) {
            Incoming::Text(text) => assert_eq!(text, "héllo 🌍 مرحبا"),
            _ => panic!("expected text"),
        }
    }
}
