//! The tiny in-band protocol carried inside each encrypted frame.
//!
//! Every sealed frame begins with a one-byte tag so the peers can tell a chat
//! message apart from a control signal. The control signals are:
//!
//!   - `Bye`, sent when a peer leaves so the other side shows a clean notice
//!     instead of a raw connection error; and
//!   - `Name`, an optional display name a peer chooses to share *after* the
//!     channel has been accepted. It travels in the same sealed frames as chat
//!     text, so it gets the same end-to-end encryption and authentication. An
//!     empty body means "I've cleared my display name".
//!
//! Display names are purely cosmetic and self-asserted: the trust anchor is the
//! handshake's safety number, never the name. So we sanitise received names
//! (strip control characters, cap the length) before showing them, and never
//! let them influence identity verification.

/// Longest display name we keep, in characters. Anything longer is truncated.
pub const MAX_NAME_CHARS: usize = 32;

/// A message the local user sends to the peer.
pub enum Outgoing {
    /// A chat message.
    Text(String),
    /// A "leaving now" signal.
    Bye,
    /// Announce (or, with `None`, clear) our display name.
    Name(Option<String>),
}

/// A message decoded from a frame received from the peer.
pub enum Incoming {
    Text(String),
    Bye,
    /// The peer's display name (`None` if they cleared it or it sanitised away).
    Name(Option<String>),
    Malformed,
}

const TAG_TEXT: u8 = 0;
const TAG_BYE: u8 = 1;
const TAG_NAME: u8 = 2;

/// Encode an outgoing message into the plaintext that will be sealed.
pub fn encode(message: &Outgoing) -> Vec<u8> {
    match message {
        Outgoing::Text(text) => {
            let mut buf = Vec::with_capacity(1 + text.len());
            buf.push(TAG_TEXT);
            buf.extend_from_slice(text.as_bytes());
            buf
        }
        Outgoing::Bye => vec![TAG_BYE],
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
pub fn decode(plaintext: &[u8]) -> Incoming {
    match plaintext.split_first() {
        Some((&TAG_TEXT, body)) => Incoming::Text(String::from_utf8_lossy(body).into_owned()),
        Some((&TAG_BYE, _)) => Incoming::Bye,
        Some((&TAG_NAME, body)) => Incoming::Name(sanitize_name(&String::from_utf8_lossy(body))),
        _ => Incoming::Malformed,
    }
}

/// Normalise a display name for storage, sending, and display.
///
/// Strips control characters (so a peer can't smuggle newlines or escape
/// sequences into our terminal), trims surrounding whitespace, and caps the
/// length. Returns `None` when nothing usable is left — the caller treats that
/// as "no display name".
pub fn sanitize_name(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(MAX_NAME_CHARS).collect())
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
}
