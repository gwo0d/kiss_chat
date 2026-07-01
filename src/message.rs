//! The tiny in-band protocol carried inside each encrypted frame.
//!
//! Every sealed frame begins with a one-byte tag so the peers can tell a chat
//! message apart from a control signal. Right now the only control signal is
//! `Bye`, sent when a peer leaves so the other side shows a clean notice instead
//! of a raw connection error.

/// A message the local user sends to the peer.
pub enum Outgoing {
    /// A chat message.
    Text(String),
    /// A "leaving now" signal.
    Bye,
}

/// A message decoded from a frame received from the peer.
pub enum Incoming {
    Text(String),
    Bye,
    Malformed,
}

const TAG_TEXT: u8 = 0;
const TAG_BYE: u8 = 1;

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
    }
}

/// Decode a decrypted plaintext frame received from the peer.
pub fn decode(plaintext: &[u8]) -> Incoming {
    match plaintext.split_first() {
        Some((&TAG_TEXT, body)) => Incoming::Text(String::from_utf8_lossy(body).into_owned()),
        Some((&TAG_BYE, _)) => Incoming::Bye,
        _ => Incoming::Malformed,
    }
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
}
