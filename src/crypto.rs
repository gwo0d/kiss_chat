//! End-to-end encryption for kiss_chat.
//!
//! The design is deliberately small. iroh already hands us an authenticated,
//! TLS-1.3-encrypted QUIC stream, so all we add here is a *quantum-resistant*
//! session key on top of it:
//!
//! 1. A two-message **hybrid handshake** combining classical X25519 ECDH with
//!    post-quantum ML-KEM-768. The session key survives even if *one* of the two
//!    primitives is later broken — this is the same construction shipped by
//!    Chrome/Cloudflare/AWS in TLS.
//! 2. Both secrets are folded into HKDF-SHA256, salted with the full handshake
//!    transcript and bound to both peers' iroh identities, so a man-in-the-middle
//!    would have to break the transport authentication *and* the KEM.
//! 3. Messages are sealed with ChaCha20-Poly1305 using deterministic, per-direction
//!    nonce counters (QUIC delivers the stream reliably and in order, so both sides
//!    keep their counters in lockstep and no nonce is ever reused).

use anyhow::{Result, ensure};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{
    Ciphertext, DecapsulationKey768, EncapsulationKey768, Kem, MlKem768,
    kem::Key as KemKey,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Length of an X25519 public key / shared secret, in bytes.
const X25519_LEN: usize = 32;

/// HKDF `info` domain-separation prefix. Bumped whenever the wire format changes.
const HKDF_INFO_PREFIX: &[u8] = b"kiss-chat/0 e2e session";

/// Nonce direction tag for initiator -> responder traffic.
const DIR_I2R: [u8; 4] = [0, 0, 0, 1];
/// Nonce direction tag for responder -> initiator traffic.
const DIR_R2I: [u8; 4] = [0, 0, 0, 2];

/// Which side of the handshake we are. The dialer is always the initiator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// State the initiator must hold between sending msg1 and receiving msg2.
pub struct Initiator {
    dk: DecapsulationKey768,
    x_secret: StaticSecret,
    msg1: Vec<u8>,
}

/// Build the initiator's first handshake message.
///
/// Returns the in-flight [`Initiator`] state and `msg1 = ek_pq || x25519_pub`.
pub fn initiator_start() -> Initiator {
    let (dk, ek) = MlKem768::generate_keypair();
    let x_secret = StaticSecret::from(rand::random::<[u8; 32]>());
    let x_pub = PublicKey::from(&x_secret);

    let mut msg1 = ek.to_bytes().to_vec();
    msg1.extend_from_slice(x_pub.as_bytes());

    Initiator {
        dk,
        x_secret,
        msg1,
    }
}

impl Initiator {
    /// The bytes to send to the responder.
    pub fn msg1(&self) -> &[u8] {
        &self.msg1
    }

    /// Consume msg2 from the responder and derive the [`Session`].
    ///
    /// `initiator_id` is our own iroh EndpointId, `responder_id` the peer's.
    pub fn finish(
        self,
        msg2: &[u8],
        initiator_id: &[u8; 32],
        responder_id: &[u8; 32],
    ) -> Result<Session> {
        let (ct_bytes, their_x_pub) = split_tail(msg2)?;
        let ct = Ciphertext::<MlKem768>::try_from(ct_bytes)
            .map_err(|_| anyhow::anyhow!("malformed ML-KEM ciphertext"))?;
        let ss_kem = self.dk.decapsulate(&ct);

        let ss_dh = self
            .x_secret
            .diffie_hellman(&PublicKey::from(their_x_pub));

        let key = derive_key(
            ss_kem.as_slice(),
            ss_dh.as_bytes(),
            &self.msg1,
            msg2,
            initiator_id,
            responder_id,
        );
        Ok(Session::new(key, Role::Initiator))
    }
}

/// Handle the initiator's msg1 and produce our reply plus the [`Session`].
///
/// Returns `(session, msg2)` where `msg2 = kem_ciphertext || x25519_pub`.
pub fn responder_respond(
    msg1: &[u8],
    initiator_id: &[u8; 32],
    responder_id: &[u8; 32],
) -> Result<(Session, Vec<u8>)> {
    let (ek_bytes, their_x_pub) = split_tail(msg1)?;

    let ek_key = KemKey::<EncapsulationKey768>::try_from(ek_bytes)
        .map_err(|_| anyhow::anyhow!("malformed ML-KEM encapsulation key"))?;
    let ek = EncapsulationKey768::new(&ek_key)
        .map_err(|_| anyhow::anyhow!("invalid ML-KEM encapsulation key"))?;
    let (ct, ss_kem) = ek.encapsulate();

    let x_secret = StaticSecret::from(rand::random::<[u8; 32]>());
    let x_pub = PublicKey::from(&x_secret);
    let ss_dh = x_secret.diffie_hellman(&PublicKey::from(their_x_pub));

    let mut msg2 = ct.as_slice().to_vec();
    msg2.extend_from_slice(x_pub.as_bytes());

    let key = derive_key(
        ss_kem.as_slice(),
        ss_dh.as_bytes(),
        msg1,
        &msg2,
        initiator_id,
        responder_id,
    );
    Ok((Session::new(key, Role::Responder), msg2))
}

/// Split a handshake message into `(head, trailing_32_byte_x25519_pubkey)`.
fn split_tail(msg: &[u8]) -> Result<(&[u8], [u8; 32])> {
    ensure!(
        msg.len() > X25519_LEN,
        "handshake message too short: {} bytes",
        msg.len()
    );
    let (head, tail) = msg.split_at(msg.len() - X25519_LEN);
    let mut pk = [0u8; X25519_LEN];
    pk.copy_from_slice(tail);
    Ok((head, pk))
}

/// Fold both shared secrets into a single 32-byte session key.
///
/// `ikm = ss_kem || ss_dh` (hybrid), `salt = SHA256(msg1 || msg2)` (transcript
/// binding), and `info` binds the key to both peers' identities.
fn derive_key(
    ss_kem: &[u8],
    ss_dh: &[u8; 32],
    msg1: &[u8],
    msg2: &[u8],
    initiator_id: &[u8; 32],
    responder_id: &[u8; 32],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(ss_kem.len() + X25519_LEN);
    ikm.extend_from_slice(ss_kem);
    ikm.extend_from_slice(ss_dh);

    let salt = Sha256::new().chain_update(msg1).chain_update(msg2).finalize();

    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 64);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(initiator_id);
    info.extend_from_slice(responder_id);

    let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("HKDF expand of 32 bytes never fails");
    key
}

/// An established, quantum-resistant session over which messages are sealed.
///
/// Splits into a [`Sealer`] (outgoing) and [`Opener`] (incoming) so the read and
/// write halves can run on independent tasks without sharing mutable state.
pub struct Session {
    key: [u8; 32],
    role: Role,
}

impl Session {
    fn new(key: [u8; 32], role: Role) -> Self {
        Self { key, role }
    }

    /// A short human-comparable fingerprint of the session key, for optional
    /// out-of-band verification against a MITM. Both peers see the same value.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.key);
        digest[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Split into directional halves. The direction tags depend on our role so
    /// the two peers never collide on a nonce.
    pub fn split(self) -> (Sealer, Opener) {
        let (send_dir, recv_dir) = match self.role {
            Role::Initiator => (DIR_I2R, DIR_R2I),
            Role::Responder => (DIR_R2I, DIR_I2R),
        };
        let cipher = ChaCha20Poly1305::new(&Key::from(self.key));
        (
            Sealer {
                cipher: cipher.clone(),
                dir: send_dir,
                counter: 0,
            },
            Opener {
                cipher,
                dir: recv_dir,
                counter: 0,
            },
        )
    }
}

/// Build the 96-bit nonce for a given direction and counter.
fn make_nonce(dir: [u8; 4], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&dir);
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Encrypts outgoing messages.
pub struct Sealer {
    cipher: ChaCha20Poly1305,
    dir: [u8; 4],
    counter: u64,
}

impl Sealer {
    /// Encrypt `plaintext`, advancing the nonce counter.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = make_nonce(self.dir, self.counter);
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("send nonce counter exhausted"))?;
        self.cipher
            .encrypt(&Nonce::from(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("encryption failed"))
    }
}

/// Decrypts incoming messages.
pub struct Opener {
    cipher: ChaCha20Poly1305,
    dir: [u8; 4],
    counter: u64,
}

impl Opener {
    /// Decrypt and authenticate `ciphertext`, advancing the nonce counter.
    ///
    /// Because nonces are deterministic, a dropped/reordered/forged frame makes
    /// authentication fail and the session is torn down by the caller.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = make_nonce(self.dir, self.counter);
        let plaintext = self
            .cipher
            .decrypt(&Nonce::from(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("decryption/authentication failed"))?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("recv nonce counter exhausted"))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Run a full handshake in-process and return both established sessions.
    fn handshake() -> (Session, Session) {
        let id_a = [0xAAu8; 32]; // initiator id
        let id_b = [0xBBu8; 32]; // responder id

        let initiator = initiator_start();
        let (responder_session, msg2) =
            responder_respond(initiator.msg1(), &id_a, &id_b).expect("responder");
        let initiator_session = initiator.finish(&msg2, &id_a, &id_b).expect("initiator");
        (initiator_session, responder_session)
    }

    #[test]
    fn both_sides_derive_the_same_key() {
        let (a, b) = handshake();
        assert_eq!(a.key, b.key, "session keys must match");
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn message_round_trips_in_both_directions() {
        let (a, b) = handshake();
        let (mut a_seal, mut a_open) = a.split();
        let (mut b_seal, mut b_open) = b.split();

        // initiator -> responder
        let ct = a_seal.seal(b"hello from A").unwrap();
        assert_eq!(b_open.open(&ct).unwrap(), b"hello from A");

        // responder -> initiator
        let ct = b_seal.seal(b"hi back from B").unwrap();
        assert_eq!(a_open.open(&ct).unwrap(), b"hi back from B");
    }

    #[test]
    fn counters_advance_so_repeated_plaintext_differs() {
        let (a, _b) = handshake();
        let (mut seal, _open) = a.split();
        let c1 = seal.seal(b"same").unwrap();
        let c2 = seal.seal(b"same").unwrap();
        assert_ne!(c1, c2, "nonce counter must make ciphertexts differ");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (a, b) = handshake();
        let (mut a_seal, _) = a.split();
        let (_, mut b_open) = b.split();

        let mut ct = a_seal.seal(b"trust me").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01; // flip a bit in the tag
        assert!(b_open.open(&ct).is_err(), "AEAD must reject tampering");
    }

    #[test]
    fn mismatched_identities_break_the_handshake() {
        // If the two sides disagree about who they're talking to (e.g. a MITM
        // splicing identities), the derived keys diverge and decryption fails.
        let initiator = initiator_start();
        let (b, msg2) = responder_respond(initiator.msg1(), &[1u8; 32], &[2u8; 32]).unwrap();
        let a = initiator.finish(&msg2, &[1u8; 32], &[9u8; 32]).unwrap();
        assert_ne!(a.key, b.key);

        let (mut a_seal, _) = a.split();
        let (_, mut b_open) = b.split();
        let ct = a_seal.seal(b"secret").unwrap();
        assert!(b_open.open(&ct).is_err());
    }
}
