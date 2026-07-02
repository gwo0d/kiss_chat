//! End-to-end encryption **and authentication** for kiss_chat.
//!
//! iroh already hands us an authenticated, TLS-1.3-encrypted QUIC stream. On top
//! of it we run a small handshake that is quantum-resistant end to end:
//!
//! 1. A **hybrid key exchange** combining classical X25519 ECDH with post-quantum
//!    ML-KEM-768. The session key survives even if *one* of the two primitives is
//!    later broken — the same construction shipped by Chrome/Cloudflare/AWS in TLS.
//! 2. **Post-quantum mutual authentication** with ML-DSA-65 (FIPS 204). Each peer
//!    holds a long-term ML-DSA identity key and signs the full handshake transcript,
//!    so a man-in-the-middle cannot impersonate a known identity even with a quantum
//!    computer. The signatures bind the ephemeral keys to the identity keys.
//! 3. Both shared secrets are folded into HKDF-SHA256, salted with the transcript
//!    (which includes both identity keys and both iroh EndpointIds), then messages
//!    are sealed with ChaCha20-Poly1305 using deterministic per-direction nonce
//!    counters (QUIC is reliable and in-order, so counters stay in lockstep and no
//!    nonce is ever reused).
//!
//! The **safety number** ([`Session::safety_number`]) is derived from both peers'
//! ML-DSA identity keys and is identical on both ends. Comparing it out-of-band
//! authenticates the identity keys themselves: under a MITM the two ends would see
//! different safety numbers. Verify it once and the signatures do the rest.
//!
//! Handshake wire format (the dialer is the *initiator*, the accepter the *responder*):
//!
//! ```text
//!   msg1  I -> R :  ml_kem_ek || x25519_pub || ml_dsa_vk_I
//!   msg2  R -> I :  ml_kem_ct || x25519_pub || ml_dsa_vk_R || sig_R(transcript)
//!   msg3  I -> R :  sig_I(transcript)
//! ```

use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use ml_dsa::{
    B32, EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey, Verifier,
    VerifyingKey,
};
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{
    Ciphertext, DecapsulationKey768, EncapsulationKey768, Kem, MlKem768, kem::Key as KemKey,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Length of an X25519 public key, in bytes.
const X25519_LEN: usize = 32;
/// Encoded length of an ML-KEM-768 encapsulation key (FIPS 203).
const MLKEM_EK_LEN: usize = 1184;
/// Encoded length of an ML-KEM-768 ciphertext (FIPS 203).
const MLKEM_CT_LEN: usize = 1088;
/// Encoded length of an ML-DSA-65 verifying (public) key (FIPS 204).
const MLDSA_VK_LEN: usize = 1952;
/// Encoded length of an ML-DSA-65 signature (FIPS 204).
const MLDSA_SIG_LEN: usize = 3309;

/// HKDF `info` domain-separation prefix. Bumped whenever the wire format changes.
const HKDF_INFO_PREFIX: &[u8] = b"kiss-chat/0 e2e session";
/// Domain separator for the transcript digest that both peers sign.
const SIG_CONTEXT: &[u8] = b"kiss-chat/0 handshake signature";
/// Domain separator for the safety-number derivation.
const SN_CONTEXT: &[u8] = b"kiss-chat/0 safety number";

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

/// A long-term ML-DSA-65 identity used to authenticate the handshake.
///
/// Built deterministically from a persistent 32-byte seed (see [`crate::identity`]),
/// so the same seed always yields the same public identity.
pub struct SigningIdentity {
    signing_key: SigningKey<MlDsa65>,
    verifying_key: Vec<u8>,
}

impl SigningIdentity {
    /// Derive the identity from its 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::<MlDsa65>::from_seed(&B32::from(*seed));
        let verifying_key = signing_key.verifying_key().encode().to_vec();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Our ML-DSA verifying (public) key, as sent on the wire.
    pub fn public_bytes(&self) -> &[u8] {
        &self.verifying_key
    }

    /// Sign a transcript digest, returning the encoded signature bytes.
    ///
    /// Deterministic signing keeps us independent of an RNG and is safe here: the
    /// digest already commits to fresh ephemeral keys, so signatures never repeat.
    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        self.signing_key
            .expanded_key()
            .sign_deterministic(digest, &[])
            .expect("ML-DSA signing of a fixed-size digest never fails")
            .encode()
            .to_vec()
    }
}

/// State the initiator holds between sending msg1 and receiving msg2.
pub struct Initiator {
    dk: DecapsulationKey768,
    x_secret: StaticSecret,
    identity: SigningIdentity,
    /// msg1 == the initiator's transcript contribution (`ek || x_pub || vk_I`).
    msg1: Vec<u8>,
}

/// Build the initiator's first handshake message.
pub fn initiator_start(identity: SigningIdentity) -> Initiator {
    let (dk, ek) = MlKem768::generate_keypair();
    let x_secret = StaticSecret::from(rand::random::<[u8; 32]>());
    let x_pub = PublicKey::from(&x_secret);

    let mut msg1 = ek.to_bytes().to_vec();
    msg1.extend_from_slice(x_pub.as_bytes());
    msg1.extend_from_slice(identity.public_bytes());

    Initiator {
        dk,
        x_secret,
        identity,
        msg1,
    }
}

impl Initiator {
    /// The bytes to send to the responder.
    pub fn msg1(&self) -> &[u8] {
        &self.msg1
    }

    /// Consume msg2, verify the responder's signature, and produce the [`Session`]
    /// plus msg3 (our own signature over the transcript).
    ///
    /// `initiator_id` is our own iroh EndpointId, `responder_id` the peer's.
    pub fn finish(
        self,
        msg2: &[u8],
        initiator_id: &[u8; 32],
        responder_id: &[u8; 32],
    ) -> Result<(Session, Vec<u8>)> {
        // msg2 = ml_kem_ct || x25519_pub || ml_dsa_vk_R || sig_R
        let (ct_bytes, rest) = take(msg2, MLKEM_CT_LEN, "ML-KEM ciphertext")?;
        let (their_x, rest) = take(rest, X25519_LEN, "responder X25519 key")?;
        let (responder_vk, sig_r) = take(rest, MLDSA_VK_LEN, "responder identity key")?;
        ensure!(
            sig_r.len() == MLDSA_SIG_LEN,
            "responder signature wrong length: {} bytes",
            sig_r.len()
        );

        let ct = Ciphertext::<MlKem768>::try_from(ct_bytes)
            .map_err(|_| anyhow!("malformed ML-KEM ciphertext"))?;
        let ss_kem = self.dk.decapsulate(&ct);
        let ss_dh = self.x_secret.diffie_hellman(&x25519_public(their_x)?);

        // msg2's transcript contribution excludes the signature that signs it.
        let msg2_core_len = MLKEM_CT_LEN + X25519_LEN + MLDSA_VK_LEN;
        let transcript = transcript(
            initiator_id,
            responder_id,
            &self.msg1,
            &msg2[..msg2_core_len],
        );
        let digest = signing_digest(&transcript);

        verify_signature(responder_vk, &digest, sig_r)?;

        let key = derive_key(ss_kem.as_slice(), ss_dh.as_bytes(), &transcript);
        let safety = safety_number(self.identity.public_bytes(), responder_vk);
        let sig_i = self.identity.sign(&digest);
        Ok((Session::new(key, Role::Initiator, safety), sig_i))
    }
}

/// The responder's state after replying with msg2, awaiting the initiator's
/// signature (msg3) before the [`Session`] can be trusted.
pub struct PendingResponder {
    session: Session,
    initiator_vk: Vec<u8>,
    digest: [u8; 32],
}

/// Handle the initiator's msg1: derive the shared secret, sign the transcript, and
/// return our reply (msg2) together with a [`PendingResponder`] awaiting msg3.
pub fn responder_receive(
    msg1: &[u8],
    initiator_id: &[u8; 32],
    responder_id: &[u8; 32],
    identity: SigningIdentity,
) -> Result<(PendingResponder, Vec<u8>)> {
    // msg1 = ml_kem_ek || x25519_pub || ml_dsa_vk_I
    let (ek_bytes, rest) = take(msg1, MLKEM_EK_LEN, "ML-KEM encapsulation key")?;
    let (their_x, initiator_vk) = take(rest, X25519_LEN, "initiator X25519 key")?;
    ensure!(
        initiator_vk.len() == MLDSA_VK_LEN,
        "initiator identity key wrong length: {} bytes",
        initiator_vk.len()
    );

    let ek_key = KemKey::<EncapsulationKey768>::try_from(ek_bytes)
        .map_err(|_| anyhow!("malformed ML-KEM encapsulation key"))?;
    let ek = EncapsulationKey768::new(&ek_key)
        .map_err(|_| anyhow!("invalid ML-KEM encapsulation key"))?;
    let (ct, ss_kem) = ek.encapsulate();

    let x_secret = StaticSecret::from(rand::random::<[u8; 32]>());
    let x_pub = PublicKey::from(&x_secret);
    let ss_dh = x_secret.diffie_hellman(&x25519_public(their_x)?);

    let mut msg2_core = ct.as_slice().to_vec();
    msg2_core.extend_from_slice(x_pub.as_bytes());
    msg2_core.extend_from_slice(identity.public_bytes());

    let transcript = transcript(initiator_id, responder_id, msg1, &msg2_core);
    let digest = signing_digest(&transcript);

    let key = derive_key(ss_kem.as_slice(), ss_dh.as_bytes(), &transcript);
    let safety = safety_number(initiator_vk, identity.public_bytes());
    let session = Session::new(key, Role::Responder, safety);

    let mut msg2 = msg2_core;
    msg2.extend_from_slice(&identity.sign(&digest));

    let pending = PendingResponder {
        session,
        initiator_vk: initiator_vk.to_vec(),
        digest,
    };
    Ok((pending, msg2))
}

impl PendingResponder {
    /// Verify the initiator's signature (msg3) and hand back the trusted [`Session`].
    pub fn finish(self, msg3: &[u8]) -> Result<Session> {
        ensure!(
            msg3.len() == MLDSA_SIG_LEN,
            "initiator signature wrong length: {} bytes",
            msg3.len()
        );
        verify_signature(&self.initiator_vk, &self.digest, msg3)?;
        Ok(self.session)
    }
}

/// Split `n` bytes off the front of `buf`, erroring (with `what`) if it is too short.
fn take<'a>(buf: &'a [u8], n: usize, what: &str) -> Result<(&'a [u8], &'a [u8])> {
    ensure!(
        buf.len() >= n,
        "handshake message truncated: need {n} bytes for {what}, have {}",
        buf.len()
    );
    Ok(buf.split_at(n))
}

/// Reconstruct an X25519 public key from exactly 32 bytes.
fn x25519_public(bytes: &[u8]) -> Result<PublicKey> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("X25519 public key must be 32 bytes"))?;
    Ok(PublicKey::from(array))
}

/// Verify an ML-DSA signature `sig` over `digest` against the encoded `vk`.
fn verify_signature(vk: &[u8], digest: &[u8; 32], sig: &[u8]) -> Result<()> {
    let vk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(vk)
        .map_err(|_| anyhow!("malformed ML-DSA key"))?;
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&vk_enc);
    let sig_enc = EncodedSignature::<MlDsa65>::try_from(sig)
        .map_err(|_| anyhow!("malformed ML-DSA signature"))?;
    let signature = Signature::<MlDsa65>::decode(&sig_enc)
        .ok_or_else(|| anyhow!("invalid ML-DSA signature"))?;
    verifying_key
        .verify(digest, &signature)
        .map_err(|_| anyhow!("handshake authentication failed: signature did not verify"))
}

/// The transcript both peers sign and salt the session key with:
/// both iroh identities followed by each side's key contribution.
fn transcript(
    initiator_id: &[u8; 32],
    responder_id: &[u8; 32],
    msg1_core: &[u8],
    msg2_core: &[u8],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(64 + msg1_core.len() + msg2_core.len());
    t.extend_from_slice(initiator_id);
    t.extend_from_slice(responder_id);
    t.extend_from_slice(msg1_core);
    t.extend_from_slice(msg2_core);
    t
}

/// The 32-byte digest that each peer signs (domain-separated from other hashes).
fn signing_digest(transcript: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(SIG_CONTEXT)
        .chain_update(transcript)
        .finalize()
        .into()
}

/// Fold both shared secrets into a single 32-byte session key.
///
/// `ikm = ss_kem || ss_dh` (hybrid), `salt = SHA256(transcript)` (binds identities,
/// iroh IDs, and both ephemeral keys), and `info` domain-separates the output.
fn derive_key(ss_kem: &[u8], ss_dh: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(ss_kem.len() + X25519_LEN);
    ikm.extend_from_slice(ss_kem);
    ikm.extend_from_slice(ss_dh);

    let salt = Sha256::digest(transcript);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO_PREFIX, &mut key)
        .expect("HKDF expand of 32 bytes never fails");
    key
}

/// A short, order-independent fingerprint of both peers' identity keys, for
/// out-of-band verification. Both ends compute the same value.
fn safety_number(vk_a: &[u8], vk_b: &[u8]) -> String {
    // Sort so the value is symmetric regardless of who dialed whom.
    let (lo, hi) = if vk_a <= vk_b {
        (vk_a, vk_b)
    } else {
        (vk_b, vk_a)
    };
    let digest = Sha256::new()
        .chain_update(SN_CONTEXT)
        .chain_update(lo)
        .chain_update(hi)
        .finalize();
    digest[..8]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join("-")
}

/// An established, authenticated, quantum-resistant session.
///
/// Splits into a [`Sealer`] (outgoing) and [`Opener`] (incoming) so the read and
/// write halves can run on independent tasks without sharing mutable state.
pub struct Session {
    key: [u8; 32],
    role: Role,
    safety_number: String,
}

impl Session {
    fn new(key: [u8; 32], role: Role, safety_number: String) -> Self {
        Self {
            key,
            role,
            safety_number,
        }
    }

    /// The out-of-band verification string derived from both identity keys.
    /// Identical on both ends when the channel is genuine.
    pub fn safety_number(&self) -> &str {
        &self.safety_number
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
            .ok_or_else(|| anyhow!("send nonce counter exhausted"))?;
        self.cipher
            .encrypt(&Nonce::from(nonce), plaintext)
            .map_err(|_| anyhow!("encryption failed"))
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
            .map_err(|_| anyhow!("decryption/authentication failed"))?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("recv nonce counter exhausted"))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> SigningIdentity {
        SigningIdentity::from_seed(&[seed; 32])
    }

    // Run a full three-message handshake in-process and return both sessions.
    fn handshake() -> (Session, Session) {
        run_handshake(&[0xAA; 32], &[0xBB; 32], &[0xAA; 32], &[0xBB; 32])
            .expect("handshake should succeed")
    }

    // Run a handshake letting each side use its own view of the two iroh IDs, so
    // tests can simulate an identity splice. Returns an error if authentication fails.
    fn run_handshake(
        init_id_i: &[u8; 32],
        init_id_r: &[u8; 32],
        resp_id_i: &[u8; 32],
        resp_id_r: &[u8; 32],
    ) -> Result<(Session, Session)> {
        let initiator = initiator_start(identity(1));
        let (pending, msg2) =
            responder_receive(initiator.msg1(), resp_id_i, resp_id_r, identity(2))?;
        let (init_session, msg3) = initiator.finish(&msg2, init_id_i, init_id_r)?;
        let resp_session = pending.finish(&msg3)?;
        Ok((init_session, resp_session))
    }

    #[test]
    fn wire_lengths_match_the_declared_constants() {
        // If a crate ever changes an encoding size, our field parsing would silently
        // misalign — this catches it.
        let initiator = initiator_start(identity(1));
        assert_eq!(
            initiator.msg1().len(),
            MLKEM_EK_LEN + X25519_LEN + MLDSA_VK_LEN
        );
        let (_pending, msg2) =
            responder_receive(initiator.msg1(), &[1; 32], &[2; 32], identity(2)).unwrap();
        assert_eq!(
            msg2.len(),
            MLKEM_CT_LEN + X25519_LEN + MLDSA_VK_LEN + MLDSA_SIG_LEN
        );
    }

    #[test]
    fn both_sides_derive_the_same_key_and_safety_number() {
        let (a, b) = handshake();
        assert_eq!(a.key, b.key, "session keys must match");
        assert_eq!(a.safety_number(), b.safety_number());
    }

    #[test]
    fn message_round_trips_in_both_directions() {
        let (a, b) = handshake();
        let (mut a_seal, mut a_open) = a.split();
        let (mut b_seal, mut b_open) = b.split();

        let ct = a_seal.seal(b"hello from A").unwrap();
        assert_eq!(b_open.open(&ct).unwrap(), b"hello from A");

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
        ct[last] ^= 0x01;
        assert!(b_open.open(&ct).is_err(), "AEAD must reject tampering");
    }

    #[test]
    fn tampered_responder_signature_is_rejected() {
        let initiator = initiator_start(identity(1));
        let (_pending, mut msg2) =
            responder_receive(initiator.msg1(), &[1; 32], &[2; 32], identity(2)).unwrap();
        // Flip a byte inside the responder's signature (the trailing field).
        let last = msg2.len() - 1;
        msg2[last] ^= 0x01;
        assert!(
            initiator.finish(&msg2, &[1; 32], &[2; 32]).is_err(),
            "initiator must reject a bad responder signature"
        );
    }

    #[test]
    fn tampered_initiator_signature_is_rejected() {
        let initiator = initiator_start(identity(1));
        let (pending, msg2) =
            responder_receive(initiator.msg1(), &[1; 32], &[2; 32], identity(2)).unwrap();
        let (_session, mut msg3) = initiator.finish(&msg2, &[1; 32], &[2; 32]).unwrap();
        msg3[0] ^= 0x01;
        assert!(
            pending.finish(&msg3).is_err(),
            "responder must reject a bad initiator signature"
        );
    }

    #[test]
    fn mismatched_iroh_ids_break_authentication() {
        // The two sides disagree about the responder's iroh id (as a MITM splice
        // would). Their transcripts diverge, so the responder's signature — made over
        // its own transcript — fails to verify against the initiator's transcript.
        let result = run_handshake(&[1; 32], &[2; 32], &[1; 32], &[9; 32]);
        assert!(
            result.is_err(),
            "spliced identities must fail the handshake"
        );
    }

    #[test]
    fn a_different_identity_key_changes_the_safety_number() {
        // A MITM substituting its own identity key would change what each side sees.
        let (a, _b) = handshake();
        let mitm = safety_number(identity(1).public_bytes(), identity(3).public_bytes());
        assert_ne!(a.safety_number(), mitm);
    }

    #[test]
    fn the_same_seed_yields_the_same_identity() {
        assert_eq!(identity(7).public_bytes(), identity(7).public_bytes());
        assert_ne!(identity(7).public_bytes(), identity(8).public_bytes());
    }
}
