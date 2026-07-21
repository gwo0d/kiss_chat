//! End-to-end encryption **and authentication** for kiss_chat.
//!
//! iroh already hands us an authenticated, TLS-1.3-encrypted QUIC stream. On top
//! of it we run a small handshake that is quantum-resistant end to end:
//!
//! 1. A **hybrid key exchange** combining classical X25519 ECDH with post-quantum
//!    ML-KEM-1024 (NIST security category 5). The session key survives even if *one*
//!    of the two primitives is later broken — the same construction shipped by
//!    Chrome/Cloudflare/AWS in TLS.
//! 2. **Post-quantum mutual authentication** with ML-DSA-87 (FIPS 204, category 5). Each peer
//!    holds a long-term ML-DSA identity key and signs the full handshake transcript,
//!    so a man-in-the-middle cannot impersonate a known identity even with a quantum
//!    computer. The signatures bind the ephemeral keys to the identity keys.
//! 3. Both shared secrets are folded into HKDF-SHA256, salted with the transcript
//!    (which includes both identity keys and both iroh EndpointIds), then messages
//!    are sealed with ChaCha20-Poly1305 using deterministic per-direction nonce
//!    counters (QUIC is reliable and in-order, so counters stay in lockstep and no
//!    nonce is ever reused).
//!
//! The **safety number** ([`Session::safety_number`]) is derived from the full
//! handshake transcript — both identity keys, both ephemeral keys, and both iroh
//! EndpointIds — and rendered as a short word phrase (BIP39 wordlist) that is
//! identical on both ends. Reading it aloud out-of-band authenticates the channel:
//! under a MITM the two ends would see different phrases. Folding in the ephemeral
//! keys means the value cannot be precomputed offline, so a MITM cannot mine
//! colliding identities ahead of time. Verify it once and the signatures do the rest.
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
    B32, EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Signature, SigningKey, Verifier,
    VerifyingKey,
};
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{
    Ciphertext, DecapsulationKey1024, EncapsulationKey1024, Kem, MlKem1024, kem::Key as KemKey,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Length of an X25519 public key, in bytes.
const X25519_LEN: usize = 32;
/// Encoded length of an ML-KEM-1024 encapsulation key (FIPS 203).
const MLKEM_EK_LEN: usize = 1568;
/// Encoded length of an ML-KEM-1024 ciphertext (FIPS 203).
const MLKEM_CT_LEN: usize = 1568;
/// Encoded length of an ML-DSA-87 verifying (public) key (FIPS 204).
const MLDSA_VK_LEN: usize = 2592;
/// Encoded length of an ML-DSA-87 signature (FIPS 204).
const MLDSA_SIG_LEN: usize = 4627;

/// HKDF `info` domain-separation prefix. Bumped whenever the wire format changes.
const HKDF_INFO_PREFIX: &[u8] = b"kiss-chat/0 e2e session";
/// Domain separator for the transcript digest that both peers sign.
const SIG_CONTEXT: &[u8] = b"kiss-chat/0 handshake signature";
/// Domain separator for the safety-number derivation.
const SN_CONTEXT: &[u8] = b"kiss-chat/0 safety number";
/// Words in the safety phrase we surface out-of-band, and bits each encodes.
/// 12 words × 11 bits = 132 bits, so even a MITM's best online collision search
/// (~2^66 hashes) stays out of reach, while a dozen distinct words are far easier
/// to read aloud and compare accurately than a hex string.
const SN_WORDS: usize = 12;
const SN_WORD_BITS: usize = 11;

/// The BIP39 English wordlist (2048 = 2^11 words), embedded verbatim. It only has
/// to be consistent between two kiss_chat instances — we use it purely to render a
/// digest as a memorable phrase — but a vetted, phonetically-distinct list keeps
/// spoken comparison reliable. SHA-256: 2f5eed53…3b24dbda.
const BIP39_ENGLISH: &str = include_str!("bip39-english.txt");

/// Nonce direction tag for initiator -> responder traffic.
const DIR_I2R: [u8; 4] = [0, 0, 0, 1];
/// Nonce direction tag for responder -> initiator traffic.
const DIR_R2I: [u8; 4] = [0, 0, 0, 2];

/// 32 fresh bytes drawn straight from the operating system CSPRNG.
///
/// We read the OS entropy source explicitly rather than leaning on a library's
/// default RNG, so key generation stays sound even if a dependency ever changes
/// which RNG its `random()` helper picks.
fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("operating system CSPRNG must be available");
    bytes
}

/// Which side of the handshake we are. The dialer is always the initiator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// A long-term ML-DSA-87 identity used to authenticate the handshake.
///
/// Built deterministically from a persistent 32-byte seed (see [`crate::identity`]),
/// so the same seed always yields the same public identity.
pub struct SigningIdentity {
    signing_key: SigningKey<MlDsa87>,
    verifying_key: Vec<u8>,
}

impl SigningIdentity {
    /// Derive the identity from its 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::<MlDsa87>::from_seed(&B32::from(*seed));
        let verifying_key = signing_key.verifying_key().encode().to_vec();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Our ML-DSA verifying (public) key, as sent on the wire.
    #[must_use]
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
    dk: DecapsulationKey1024,
    x_secret: StaticSecret,
    identity: SigningIdentity,
    /// msg1 == the initiator's transcript contribution (`ek || x_pub || vk_I`).
    msg1: Vec<u8>,
}

/// Build the initiator's first handshake message.
#[must_use]
pub fn initiator_start(identity: SigningIdentity) -> Initiator {
    let (dk, ek) = MlKem1024::generate_keypair();
    let x_secret = StaticSecret::from(random_bytes());
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
    #[must_use]
    pub fn msg1(&self) -> &[u8] {
        &self.msg1
    }

    /// Consume msg2, verify the responder's signature, and produce the [`Session`]
    /// plus msg3 (our own signature over the transcript).
    ///
    /// `initiator_id` is our own iroh EndpointId, `responder_id` the peer's.
    ///
    /// # Errors
    ///
    /// Fails if msg2 is truncated or malformed, or if the responder's signature
    /// does not verify against the transcript (a MITM, or a corrupted message).
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

        let ct = Ciphertext::<MlKem1024>::try_from(ct_bytes)
            .map_err(|_| anyhow!("malformed ML-KEM ciphertext"))?;
        let ss_kem = self.dk.decapsulate(&ct);
        let ss_dh = self.x_secret.diffie_hellman(&x25519_public(their_x)?);
        // Reject a low-order X25519 key, which would force an all-zero DH share.
        // Defence in depth: the ML-KEM secret and signed transcript already protect
        // the session key, but a contributory exchange is one line to guarantee.
        ensure!(
            ss_dh.was_contributory(),
            "peer sent a non-contributory (low-order) X25519 key"
        );

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
        let safety = safety_number(&transcript);
        let sig_i = self.identity.sign(&digest);
        let session = Session::new(key, Role::Initiator, safety, responder_vk.to_vec());
        Ok((session, sig_i))
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
///
/// # Errors
///
/// Fails if msg1 is truncated or carries a malformed ML-KEM encapsulation key,
/// X25519 key, or ML-DSA identity key.
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

    let ek_key = KemKey::<EncapsulationKey1024>::try_from(ek_bytes)
        .map_err(|_| anyhow!("malformed ML-KEM encapsulation key"))?;
    let ek = EncapsulationKey1024::new(&ek_key)
        .map_err(|_| anyhow!("invalid ML-KEM encapsulation key"))?;
    let (ct, ss_kem) = ek.encapsulate();

    let x_secret = StaticSecret::from(random_bytes());
    let x_pub = PublicKey::from(&x_secret);
    let ss_dh = x_secret.diffie_hellman(&x25519_public(their_x)?);
    // Reject a low-order X25519 key (see the initiator side for the rationale).
    ensure!(
        ss_dh.was_contributory(),
        "peer sent a non-contributory (low-order) X25519 key"
    );

    let mut msg2_core = ct.as_slice().to_vec();
    msg2_core.extend_from_slice(x_pub.as_bytes());
    msg2_core.extend_from_slice(identity.public_bytes());

    let transcript = transcript(initiator_id, responder_id, msg1, &msg2_core);
    let digest = signing_digest(&transcript);

    let key = derive_key(ss_kem.as_slice(), ss_dh.as_bytes(), &transcript);
    let safety = safety_number(&transcript);
    let session = Session::new(key, Role::Responder, safety, initiator_vk.to_vec());

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
    ///
    /// # Errors
    ///
    /// Fails if msg3 is the wrong length or the initiator's signature does not
    /// verify against the transcript.
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
    let vk_enc = EncodedVerifyingKey::<MlDsa87>::try_from(vk)
        .map_err(|_| anyhow!("malformed ML-DSA key"))?;
    let verifying_key = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let sig_enc = EncodedSignature::<MlDsa87>::try_from(sig)
        .map_err(|_| anyhow!("malformed ML-DSA signature"))?;
    let signature = Signature::<MlDsa87>::decode(&sig_enc)
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
    // The combined input keying material is secret; scrub it once we're done.
    let mut ikm = Zeroizing::new(Vec::with_capacity(ss_kem.len() + X25519_LEN));
    ikm.extend_from_slice(ss_kem);
    ikm.extend_from_slice(ss_dh);

    let salt = Sha256::digest(transcript);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO_PREFIX, &mut key)
        .expect("HKDF expand of 32 bytes never fails");
    key
}

/// A short, human-comparable fingerprint of the whole handshake, rendered as a
/// [`SN_WORDS`]-word phrase for out-of-band verification. Both ends compute the
/// same value.
///
/// It is derived from the full transcript — which commits to both identity keys,
/// both *ephemeral* keys, and both iroh EndpointIds — not the long-term identity
/// keys alone. Binding the ephemeral keys is what defeats an *offline* collision
/// search: a MITM can no longer precompute identities whose fingerprints coincide,
/// because every session folds in fresh ephemeral material it cannot know in
/// advance. Any collision search is forced into the live handshake, and at 132
/// bits even a real-time birthday grind (~2^66 hashes) is out of reach. The
/// transcript is already byte-identical on both ends — the signatures prove it —
/// so no sorting is needed for symmetry.
fn safety_number(transcript: &[u8]) -> String {
    let digest = Sha256::new()
        .chain_update(SN_CONTEXT)
        .chain_update(transcript)
        .finalize();
    let words: Vec<&str> = BIP39_ENGLISH.lines().collect();
    debug_assert_eq!(
        words.len(),
        1 << SN_WORD_BITS,
        "wordlist must be 2^11 entries"
    );
    (0..SN_WORDS)
        .map(|i| words[take_bits(&digest, i * SN_WORD_BITS, SN_WORD_BITS)])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Read `n` bits (n ≤ 16) from `bytes` starting at bit `offset`, most-significant
/// bit first, as an integer. Used to slice the digest into wordlist indices.
fn take_bits(bytes: &[u8], offset: usize, n: usize) -> usize {
    let mut value = 0usize;
    for i in 0..n {
        let bit = offset + i;
        let set = (bytes[bit / 8] >> (7 - (bit % 8))) & 1;
        value = (value << 1) | set as usize;
    }
    value
}

/// An established, authenticated, quantum-resistant session.
///
/// Splits into a [`Sealer`] (outgoing) and [`Opener`] (incoming) so the read and
/// write halves can run on independent tasks without sharing mutable state.
pub struct Session {
    key: [u8; 32],
    role: Role,
    safety_number: String,
    /// The peer's long-term ML-DSA verifying key, as presented and verified in the
    /// handshake. Stable across sessions with the same peer, so it can be pinned.
    peer_identity: Vec<u8>,
}

impl Drop for Session {
    /// Scrub the raw session key from memory when the session ends. (The `Sealer`
    /// and `Opener` ciphers zeroize their own copies via the `zeroize` feature.)
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Session {
    fn new(key: [u8; 32], role: Role, safety_number: String, peer_identity: Vec<u8>) -> Self {
        Self {
            key,
            role,
            safety_number,
            peer_identity,
        }
    }

    /// The out-of-band verification string derived from both identity keys.
    /// Identical on both ends when the channel is genuine.
    #[must_use]
    pub fn safety_number(&self) -> &str {
        &self.safety_number
    }

    /// The peer's long-term ML-DSA verifying key, verified during the handshake.
    ///
    /// This is the peer's *stable* identity (unlike the per-session safety number,
    /// which folds in fresh ephemeral keys). Pinning it against the peer's address
    /// lets [`crate::contacts`] flag a later identity-key change.
    #[must_use]
    pub fn peer_identity(&self) -> &[u8] {
        &self.peer_identity
    }

    /// Split into directional halves. The direction tags depend on our role so
    /// the two peers never collide on a nonce.
    #[must_use]
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
    ///
    /// # Errors
    ///
    /// Fails if the per-direction nonce counter is exhausted (after 2^64 messages)
    /// or the AEAD reports an encryption error.
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
    ///
    /// # Errors
    ///
    /// Fails if authentication does not verify (tampered, reordered, or dropped
    /// frame) or the nonce counter is exhausted.
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
    fn each_side_learns_the_peers_long_term_identity() {
        // handshake() runs identity(1) as initiator and identity(2) as responder,
        // so each session should expose the *other* side's verifying key.
        let (init, resp) = handshake();
        assert_eq!(init.peer_identity(), identity(2).public_bytes());
        assert_eq!(resp.peer_identity(), identity(1).public_bytes());
        assert_ne!(init.peer_identity(), resp.peer_identity());
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
    fn a_failed_open_does_not_advance_the_counter() {
        // Replicates: seal a frame, corrupt a copy, fail to open the corrupt copy,
        // then open the genuine frame. A rejected frame must not consume a nonce, so
        // the untouched original must still decrypt.
        let (a, b) = handshake();
        let (mut a_seal, _) = a.split();
        let (_, mut b_open) = b.split();

        let genuine = a_seal.seal(b"the real message").unwrap();
        let mut corrupt = genuine.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0x01;

        assert!(
            b_open.open(&corrupt).is_err(),
            "corrupt frame must be rejected"
        );
        assert_eq!(
            b_open.open(&genuine).unwrap(),
            b"the real message",
            "a rejected frame must not advance the nonce counter"
        );
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
    fn a_low_order_initiator_x25519_key_is_rejected() {
        // A peer offering a low-order point (here the all-zero public key) would force
        // an all-zero DH share; the responder's contributory check must reject it.
        let initiator = initiator_start(identity(1));
        let mut msg1 = initiator.msg1().to_vec();
        // Zero the X25519 field: msg1 = ek || x25519 || vk_I.
        for byte in &mut msg1[MLKEM_EK_LEN..MLKEM_EK_LEN + X25519_LEN] {
            *byte = 0;
        }
        assert!(
            responder_receive(&msg1, &[1; 32], &[2; 32], identity(2)).is_err(),
            "a low-order initiator X25519 key must fail the handshake"
        );
    }

    #[test]
    fn a_low_order_responder_x25519_key_is_rejected() {
        // The mirror case: the initiator must reject a low-order key in msg2. The
        // contributory check runs before signature verification, so it fires first.
        let initiator = initiator_start(identity(1));
        let (_pending, mut msg2) =
            responder_receive(initiator.msg1(), &[1; 32], &[2; 32], identity(2)).unwrap();
        // Zero the X25519 field: msg2 = ct || x25519 || vk_R || sig_R.
        for byte in &mut msg2[MLKEM_CT_LEN..MLKEM_CT_LEN + X25519_LEN] {
            *byte = 0;
        }
        assert!(
            initiator.finish(&msg2, &[1; 32], &[2; 32]).is_err(),
            "a low-order responder X25519 key must fail the handshake"
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
    fn safety_number_is_bound_to_the_transcript() {
        // Different transcripts (a MITM's spliced handshake differs from the real
        // one on both ends) must yield different fingerprints; the same transcript
        // is stable.
        let one = safety_number(b"transcript-one");
        assert_eq!(one, safety_number(b"transcript-one"));
        assert_ne!(one, safety_number(b"transcript-two"));
    }

    #[test]
    fn safety_number_is_a_valid_word_phrase() {
        // Twelve space-separated words, each drawn from the embedded wordlist.
        let wordlist: std::collections::HashSet<&str> = BIP39_ENGLISH.lines().collect();
        assert_eq!(wordlist.len(), 1 << SN_WORD_BITS, "2048 distinct words");

        let phrase = safety_number(b"anything");
        let words: Vec<&str> = phrase.split(' ').collect();
        assert_eq!(words.len(), SN_WORDS);
        assert!(
            words.iter().all(|w| wordlist.contains(w)),
            "every word must come from the wordlist"
        );
    }

    #[test]
    fn take_bits_reads_big_endian() {
        // 0xA6 = 0b1010_0110, 0xC0 = 0b1100_0000.
        let bytes = [0xA6, 0xC0];
        assert_eq!(take_bits(&bytes, 0, 5), 0b10100);
        assert_eq!(take_bits(&bytes, 5, 6), 0b110110);
    }

    #[test]
    fn the_same_seed_yields_the_same_identity() {
        assert_eq!(identity(7).public_bytes(), identity(7).public_bytes());
        assert_ne!(identity(7).public_bytes(), identity(8).public_bytes());
    }
}
