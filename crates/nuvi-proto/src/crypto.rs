use anyhow::{anyhow, bail, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
pub use ed25519_dalek::VerifyingKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Unambiguous 32-character alphabet (no 0/O, 1/I/L).
const KEY_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

#[derive(Clone)]
pub struct IdentityKeypair {
    signing: SigningKey,
}

impl IdentityKeypair {
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let signing = SigningKey::from_bytes(&secret);
        secret.zeroize();
        Self { signing }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.verifying_key().as_bytes())
    }

    pub fn device_id(&self) -> String {
        device_id_from_pubkey(&self.verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}

pub fn decode_verifying_key(b64: &str) -> Result<VerifyingKey> {
    let raw = B64
        .decode(b64.trim())
        .map_err(|e| anyhow!("invalid base64 public key: {e}"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow!("invalid ed25519 public key: {e}"))
}

pub fn device_id_from_pubkey(vk: &VerifyingKey) -> String {
    let hash = Sha256::digest(vk.as_bytes());
    let n = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 1_000_000_000;
    let part1 = n / 1_000_000;
    let part2 = (n / 1_000) % 1_000;
    let part3 = n % 1_000;
    format!("NUVI-{part1:03}-{part2:03}-{part3:03}")
}

pub fn generate_challenge_nonce_b64() -> String {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    B64.encode(nonce)
}

fn build_registration_challenge_payload(device_id: &str, nonce: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(17 + device_id.len() + 1 + 32);
    payload.extend_from_slice(b"nuvi-register-v1:");
    payload.extend_from_slice(device_id.as_bytes());
    payload.push(b':');
    payload.extend_from_slice(nonce);
    payload
}

pub fn sign_registration_challenge(
    kp: &IdentityKeypair,
    device_id: &str,
    nonce_b64: &str,
) -> Result<String> {
    let raw = B64
        .decode(nonce_b64.trim())
        .map_err(|e| anyhow!("invalid challenge nonce b64: {e}"))?;
    let nonce: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("challenge nonce must be 32 bytes"))?;
    let payload = build_registration_challenge_payload(device_id, &nonce);
    Ok(B64.encode(kp.sign(&payload)))
}

pub fn verify_registration_challenge(
    vk: &VerifyingKey,
    device_id: &str,
    nonce_b64: &str,
    signature_b64: &str,
) -> Result<()> {
    let raw_nonce = B64
        .decode(nonce_b64.trim())
        .map_err(|e| anyhow!("invalid challenge nonce b64: {e}"))?;
    let nonce: [u8; 32] = raw_nonce
        .try_into()
        .map_err(|_| anyhow!("challenge nonce must be 32 bytes"))?;

    let sig_raw = B64
        .decode(signature_b64.trim())
        .map_err(|e| anyhow!("invalid registration signature b64: {e}"))?;
    let sig_arr: [u8; 64] = sig_raw
        .try_into()
        .map_err(|_| anyhow!("registration signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);

    let payload = build_registration_challenge_payload(device_id, &nonce);
    vk.verify(&payload, &sig)
        .map_err(|_| anyhow!("registration signature verification failed"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Host,
    Client,
}

pub struct HandshakeState {
    session_id: Uuid,
    role: Role,
    ephemeral_secret: StaticSecret,
    ephemeral_pub: X25519PublicKey,
}

impl HandshakeState {
    pub fn new(session_id: Uuid, role: Role) -> Self {
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
        Self {
            session_id,
            role,
            ephemeral_secret,
            ephemeral_pub,
        }
    }

    pub fn ephemeral_pub_b64(&self) -> String {
        B64.encode(self.ephemeral_pub.as_bytes())
    }

    pub fn sign_ephemeral(&self, identity: &IdentityKeypair) -> String {
        let mut payload = Vec::with_capacity(16 + 32);
        payload.extend_from_slice(self.session_id.as_bytes());
        payload.extend_from_slice(self.ephemeral_pub.as_bytes());
        B64.encode(identity.sign(&payload))
    }

    pub fn complete(
        self,
        expected_peer_vk: &VerifyingKey,
        peer_ephemeral_b64: &str,
        peer_identity_b64: &str,
        peer_signature_b64: &str,
    ) -> Result<SessionCipher> {
        let peer_vk = decode_verifying_key(peer_identity_b64)?;
        if peer_vk.as_bytes() != expected_peer_vk.as_bytes() {
            bail!("peer identity key mismatch");
        }

        let peer_eph_raw = B64
            .decode(peer_ephemeral_b64.trim())
            .map_err(|e| anyhow!("invalid peer ephemeral key: {e}"))?;
        let peer_eph_arr: [u8; 32] = peer_eph_raw
            .try_into()
            .map_err(|_| anyhow!("peer ephemeral key must be 32 bytes"))?;
        let peer_eph_pub = X25519PublicKey::from(peer_eph_arr);

        let sig_raw = B64
            .decode(peer_signature_b64.trim())
            .map_err(|e| anyhow!("invalid peer signature b64: {e}"))?;
        let sig_arr: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| anyhow!("signature must be 64 bytes"))?;
        let sig = Signature::from_bytes(&sig_arr);

        let mut payload = Vec::with_capacity(16 + 32);
        payload.extend_from_slice(self.session_id.as_bytes());
        payload.extend_from_slice(peer_eph_pub.as_bytes());
        peer_vk
            .verify(&payload, &sig)
            .map_err(|_| anyhow!("peer handshake signature verification failed"))?;

        let shared = self.ephemeral_secret.diffie_hellman(&peer_eph_pub);
        let h2c = derive_direction_key(shared.as_bytes(), self.session_id, b"nuvi-remote-v1-h2c");
        let c2h = derive_direction_key(shared.as_bytes(), self.session_id, b"nuvi-remote-v1-c2h");

        let (tx_key, rx_key) = match self.role {
            Role::Host => (h2c, c2h),
            Role::Client => (c2h, h2c),
        };

        Ok(SessionCipher {
            tx: ChaCha20Poly1305::new(Key::from_slice(&tx_key)),
            rx: ChaCha20Poly1305::new(Key::from_slice(&rx_key)),
            tx_counter: 0,
            rx_counter: 0,
        })
    }
}

fn derive_direction_key(shared: &[u8], session_id: Uuid, label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared);
    hasher.update(session_id.as_bytes());
    hasher.update(label);
    hasher.finalize().into()
}

pub struct SessionCipher {
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_counter: u64,
    rx_counter: u64,
}

impl SessionCipher {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.tx_counter;
        self.tx_counter = self
            .tx_counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("tx nonce counter exhausted"))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        let ct = self
            .tx
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| anyhow!("encrypt failed: {e}"))?;

        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < 8 {
            bail!("encrypted frame too short");
        }
        let counter = u64::from_be_bytes(frame[..8].try_into()?);
        if counter < self.rx_counter {
            bail!("replayed or out-of-order counter");
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        let pt = self
            .rx
            .decrypt(Nonce::from_slice(&nonce_bytes), &frame[8..])
            .map_err(|e| anyhow!("decrypt failed: {e}"))?;
        self.rx_counter = counter + 1;
        Ok(pt)
    }
}

pub fn generate_unattended_key() -> String {
    let limit = (256 / KEY_ALPHABET.len()) * KEY_ALPHABET.len();
    let mut chars = [b'2'; 12];
    let mut buf = [0u8; 32];
    let mut i = 0;
    while i < chars.len() {
        OsRng.fill_bytes(&mut buf);
        for &b in &buf {
            if (b as usize) < limit {
                chars[i] = KEY_ALPHABET[(b as usize) % KEY_ALPHABET.len()];
                i += 1;
                if i == chars.len() {
                    break;
                }
            }
        }
    }
    let s = std::str::from_utf8(&chars).unwrap_or("222222222222");
    format!("NUVI-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12])
}

pub fn normalize_unattended_key(input: &str) -> String {
    input.trim().to_ascii_uppercase()
}

pub fn hash_unattended_key(key: &str) -> Result<String> {
    let norm = normalize_unattended_key(key);
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(norm.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2 hash failed: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_unattended_key(candidate: &str, stored_hash: &str) -> bool {
    let norm = normalize_unattended_key(candidate);
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(norm.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_device_id_format() {
        let kp = IdentityKeypair::generate();
        let id1 = kp.device_id();
        let id2 = device_id_from_pubkey(&kp.verifying_key());
        assert_eq!(id1, id2);
        assert!(id1.starts_with("NUVI-"));
        assert_eq!(id1.len(), 16); // NUVI-XXX-XXX-XXX
    }

    #[test]
    fn handshake_and_cipher_roundtrip_and_tamper_reject() {
        let host_id = IdentityKeypair::generate();
        let client_id = IdentityKeypair::generate();
        let session_id = Uuid::new_v4();

        let h_hs = HandshakeState::new(session_id, Role::Host);
        let c_hs = HandshakeState::new(session_id, Role::Client);

        let h_eph = h_hs.ephemeral_pub_b64();
        let h_sig = h_hs.sign_ephemeral(&host_id);

        let c_eph = c_hs.ephemeral_pub_b64();
        let c_sig = c_hs.sign_ephemeral(&client_id);

        let mut host_cipher = h_hs
            .complete(
                &client_id.verifying_key(),
                &c_eph,
                &client_id.public_key_b64(),
                &c_sig,
            )
            .expect("host handshake");

        let mut client_cipher = c_hs
            .complete(
                &host_id.verifying_key(),
                &h_eph,
                &host_id.public_key_b64(),
                &h_sig,
            )
            .expect("client handshake");

        let ct = host_cipher.encrypt(b"hello client").unwrap();
        let pt = client_cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello client");

        // Replay must fail
        assert!(client_cipher.decrypt(&ct).is_err());

        // Tamper must fail
        let mut tampered = client_cipher.encrypt(b"hello host").unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(host_cipher.decrypt(&tampered).is_err());
    }

    #[test]
    fn unattended_key_argon2_verify() {
        let key = generate_unattended_key();
        assert!(key.starts_with("NUVI-"));
        let hash = hash_unattended_key(&key).unwrap();
        assert!(verify_unattended_key(&key.to_lowercase(), &hash));
        assert!(verify_unattended_key(&format!("  {key}  "), &hash));
        assert!(!verify_unattended_key("NUVI-0000-0000-0000", &hash));
    }

    #[test]
    fn registration_challenge_sign_and_verify() {
        let kp = IdentityKeypair::generate();
        let other = IdentityKeypair::generate();
        let dev_id = kp.device_id();
        let nonce = generate_challenge_nonce_b64();
        let sig = sign_registration_challenge(&kp, &dev_id, &nonce).unwrap();

        assert!(verify_registration_challenge(&kp.verifying_key(), &dev_id, &nonce, &sig).is_ok());
        assert!(
            verify_registration_challenge(&other.verifying_key(), &dev_id, &nonce, &sig).is_err()
        );
        assert!(verify_registration_challenge(
            &kp.verifying_key(),
            "NUVI-000-000-000",
            &nonce,
            &sig
        )
        .is_err());
        let other_nonce = generate_challenge_nonce_b64();
        assert!(verify_registration_challenge(
            &kp.verifying_key(),
            &dev_id,
            &other_nonce,
            &sig
        )
        .is_err());
    }
}
