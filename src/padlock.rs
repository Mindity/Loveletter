// loveletter/src/padlock.rs

use ring::rand::{SecureRandom, SystemRandom};
use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM, Aad, Nonce, NONCE_LEN};
use ring::hmac;

// This struct now holds two keys:
// 1) The AES-GCM key for encryption
// 2) The HMAC key for hashing
pub struct Padlock {
    encryption_key: LessSafeKey,
    hmac_key: hmac::Key, // key for HMAC
}

impl Padlock {
    /// Create a new Padlock with random 256-bit keys
    pub fn new() -> Self {
        let sys_rng = SystemRandom::new();

        // --- Encryption Key (AES-GCM) ---
        let mut enc_bytes = [0u8; 32];
        sys_rng.fill(&mut enc_bytes).unwrap();
        let unbound_key = UnboundKey::new(&AES_256_GCM, &enc_bytes).unwrap();
        let encryption_key = LessSafeKey::new(unbound_key);

        // --- HMAC Key (SHA256) ---
        let mut hmac_bytes = [0u8; 32];
        sys_rng.fill(&mut hmac_bytes).unwrap();
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_bytes);

        Padlock {
            encryption_key,
            hmac_key,
        }
    }

    /// Encrypt data with AES-256-GCM (same as before)
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let sys_rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        sys_rng.fill(&mut nonce_bytes).unwrap();

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        in_out.resize(in_out.len() + 16, 0); // 16 bytes for GCM tag

        self.encryption_key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .expect("Encryption failed");

        // Combine nonce + ciphertext
        let mut ciphertext = nonce_bytes.to_vec();
        ciphertext.extend_from_slice(&in_out);
        ciphertext
    }

    /// Decrypt data with AES-256-GCM
    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < NONCE_LEN + 16 {
            return None;
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).ok()?;

        let mut in_out = encrypted.to_vec();
        let res = self
            .encryption_key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .ok()?;

        Some(res.to_vec())
    }

    /// Compute HMAC-SHA256 of some plaintext
    pub fn compute_hmac(&self, data: &[u8]) -> Vec<u8> {
        let tag = hmac::sign(&self.hmac_key, data);
        tag.as_ref().to_vec()
    }

    /// Verify HMAC-SHA256 (returns `true` if valid, `false` if mismatch)
    pub fn verify_hmac(&self, data: &[u8], expected_tag: &[u8]) -> bool {
        hmac::verify(&self.hmac_key, data, expected_tag).is_ok()
    }
}

