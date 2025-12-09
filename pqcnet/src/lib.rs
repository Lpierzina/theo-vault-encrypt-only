pub mod kem;
pub mod sig;

pub use kem::MlKem1024;
pub use sig::Dilithium5;

use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use rand::{thread_rng, RngCore};
use std::io;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub fn encrypt_aes_gcm_siv(secret: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key_material = blake3::hash(secret);
    let key = Key::<Aes256GcmSiv>::from_slice(key_material.as_bytes());
    let cipher = Aes256GcmSiv::new(key);

    let nonce_bytes = random_array::<12>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "encryption failure"))?;

    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub(crate) fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    thread_rng().fill_bytes(&mut buf);
    buf
}

pub(crate) fn random_vec(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    thread_rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_changes_ciphertext() {
        let key = [0u8; 32];
        let plaintext = b"hello world";

        let first = encrypt_aes_gcm_siv(&key, plaintext).expect("first encryption");
        let second = encrypt_aes_gcm_siv(&key, plaintext).expect("second encryption");

        assert_ne!(first, second);
    }

    #[test]
    fn ciphertext_includes_nonce_and_tag() {
        let key = [0u8; 32];
        let plaintext = vec![0u8; 64];

        let ciphertext = encrypt_aes_gcm_siv(&key, &plaintext).expect("ciphertext");

        // 12-byte nonce + 64-byte body + 16-byte tag
        assert_eq!(ciphertext.len(), 12 + plaintext.len() + 16);
    }
}
