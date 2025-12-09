use crate::{random_array, random_vec, Result};

/// Lightweight ML-KEM style wrapper that provides deterministic key derivation.
#[derive(Debug, Clone)]
pub struct MlKem1024 {
    seed: [u8; 32],
}

impl MlKem1024 {
    pub fn new() -> Result<Self> {
        Ok(Self {
            seed: random_array::<32>(),
        })
    }

    pub fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut pk_hasher = blake3::Hasher::new_keyed(&self.seed);
        pk_hasher.update(b"mlkem1024-public");

        let mut sk_hasher = blake3::Hasher::new_keyed(&self.seed);
        sk_hasher.update(b"mlkem1024-secret");

        Ok((
            pk_hasher.finalize().as_bytes().to_vec(),
            sk_hasher.finalize().as_bytes().to_vec(),
        ))
    }

    pub fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let salt = random_vec(32);
        let mut ss_hasher = blake3::Hasher::new_keyed(&self.seed);
        ss_hasher.update(pk);
        ss_hasher.update(&salt);

        let shared_secret = ss_hasher.finalize().as_bytes().to_vec();
        let mut ciphertext = salt;
        ciphertext.extend_from_slice(&random_vec(64));

        Ok((ciphertext, shared_secret))
    }
}
