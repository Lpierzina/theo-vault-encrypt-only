use crate::{random_array, Result};

/// Simplified Dilithium-style signature helper backed by BLAKE3 commitments.
#[derive(Debug, Clone)]
pub struct Dilithium5 {
    seed: [u8; 32],
}

impl Dilithium5 {
    pub fn new() -> Result<Self> {
        Ok(Self {
            seed: random_array::<32>(),
        })
    }

    pub fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut pk_hasher = blake3::Hasher::new_keyed(&self.seed);
        pk_hasher.update(b"dilithium5-public");
        Ok((pk_hasher.finalize().as_bytes().to_vec(), self.seed.to_vec()))
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut signer = blake3::Hasher::new_keyed(&self.seed);
        signer.update(message);
        Ok(signer.finalize().as_bytes().to_vec())
    }
}
