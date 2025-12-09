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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_returns_expected_lengths() {
        let sig = Dilithium5::new().expect("sig");
        let (pk, sk) = sig.keypair().expect("keypair");

        assert_eq!(pk.len(), 32);
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn sign_is_deterministic_per_message() {
        let sig = Dilithium5::new().expect("sig");
        let message = b"quantum immune";

        let first = sig.sign(message).expect("first signature");
        let second = sig.sign(message).expect("second signature");
        let different = sig.sign(b"different payload").expect("different signature");

        assert_eq!(first, second);
        assert_ne!(first, different);
    }
}
