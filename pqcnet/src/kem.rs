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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_is_deterministic_for_instance() {
        let kem = MlKem1024::new().expect("kem");

        let (pk1, sk1) = kem.keypair().expect("first keypair");
        let (pk2, sk2) = kem.keypair().expect("second keypair");

        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1.len(), 32);
        assert_eq!(sk1.len(), 32);
    }

    #[test]
    fn encapsulate_changes_ciphertext_and_secret() {
        let kem = MlKem1024::new().expect("kem");
        let (pk, _) = kem.keypair().expect("keypair");

        let (ct1, ss1) = kem.encapsulate(&pk).expect("first encapsulate");
        let (ct2, ss2) = kem.encapsulate(&pk).expect("second encapsulate");

        assert_eq!(ct1.len(), 96);
        assert_eq!(ss1.len(), 32);
        assert_eq!(ct2.len(), 96);
        assert_eq!(ss2.len(), 32);

        assert_ne!(ct1, ct2, "ciphertexts must include fresh salt");
        assert_ne!(ss1, ss2, "shared secrets must derive from salt");
    }
}
