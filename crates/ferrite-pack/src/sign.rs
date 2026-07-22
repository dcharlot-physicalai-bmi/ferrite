use crate::PackError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// An ed25519 author identity. The 32-byte seed is the secret; the public key
/// (hex) is the signer id devices allowlist.
pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self, PackError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| PackError::Rng(e.to_string()))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, PackError> {
        let bytes = hex::decode(seed_hex.trim()).map_err(|e| PackError::Crypto(e.to_string()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PackError::Crypto("seed must be 32 bytes".into()))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    pub fn seed_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    pub fn sign(&self, manifest_bytes: &[u8]) -> SignatureBlock {
        let sig = self.signing.sign(manifest_bytes);
        SignatureBlock {
            alg: "ed25519".into(),
            public_key: self.public_hex(),
            sig: hex::encode(sig.to_bytes()),
        }
    }
}

/// Contents of signature.json — self-describing so verification needs no
/// out-of-band key distribution (trust in the key is the agent's allowlist
/// decision, not the format's).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    pub alg: String,
    /// Signer's ed25519 public key, lowercase hex.
    pub public_key: String,
    /// Signature over the exact stored manifest.json bytes, lowercase hex.
    pub sig: String,
}

impl SignatureBlock {
    /// Verify `manifest_bytes` against this block. Returns the signer's public
    /// key hex on success (the identity to check against an allowlist).
    pub fn verify(&self, manifest_bytes: &[u8]) -> Result<String, PackError> {
        if self.alg != "ed25519" {
            return Err(PackError::Crypto(format!("unsupported alg {:?}", self.alg)));
        }
        let pk_bytes: [u8; 32] = hex::decode(&self.public_key)
            .map_err(|e| PackError::Crypto(e.to_string()))?
            .try_into()
            .map_err(|_| PackError::Crypto("public key must be 32 bytes".into()))?;
        let key = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| PackError::Crypto(e.to_string()))?;
        let sig_bytes: [u8; 64] = hex::decode(&self.sig)
            .map_err(|e| PackError::Crypto(e.to_string()))?
            .try_into()
            .map_err(|_| PackError::Crypto("signature must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        key.verify(manifest_bytes, &sig)
            .map_err(|e| PackError::Crypto(format!("signature check failed: {e}")))?;
        Ok(self.public_key.clone())
    }
}
