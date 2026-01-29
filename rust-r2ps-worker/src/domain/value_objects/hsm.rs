use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct WrappedPrivateKey(Vec<u8>);

impl WrappedPrivateKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for WrappedPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrappedPrivateKey({} bytes)", self.0.len())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HsmKey {
    pub wrapped_private_key: WrappedPrivateKey,
    pub public_key_jwk: EcPublicJwk,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl HsmKey {
    pub fn kid(&self) -> &str {
        &self.public_key_jwk.kid
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcPublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub kid: String,
}
