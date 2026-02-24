use crate::application::WorkerError;
use crate::application::port::outgoing::jose_port;
use crate::application::session_key_spi_port::SessionKey;
use crate::domain::{
    EcPublicJwk, EncryptOption, InnerRequest, InnerResponse, OuterRequest, OuterResponse, TypedJwe,
    TypedJws,
};
use tracing::{debug, error};

impl OuterRequest {
    pub fn from_jws(
        jws: &str,
        jose: &dyn jose_port::JosePort,
        key: &EcPublicJwk,
    ) -> Result<Self, WorkerError> {
        let jws_err = || WorkerError::decode("outer_jws_invalid");

        let bytes = jose.jws_verify_device(jws, key).map_err(|_| jws_err())?;

        serde_json::from_slice(&bytes).map_err(|e| {
            error!("Failed to deserialize outer request: {:?}", e);
            jws_err()
        })
    }

    pub fn decrypt_inner(
        &self,
        jose: &dyn jose_port::JosePort,
        session_key: Option<&SessionKey>,
    ) -> Result<InnerRequest, WorkerError> {
        let jwe = self
            .inner_jwe
            .as_ref()
            .ok_or(WorkerError::decode("inner_jwe_missing"))?;

        let peeked_kid = jose
            .peek_kid(jwe.as_str())
            .map_err(|_| WorkerError::decode("inner_jwe_header_invalid"))?;
        debug!("Peeked inner JWE kid: {:?}", peeked_kid);

        let (bytes, enc_option) = match peeked_kid.as_deref() {
            Some("session") => {
                let key = session_key.ok_or(WorkerError::decode("session_key_missing"))?;
                let bytes = jose
                    .jwe_decrypt(jwe.as_str(), jose_port::JweDecryptionKey::Session(key))
                    .map_err(|_| WorkerError::decode("decryption_failed"))?;
                (bytes, EncryptOption::Session)
            }
            Some("device") => {
                let bytes = jose
                    .jwe_decrypt(jwe.as_str(), jose_port::JweDecryptionKey::Device)
                    .map_err(|_| WorkerError::decode("decryption_failed"))?;
                (bytes, EncryptOption::Device)
            }
            _ => {
                error!("Unknown encryption option in JWE kid: {:?}", peeked_kid);
                return Err(WorkerError::decode("unknown_encryption_option"));
            }
        };

        let inner_request: InnerRequest =
            serde_json::from_slice(&bytes).map_err(|_| WorkerError::decode("decryption_failed"))?;

        if inner_request.request_type.encrypt_option() != enc_option {
            error!(
                "Encryption option mismatch for {:?}: expected {:?}, got {:?}",
                inner_request.request_type,
                inner_request.request_type.encrypt_option(),
                enc_option
            );
            return Err(WorkerError::decode("decryption_failed"));
        }

        Ok(inner_request)
    }
}

impl OuterResponse {
    pub fn sign(
        &self,
        jose: &dyn jose_port::JosePort,
    ) -> Result<TypedJws<OuterResponse>, WorkerError> {
        let sign_err = || WorkerError::encode("outer_response_sign_failed");

        let bytes = serde_json::to_vec(self).map_err(|e| {
            error!("Failed to serialize outer response: {:?}", e);
            sign_err()
        })?;

        let jws_str = jose.jws_sign(&bytes).map_err(|_| sign_err())?;

        Ok(TypedJws::new(jws_str))
    }
}

impl InnerResponse {
    pub fn encrypt(
        &self,
        jose: &dyn jose_port::JosePort,
        key: jose_port::JweEncryptionKey<'_>,
    ) -> Result<TypedJwe<InnerResponse>, WorkerError> {
        let enc_err = || WorkerError::encode("inner_response_encrypt_failed");

        let bytes = serde_json::to_vec(self).map_err(|e| {
            error!("Failed to serialize inner response: {:?}", e);
            enc_err()
        })?;

        let jwe_str = jose.jwe_encrypt(&bytes, key).map_err(|_| enc_err())?;

        Ok(TypedJwe::new(jwe_str))
    }
}
