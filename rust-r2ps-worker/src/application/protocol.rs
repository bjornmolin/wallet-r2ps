use crate::application::port::outgoing::jose_port;
use crate::application::port::outgoing::session_state_spi_port::SessionKey;
use crate::application::{OuterError, UpstreamError};
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
    ) -> Result<Self, UpstreamError> {
        let bytes = jose
            .jws_verify_device(jws, key)
            .map_err(|_| UpstreamError::OuterJwsInvalid)?;

        serde_json::from_slice(&bytes).map_err(|e| {
            error!("Failed to deserialize outer request: {:?}", e);
            UpstreamError::OuterJwsInvalid
        })
    }

    pub fn decrypt_inner(
        &self,
        jose: &dyn jose_port::JosePort,
        session_key: Option<&SessionKey>,
    ) -> Result<InnerRequest, OuterError> {
        let jwe = self.inner_jwe.as_ref().ok_or(OuterError::InnerJweMissing)?;

        let peeked_kid = jose
            .peek_kid(jwe.as_str())
            .map_err(|_| OuterError::InnerJweHeaderInvalid)?;
        debug!("Peeked inner JWE kid: {:?}", peeked_kid);

        let (bytes, enc_option) = match peeked_kid.as_deref() {
            Some("session") => {
                let key = session_key.ok_or(OuterError::SessionKeyMissing)?;
                let bytes = jose
                    .jwe_decrypt(jwe.as_str(), jose_port::JweDecryptionKey::Session(key))
                    .map_err(|_| OuterError::InnerJweDecryptFailed)?;
                (bytes, EncryptOption::Session)
            }
            Some("device") => {
                let bytes = jose
                    .jwe_decrypt(jwe.as_str(), jose_port::JweDecryptionKey::Device)
                    .map_err(|_| OuterError::InnerJweDecryptFailed)?;
                (bytes, EncryptOption::Device)
            }
            _ => {
                error!("Unknown encryption option in JWE kid: {:?}", peeked_kid);
                return Err(OuterError::UnknownEncryptionOption);
            }
        };

        let inner_request: InnerRequest =
            serde_json::from_slice(&bytes).map_err(|_| OuterError::InnerJweDecryptFailed)?;

        if inner_request.request_type.encrypt_option() != enc_option {
            error!(
                "Encryption option mismatch for {:?}: expected {:?}, got {:?}",
                inner_request.request_type,
                inner_request.request_type.encrypt_option(),
                enc_option
            );
            return Err(OuterError::InnerJweDecryptFailed);
        }

        Ok(inner_request)
    }
}

impl OuterResponse {
    pub fn sign(
        &self,
        jose: &dyn jose_port::JosePort,
    ) -> Result<TypedJws<OuterResponse>, UpstreamError> {
        let bytes = serde_json::to_vec(self).map_err(|e| {
            error!("Failed to serialize outer response: {:?}", e);
            UpstreamError::EncodeFailed("outer_response_sign_failed")
        })?;

        let jws_str = jose
            .jws_sign(&bytes)
            .map_err(|_| UpstreamError::EncodeFailed("outer_response_sign_failed"))?;

        Ok(TypedJws::new(jws_str))
    }
}

impl InnerResponse {
    pub fn encrypt(
        &self,
        jose: &dyn jose_port::JosePort,
        key: jose_port::JweEncryptionKey<'_>,
    ) -> Result<TypedJwe<InnerResponse>, UpstreamError> {
        let bytes = serde_json::to_vec(self).map_err(|e| {
            error!("Failed to serialize inner response: {:?}", e);
            UpstreamError::EncodeFailed("inner_response_encrypt_failed")
        })?;

        let jwe_str = jose
            .jwe_encrypt(&bytes, key)
            .map_err(|_| UpstreamError::EncodeFailed("inner_response_encrypt_failed"))?;

        Ok(TypedJwe::new(jwe_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::port::outgoing::jose_port::{
        JoseError, JosePort, JweDecryptionKey, JweEncryptionKey,
    };
    use crate::domain::{OperationId, SessionId};
    use rstest::rstest;

    /// Mock JosePort for testing decrypt_inner behavior
    struct MockJose {
        peek_kid_result: Option<String>,
        peek_kid_error: bool,
        decrypt_result: Vec<u8>,
        decrypt_error: bool,
    }

    impl JosePort for MockJose {
        fn jws_sign(&self, _payload: &[u8]) -> Result<String, JoseError> {
            unimplemented!()
        }

        fn jws_verify_server(&self, _jws: &str) -> Result<Vec<u8>, JoseError> {
            unimplemented!()
        }

        fn jws_verify_device(&self, _jws: &str, _key: &EcPublicJwk) -> Result<Vec<u8>, JoseError> {
            unimplemented!()
        }

        fn jwe_encrypt(
            &self,
            _payload: &[u8],
            _key: JweEncryptionKey,
        ) -> Result<String, JoseError> {
            unimplemented!()
        }

        fn jwe_decrypt(&self, _jwe: &str, _key: JweDecryptionKey) -> Result<Vec<u8>, JoseError> {
            if self.decrypt_error {
                Err(JoseError::DecryptError)
            } else {
                Ok(self.decrypt_result.clone())
            }
        }

        fn peek_kid(&self, _jwe: &str) -> Result<Option<String>, JoseError> {
            if self.peek_kid_error {
                Err(JoseError::InvalidKey)
            } else {
                Ok(self.peek_kid_result.clone())
            }
        }
    }

    fn create_inner_request_json(operation: OperationId) -> Vec<u8> {
        let inner_request = InnerRequest {
            version: 1,
            request_type: operation,
            request_counter: 42,
            data: Some("test_data".to_string()),
        };
        serde_json::to_vec(&inner_request).unwrap()
    }

    fn create_outer_request_with_jwe(jwe: Option<String>) -> OuterRequest {
        OuterRequest {
            version: 1,
            session_id: Some(SessionId::new()),
            context: "hsm".to_string(),
            inner_jwe: jwe.map(TypedJwe::new),
        }
    }

    #[test]
    fn test_decrypt_inner_missing_jwe() {
        let outer_request = create_outer_request_with_jwe(None);
        let jose = MockJose {
            peek_kid_result: Some("session".to_string()),
            peek_kid_error: false,
            decrypt_result: vec![],
            decrypt_error: false,
        };
        let session_key = SessionKey::new(vec![0u8; 32]);

        let result = outer_request.decrypt_inner(&jose, Some(&session_key));

        assert!(matches!(result, Err(OuterError::InnerJweMissing)));
    }

    #[test]
    fn test_decrypt_inner_invalid_jwe_header() {
        let outer_request = create_outer_request_with_jwe(Some("malformed.jwe".to_string()));
        let jose = MockJose {
            peek_kid_result: None,
            peek_kid_error: true,
            decrypt_result: vec![],
            decrypt_error: false,
        };
        let session_key = SessionKey::new(vec![0u8; 32]);

        let result = outer_request.decrypt_inner(&jose, Some(&session_key));

        assert!(matches!(result, Err(OuterError::InnerJweHeaderInvalid)));
    }

    #[test]
    fn test_decrypt_inner_session_key_missing() {
        let outer_request = create_outer_request_with_jwe(Some("valid.jwe".to_string()));
        let jose = MockJose {
            peek_kid_result: Some("session".to_string()),
            peek_kid_error: false,
            decrypt_result: vec![],
            decrypt_error: false,
        };

        let result = outer_request.decrypt_inner(&jose, None);

        assert!(matches!(result, Err(OuterError::SessionKeyMissing)));
    }

    #[rstest]
    #[case(Some("unknown".to_string()), "unknown kid value")]
    #[case(None, "missing kid")]
    fn test_decrypt_inner_unknown_encryption_option(
        #[case] kid: Option<String>,
        #[case] _description: &str,
    ) {
        let outer_request = create_outer_request_with_jwe(Some("valid.jwe".to_string()));
        let jose = MockJose {
            peek_kid_result: kid,
            peek_kid_error: false,
            decrypt_result: vec![],
            decrypt_error: false,
        };
        let session_key = SessionKey::new(vec![0u8; 32]);

        let result = outer_request.decrypt_inner(&jose, Some(&session_key));

        assert!(matches!(result, Err(OuterError::UnknownEncryptionOption)));
    }

    #[test]
    fn test_decrypt_inner_decryption_failed() {
        let outer_request = create_outer_request_with_jwe(Some("valid.jwe".to_string()));
        let jose = MockJose {
            peek_kid_result: Some("session".to_string()),
            peek_kid_error: false,
            decrypt_result: vec![],
            decrypt_error: true,
        };
        let session_key = SessionKey::new(vec![0u8; 32]);

        let result = outer_request.decrypt_inner(&jose, Some(&session_key));

        assert!(matches!(result, Err(OuterError::InnerJweDecryptFailed)));
    }

    #[test]
    fn test_decrypt_inner_invalid_json_after_decryption() {
        let outer_request = create_outer_request_with_jwe(Some("valid.jwe".to_string()));
        let jose = MockJose {
            peek_kid_result: Some("session".to_string()),
            peek_kid_error: false,
            decrypt_result: b"not valid json".to_vec(),
            decrypt_error: false,
        };
        let session_key = SessionKey::new(vec![0u8; 32]);

        let result = outer_request.decrypt_inner(&jose, Some(&session_key));

        assert!(matches!(result, Err(OuterError::InnerJweDecryptFailed)));
    }

    #[rstest]
    #[case(
        OperationId::AuthenticateStart,
        "session",
        true,
        "session for device operation"
    )]
    #[case(
        OperationId::RegisterStart,
        "session",
        true,
        "session for device operation (RegisterStart)"
    )]
    #[case(OperationId::HsmSign, "device", false, "device for session operation")]
    #[case(
        OperationId::HsmListKeys,
        "device",
        false,
        "device for session operation (HsmListKeys)"
    )]
    fn test_decrypt_inner_encryption_option_mismatch(
        #[case] operation: OperationId,
        #[case] kid: &str,
        #[case] needs_session_key: bool,
        #[case] _description: &str,
    ) {
        let inner_json = create_inner_request_json(operation);

        let outer_request = create_outer_request_with_jwe(Some("valid.jwe".to_string()));
        let jose = MockJose {
            peek_kid_result: Some(kid.to_string()),
            peek_kid_error: false,
            decrypt_result: inner_json,
            decrypt_error: false,
        };

        let session_key = SessionKey::new(vec![0u8; 32]);
        let session_key_ref = if needs_session_key {
            Some(&session_key)
        } else {
            None
        };

        let result = outer_request.decrypt_inner(&jose, session_key_ref);

        assert!(matches!(result, Err(OuterError::InnerJweDecryptFailed)));
    }

    #[rstest]
    #[case(OperationId::HsmListKeys, "session", true, "session encryption")]
    #[case(OperationId::HsmSign, "session", true, "session encryption (HsmSign)")]
    #[case(OperationId::RegisterStart, "device", false, "device encryption")]
    #[case(
        OperationId::AuthenticateStart,
        "device",
        false,
        "device encryption (AuthenticateStart)"
    )]
    fn test_decrypt_inner_success(
        #[case] operation: OperationId,
        #[case] kid: &str,
        #[case] needs_session_key: bool,
        #[case] _description: &str,
    ) {
        let inner_json = create_inner_request_json(operation);

        let outer_request = create_outer_request_with_jwe(Some("valid.jwe".to_string()));
        let jose = MockJose {
            peek_kid_result: Some(kid.to_string()),
            peek_kid_error: false,
            decrypt_result: inner_json,
            decrypt_error: false,
        };

        let session_key = SessionKey::new(vec![0u8; 32]);
        let session_key_ref = if needs_session_key {
            Some(&session_key)
        } else {
            None
        };

        let result = outer_request.decrypt_inner(&jose, session_key_ref);

        assert!(result.is_ok());
        let inner_request = result.unwrap();
        assert_eq!(inner_request.request_type, operation);
        assert_eq!(inner_request.version, 1);
        assert_eq!(inner_request.request_counter, 42);
    }
}
