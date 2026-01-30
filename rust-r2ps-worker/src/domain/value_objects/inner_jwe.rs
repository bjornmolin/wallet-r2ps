use josekit::jwe;
use josekit::jwe::alg::direct::DirectJweAlgorithm;
use josekit::jwe::{ECDH_ES, JweHeader};
use pem::Pem;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::application::session_key_spi_port::SessionKey;
use crate::domain::{EncryptOption, ServiceRequestError};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InnerJwe(String);

impl InnerJwe {
    pub fn new(jwe: String) -> Self {
        Self(jwe)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn decrypt(
        &self,
        enc_option: EncryptOption,
        server_private_key: &Pem,
        session_key: Option<&SessionKey>,
    ) -> Result<Vec<u8>, ServiceRequestError> {
        match enc_option {
            EncryptOption::User => {
                let key = session_key.ok_or(ServiceRequestError::UnknownSession)?;
                self.decrypt_with_aes(key)
            }
            EncryptOption::Device => self.decrypt_with_ec_pem(server_private_key),
        }
    }

    fn decrypt_with_ec_pem(&self, private_key: &Pem) -> Result<Vec<u8>, ServiceRequestError> {
        let decrypter = ECDH_ES.decrypter_from_pem(pem::encode(private_key))?;
        let (payload, header) = jwe::deserialize_compact(&self.0, &decrypter)?;

        debug!("decrypted inner JWE header: {:#?}", header);

        Ok(payload)
    }

    fn decrypt_with_aes(&self, session_key: &SessionKey) -> Result<Vec<u8>, ServiceRequestError> {
        debug!("decrypt inner JWE with session key {:02X?}", session_key);

        let decrypter = DirectJweAlgorithm::Dir
            .decrypter_from_bytes(session_key.as_ref())
            .map_err(|e| {
                error!("Failed to create decrypter: {:?}", e);
                ServiceRequestError::JweError
            })?;

        let (payload, header) = jwe::deserialize_compact(&self.0, &decrypter).map_err(|e| {
            error!("Failed to decrypt: {:?}", e);
            ServiceRequestError::JweError
        })?;

        debug!("decrypted inner JWE header: {:#?}", header);

        Ok(payload)
    }

    pub fn encrypt(payload: &[u8], session_key: &[u8]) -> Result<Self, ServiceRequestError> {
        let mut header = JweHeader::new();
        header.set_algorithm("dir");
        header.set_content_encryption("A256GCM");

        let encrypter = DirectJweAlgorithm::Dir
            .encrypter_from_bytes(session_key)
            .map_err(|e| {
                error!("Failed to create encrypter: {:?}", e);
                ServiceRequestError::Unknown
            })?;

        let jwe = jwe::serialize_compact(payload, &header, &encrypter).map_err(|e| {
            error!("Failed to encrypt: {:?}", e);
            ServiceRequestError::Unknown
        })?;

        Ok(Self(jwe))
    }
}
