use crate::application::helpers::ByteVector;
use crate::application::hsm_spi_port::HsmSpiPort;
use crate::application::pending_auth_spi_port::PendingAuthSpiPort;
use crate::application::session_key_spi_port::{SessionKey, SessionKeySpiPort};
use crate::application::{
    R2psRequestId, R2psRequestUseCase, R2psResponseSpiPort, load_pem_from_bas64_env,
};
use crate::define_byte_vector;
use crate::domain::value_objects::r2ps::{Claims, PakeResponsePayload, ServiceRequest};
use crate::domain::{
    DefaultCipherSuite, DeviceHsmState, EncryptOption, R2psRequest, R2psRequestError,
    R2psRequestJws, R2psResponse, R2psResponseJws, R2psServerConfig, ServiceRequestError,
};
use crate::infrastructure::ec_jwk_to_pem;
use argon2::password_hash::rand_core::OsRng;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use base64::prelude::BASE64_STANDARD;
use chrono::Utc;
use josekit::jwe;
use josekit::jwe::alg::direct::DirectJweAlgorithm;
use josekit::jwe::{ECDH_ES, JweHeader};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use opaque_ke::ServerSetup;
use opaque_ke::keypair::{KeyPair, PrivateKey, PublicKey};
use p256::NistP256;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use pem::Pem;
use rdkafka::message::ToBytes;
use std::sync::Arc;
use tracing::{debug, error, info};

define_byte_vector!(DecryptedData);

use super::operations::OperationDispatcher;

pub struct R2psService {
    r2ps_response_spi_port: Arc<dyn R2psResponseSpiPort + Send + Sync>,
    hsm_spi_port: Arc<dyn HsmSpiPort + Send + Sync>,
    opaque_server_setup: ServerSetup<DefaultCipherSuite>,
    r2ps_server_config: R2psServerConfig,
    session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
    pending_auth_spi_port: Arc<dyn PendingAuthSpiPort + Send + Sync>,
    // Operation dispatcher
    operation_dispatcher: OperationDispatcher,
}

impl R2psService {
    pub fn new(
        r2ps_response_spi_port: Arc<dyn R2psResponseSpiPort + Send + Sync>,
        session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
        hsm_spi_port: Arc<dyn HsmSpiPort + Send + Sync>,
        pending_auth_spi_port: Arc<dyn PendingAuthSpiPort + Send + Sync>,
    ) -> Self {
        let server_public_key =
            load_pem_from_bas64_env("SERVER_PUBLIC_KEY").expect("Failed to load SERVER_PUBLIC_KEY");
        let server_private_key = load_pem_from_bas64_env("SERVER_PRIVATE_KEY")
            .expect("Failed to load SERVER_PRIVATE_KEY");
        let server_setup =
            create_server_setup(&server_private_key).expect("Failed to create opaque server setup");

        let operation_dispatcher = OperationDispatcher::from_dependencies(
            server_setup.clone(),
            session_key_spi_port.clone(),
            hsm_spi_port.clone(),
            pending_auth_spi_port.clone(),
        );

        Self {
            r2ps_response_spi_port,
            hsm_spi_port: hsm_spi_port.clone(),
            r2ps_server_config: R2psServerConfig {
                server_public_key,
                server_private_key,
            },
            operation_dispatcher,
            opaque_server_setup: server_setup,
            session_key_spi_port,
            pending_auth_spi_port,
        }
    }

    pub fn encrypt_with_aes(
        &self,
        payload: &[u8],
        session_key: &SessionKey,
    ) -> Result<String, ServiceRequestError> {
        let mut header = JweHeader::new();
        header.set_algorithm("dir");
        header.set_content_encryption("A256GCM");

        let encrypter = DirectJweAlgorithm::Dir
            .encrypter_from_bytes(session_key.to_bytes())
            .map_err(|e| {
                error!("Failed to create encrypter: {:?}", e);
                ServiceRequestError::Unknown
            })?;

        jwe::serialize_compact(payload, &header, &encrypter).map_err(|e| {
            error!("Failed to encrypt: {:?}", e);
            ServiceRequestError::Unknown
        })
    }
    pub fn decrypt_jwe(
        &self,
        encrypted_payload: &str,
        session_key: &SessionKey,
    ) -> Result<DecryptedData, Box<dyn std::error::Error>> {
        match BASE64_STANDARD.decode(encrypted_payload) {
            Ok(data) => {
                // Cast to ByteVector for better debug logging. Remove casting if/when logging is removed.
                // TODO: Only log the bytes if it can't be decoded to UTF-8 (in which case it will be logged as UTF-8)
                let vec = ByteVector::new(data);
                info!("decoded service_data hex: {:02X?}", &vec);
                match String::from_utf8(vec.to_vec()) {
                    Ok(decoded_string) => {
                        info!("decoded service_data utf8: {}", decoded_string);
                        debug!("decrypt with session key {:02X?}", session_key);
                        let decrypter =
                            DirectJweAlgorithm::Dir.decrypter_from_bytes(session_key.to_bytes())?;
                        let (payload, _header) =
                            josekit::jwe::deserialize_compact(&decoded_string, &decrypter)?;
                        Ok(DecryptedData::new(payload))
                    }
                    Err(_) => Err(Box::new(std::io::Error::other("Failed to decode UTF-8"))),
                }
            }
            Err(_) => Err(Box::new(std::io::Error::other("Failed to decode base64"))),
        }
    }

    fn decrypt_service_data(
        &self,
        service_request: &ServiceRequest,
        session_key: Option<&SessionKey>,
    ) -> Result<DecryptedData, ServiceRequestError> {
        let decrypted_service_data = match service_request.service_type.encrypt_option() {
            EncryptOption::User => {
                let session_key = session_key
                    .clone()
                    .ok_or(R2psRequestError::UnknownSession)
                    .map_err(|_| ServiceRequestError::UnknownSession)?;

                self.decrypt_jwe(
                    &service_request
                        .clone()
                        .service_data
                        .ok_or(ServiceRequestError::Unknown)?, // TODO
                    &session_key,
                )
                .map_err(|_| ServiceRequestError::JweError)?
            }
            EncryptOption::Device => decrypt_service_data_jwe(
                &service_request,
                &self.r2ps_server_config.server_private_key,
            )
            .map_err(|e| {
                error!("Could not decrypt service data: {:?}", e);
                ServiceRequestError::JweError
            })?,
        };
        Ok(decrypted_service_data)
    }
}

impl R2psRequestUseCase for R2psService {
    fn execute(&self, r2ps_request_jws: R2psRequestJws) -> Result<R2psRequestId, R2psRequestError> {
        let state = decode_state_jws(
            r2ps_request_jws.state_jws,
            &self.r2ps_server_config.server_public_key,
        )
        .map_err(|_| R2psRequestError::InvalidState)?;

        let client_public_key = ec_jwk_to_pem(&state.client_public_key).map_err(|_| {
            R2psRequestError::ServiceError(ServiceRequestError::InvalidClientPublicKey)
        })?;
        let service_request =
            decode_service_request_jws(r2ps_request_jws.service_request_jws, &client_public_key)
                .map_err(|_| R2psRequestError::JwsError)?;

        debug!("DECODED JWS {:?}", service_request);

        if service_request.context != "hsm" {
            return Err(R2psRequestError::UnsupportedContext);
        }

        if let Some(pake_session_id) = &service_request.pake_session_id {
            debug!("pake_session_id: {:?}", pake_session_id);
        }

        let session_key = service_request
            .pake_session_id
            .as_ref()
            .and_then(|id| self.session_key_spi_port.get(id));

        let decrypted_service_data = if service_request.service_data.is_some() {
            Some(
                self.decrypt_service_data(&service_request, session_key.as_ref())
                    .map_err(R2psRequestError::ServiceError)?,
            )
        } else {
            None
        };

        let r2ps_response = self
            .operation_dispatcher
            .dispatch(
                R2psRequest {
                    request_id: r2ps_request_jws.request_id.clone(),
                    wallet_id: r2ps_request_jws.wallet_id.clone(),
                    device_id: r2ps_request_jws.device_id.clone(),
                    state: state.clone(),
                    service_request: service_request.clone(),
                },
                decrypted_service_data,
            )
            .map_err(R2psRequestError::ServiceError)?;

        let enc_option = service_request.service_type.encrypt_option();
        info!(
            "Response to {:?} will be encrypted with {:?} encryption",
            service_request.service_type, enc_option
        );

        let response_payload = r2ps_response
            .payload
            .serialize()
            .map_err(|_| R2psRequestError::EncryptionError)?;

        match response_payload.first() == Some(&b'{') && response_payload.last() == Some(&b'}') {
            true => debug!(
                "JSON Response payload before encryption: {}",
                String::from_utf8_lossy(&response_payload)
            ),
            false => debug!(
                "Response payload before encryption (hex): {:02X?}",
                r2ps_response
            ),
        }

        let new_state_jws =
            encode_state_jws(&r2ps_response.state, None).map_err(|_| R2psRequestError::JwsError)?;
        let jwe = match enc_option {
            EncryptOption::User => {
                let session_key = session_key
                    .clone()
                    .ok_or(R2psRequestError::UnknownSession)?;
                self.encrypt_with_aes(&response_payload, &session_key)
                    .map_err(|_| R2psRequestError::EncryptionError)?
            }
            EncryptOption::Device => encrypt_with_ec_pem(
                &response_payload,
                &ec_jwk_to_pem(&state.client_public_key)
                    .map_err(|_| R2psRequestError::EncryptionError)?,
            )
            .map_err(|_| R2psRequestError::EncryptionError)?,
        };

        let jws = jws_with_jwk(
            &jwe,
            service_request.nonce,
            service_request.service_type.encrypt_option(),
        )
        .map_err(|_| R2psRequestError::JwsError)?;

        info!(
            "JWS response payload on {:?} {}",
            service_request.service_type, jws
        );

        let r2ps_response_jws = R2psResponseJws {
            request_id: r2ps_request_jws.request_id.clone(),
            wallet_id: r2ps_request_jws.wallet_id.clone(),
            device_id: r2ps_request_jws.device_id.clone(),
            http_status: 200,
            state_jws: new_state_jws,
            service_response_jws: jws,
        };

        self.r2ps_response_spi_port
            .send(r2ps_response_jws.clone())
            .map(|_| r2ps_response_jws.request_id.clone())
            .map_err(|_| R2psRequestError::ConnectionError)
    }
}

fn create_server_setup(
    server_private_key_pem: &Pem,
) -> Result<ServerSetup<DefaultCipherSuite>, String> {
    let secret_key = p256::SecretKey::from_pkcs8_pem(&pem::encode(server_private_key_pem))
        .map_err(|e| format!("Failed to parse P-256 private key: {:?}", e))?;

    let keypair = KeyPair::new(
        PrivateKey::<NistP256>::deserialize(&secret_key.to_bytes())
            .map_err(|e| format!("Failed to deserialize private key: {:?}", e))?,
        PublicKey::<NistP256>::deserialize(
            secret_key
                .public_key()
                .as_affine()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .map_err(|e| format!("Failed to deserialize public key: {:?}", e))?,
    );

    Ok(ServerSetup::<DefaultCipherSuite>::new_with_key_pair(
        &mut OsRng, keypair,
    ))
}

fn encrypt_with_ec_pem(
    payload: &[u8],
    client_public_key: &Pem,
) -> Result<String, ServiceRequestError> {
    let mut header = JweHeader::new();
    header.set_algorithm("ECDH-ES");
    header.set_content_encryption("A256GCM");

    let pem_string = pem::encode(client_public_key);
    match ECDH_ES.encrypter_from_pem(&pem_string) {
        Ok(encrypter) => match jwe::serialize_compact(payload, &header, &encrypter) {
            Ok(payload_bytes) => Ok(payload_bytes),
            Err(e) => {
                error!("********1 {:?}", e);
                Err(ServiceRequestError::Unknown)
            }
        },
        Err(e) => {
            error!("********2 {:?}", e);
            Err(ServiceRequestError::Unknown)
        }
    }
}

// todo remove logging of sensitive info
pub fn decrypt_service_data_jwe(
    service_request: &ServiceRequest,
    server_private_key: &Pem,
) -> Result<DecryptedData, ServiceRequestError> {
    let service_data = service_request
        .service_data
        .as_ref()
        .ok_or(ServiceRequestError::InvalidServiceRequestFormat)?;

    info!("SERVICE DATA ******* {} ", service_data);

    let decoded_string = String::from_utf8(BASE64_STANDARD.decode(service_data)?)?;
    let decrypter = ECDH_ES.decrypter_from_pem(pem::encode(server_private_key))?;
    let (payload, _) = jwe::deserialize_compact(&decoded_string, &decrypter)?;

    info!("decrypted JWS payload: {}", hex::encode(&payload));

    if let Ok(text) = String::from_utf8(payload.clone()) {
        info!("decrypted JWS payload: {}", text);
    }

    Ok(DecryptedData::new(payload))
}

fn encrypt_with_ec_jwk(
    payload: &PakeResponsePayload,
    ec_public_jwk: &josekit::jwk::Jwk,
) -> Result<String, Box<dyn std::error::Error>> {
    let payload_bytes = serde_json::to_vec(payload)?;

    let mut header = JweHeader::new();
    header.set_algorithm("ECDH-ES");
    header.set_content_encryption("A256GCM");

    let encrypter = ECDH_ES.encrypter_from_jwk(ec_public_jwk)?;
    let jwe = josekit::jwe::serialize_compact(&payload_bytes, &header, &encrypter)?;

    Ok(jwe)
}

impl EncryptOption {
    fn as_str(&self) -> &'static str {
        match self {
            EncryptOption::User => "user",
            EncryptOption::Device => "device",
        }
    }
}

fn jws_with_jwk(
    data: &str,
    nonce: Option<String>,
    enc: EncryptOption,
) -> Result<String, ServiceRequestError> {
    let now = Utc::now(); // Get duration in ms since Unix epoch
    let claims = Claims {
        ver: "1.0".to_string(),
        nonce: nonce.unwrap().to_string(),
        iat: now.timestamp(),
        enc: enc.as_str().to_string(),
        data: STANDARD.encode(data),
    };
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JOSE".to_string());

    let private_key_pem = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/NIIdRGO+qU2bjxT
tnZuC45gAg6wZ0UGe9nCeM7wc0yhRANCAASnNDG5ct6I/LOK0wpBtRJU4PcDFv6X
0upWOzkadhqcDWTgCYxROhakhPDldczjw0+FuAyGgzQVSng5DbrP+8JB
-----END PRIVATE KEY-----"#;

    let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes()).unwrap();

    let token = encode(&header, &claims, &encoding_key).unwrap();

    println!("JWS Token: {}", token);
    Ok(token)
}

fn encode_state_jws(
    state: &DeviceHsmState,
    nonce: Option<String>,
) -> Result<String, ServiceRequestError> {
    let now = Utc::now(); // Get duration in ms since Unix epoch

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JOSE".to_string());

    let private_key_pem = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/NIIdRGO+qU2bjxT
tnZuC45gAg6wZ0UGe9nCeM7wc0yhRANCAASnNDG5ct6I/LOK0wpBtRJU4PcDFv6X
0upWOzkadhqcDWTgCYxROhakhPDldczjw0+FuAyGgzQVSng5DbrP+8JB
-----END PRIVATE KEY-----"#;

    let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes()).unwrap();

    let token = encode(&header, &state, &encoding_key).unwrap();

    println!("JWS Token: {}", token);
    Ok(token)
}

fn decode_state_jws(
    state_jws: String,
    public_key: &Pem,
) -> Result<DeviceHsmState, ServiceRequestError> {
    let pem_string = pem::encode(public_key);

    match DecodingKey::from_ec_pem(pem_string.as_bytes()) {
        Ok(decoding_key) => {
            let mut validation = Validation::new(Algorithm::ES256);
            validation.validate_exp = false; // TODO: signera om state regelbundet?
            validation.required_spec_claims.clear();
            validation.insecure_disable_signature_validation();
            match decode::<DeviceHsmState>(&state_jws, &decoding_key, &validation) {
                Ok(service_request_claims) => {
                    info!("decoded claims: {:?}", service_request_claims);
                    Ok(service_request_claims.claims)
                }
                Err(error) => {
                    error!("Error decoding jws claims: {:?}", error);
                    Err(ServiceRequestError::JwsError)
                }
            }
        }
        Err(error) => {
            error!("invalid client public key: {:?}", error);
            Err(ServiceRequestError::InvalidClientPublicKey)
        }
    }
}
fn decode_service_request_jws(
    service_request_jws: String,
    client_public_key: &Pem,
) -> Result<ServiceRequest, ServiceRequestError> {
    let pem_string = pem::encode(client_public_key);

    match DecodingKey::from_ec_pem(pem_string.as_bytes()) {
        Ok(decoding_key) => {
            let mut validation = Validation::new(Algorithm::ES256);
            validation.validate_exp = false; // TODO kolla om vi ska validera
            validation.required_spec_claims.clear();
            match decode::<ServiceRequest>(&service_request_jws, &decoding_key, &validation) {
                Ok(service_request_claims) => {
                    info!("decoded claims: {:?}", service_request_claims);
                    Ok(service_request_claims.claims)
                }
                Err(error) => {
                    error!("Error decoding jws claims: {:?}", error);
                    Err(ServiceRequestError::JwsError)
                }
            }
        }
        Err(error) => {
            error!("invalid client public key: {:?}", error);
            Err(ServiceRequestError::InvalidClientPublicKey)
        }
    }
}
