use crate::application::helpers::debug_log_payload;
use crate::application::hsm_spi_port::HsmSpiPort;
use crate::application::pending_auth_spi_port::PendingAuthSpiPort;
use crate::application::session_key_spi_port::{SessionKey, SessionKeySpiPort};
use crate::application::{
    R2psRequestId, R2psRequestUseCase, R2psResponseSpiPort, load_pem_from_bas64_env,
};
use crate::define_byte_vector;
use crate::domain::value_objects::r2ps::{Claims, OuterRequest};
use crate::domain::{
    DefaultCipherSuite, DeviceHsmState, EncryptOption, InnerJwe, R2psRequestError, R2psRequestJws,
    R2psResponseJws, R2psServerConfig, ServiceRequestError, to_iso8601_duration,
};
use crate::infrastructure::ec_jwk_to_pem;
use argon2::password_hash::rand_core::OsRng;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use josekit::jwe;
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
use std::time::Duration;
use tracing::{debug, error, info};

define_byte_vector!(DecryptedData);

use super::operations::{OperationContext, OperationDispatcher};

pub struct R2psService {
    r2ps_response_spi_port: Arc<dyn R2psResponseSpiPort + Send + Sync>,
    r2ps_server_config: R2psServerConfig,
    session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
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
            server_setup,
            session_key_spi_port.clone(),
            hsm_spi_port,
            pending_auth_spi_port,
        );

        Self {
            r2ps_response_spi_port,
            r2ps_server_config: R2psServerConfig {
                server_public_key,
                server_private_key,
            },
            operation_dispatcher,
            session_key_spi_port,
        }
    }

    fn decrypt_service_data(
        &self,
        inner_jwe: Option<&InnerJwe>,
        enc_option: EncryptOption,
        session_key: Option<&SessionKey>,
    ) -> Result<Option<DecryptedData>, ServiceRequestError> {
        inner_jwe
            .map(|jwe| {
                jwe.decrypt(
                    enc_option,
                    &self.r2ps_server_config.server_private_key,
                    session_key,
                )
                .map(DecryptedData::new)
                .map_err(|e| {
                    error!("Could not decrypt service data: {:?}", e);
                    ServiceRequestError::JweError
                })
            })
            .transpose()
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
        let outer_request =
            decode_outer_request_jws(r2ps_request_jws.outer_request_jws, &client_public_key)
                .map_err(|_| R2psRequestError::OuterJwsError)?;

        info!(
            "Received request id {}, wallet_id {}",
            r2ps_request_jws.request_id, r2ps_request_jws.wallet_id
        );

        // TODO: Use JOSE 'aud' (audience) claim in the validation done inside decode_service_request_jws() instead
        if outer_request.context != "hsm" {
            return Err(R2psRequestError::UnsupportedContext);
        }

        let session_key = outer_request
            .pake_session_id
            .as_ref()
            .and_then(|id| self.session_key_spi_port.get(id));

        let inner_request_json = self
            .decrypt_service_data(
                outer_request.inner_jwe.as_ref(),
                outer_request.service_type.encrypt_option(),
                session_key.as_ref(),
            )
            .map_err(R2psRequestError::ServiceError)?;

        if let Some(ref data) = inner_request_json {
            debug_log_payload(data.as_ref(), "Decrypted inner request");
        }

        info!(
            "Processing request id {} of type {:?}",
            r2ps_request_jws.request_id, outer_request.service_type
        );

        let operation = OperationContext {
            request_id: r2ps_request_jws.request_id.clone(),
            wallet_id: r2ps_request_jws.wallet_id.clone(),
            device_id: r2ps_request_jws.device_id.clone(),
            state: state,
            outer_request: outer_request.clone(),
            inner_request_json,
        };

        let r2ps_response = self
            .operation_dispatcher
            .dispatch(operation)
            .map_err(R2psRequestError::ServiceError)?;

        let enc_option = outer_request.service_type.encrypt_option().clone();
        debug!(
            "Response to {:?} will be encrypted with {:?} encryption",
            outer_request.service_type, enc_option
        );

        let response_payload = r2ps_response
            .payload
            .serialize()
            .map_err(|_| R2psRequestError::EncryptionError)?;

        debug_log_payload(&response_payload, "Response payload before encryption");

        let new_state_jws = encode_state_jws(&r2ps_response.state, None)
            .map_err(|_| R2psRequestError::OuterJwsError)?;
        let jwe = match enc_option {
            EncryptOption::User => {
                let session_key = session_key
                    .clone()
                    .ok_or(R2psRequestError::UnknownSession)?;
                InnerJwe::encrypt(&response_payload, session_key.to_bytes())
                    .map_err(|_| R2psRequestError::EncryptionError)?
                    .into_string()
            }
            EncryptOption::Device => encrypt_with_ec_pem(
                &response_payload,
                &ec_jwk_to_pem(&r2ps_response.state.client_public_key)
                    .map_err(|_| R2psRequestError::EncryptionError)?,
            )
            .map_err(|_| R2psRequestError::EncryptionError)?,
        };

        let ttl = outer_request
            .pake_session_id
            .as_ref()
            .and_then(|id| self.session_key_spi_port.get_remaining_ttl(id));

        let jws = jws_with_jwk(&jwe, outer_request.nonce, enc_option, ttl)
            .map_err(|_| R2psRequestError::OuterJwsError)?;

        debug!(
            "JWS response payload on {:?} {}",
            outer_request.service_type, jws
        );

        let r2ps_response_jws = R2psResponseJws {
            request_id: r2ps_request_jws.request_id.clone(),
            wallet_id: r2ps_request_jws.wallet_id.clone(),
            device_id: r2ps_request_jws.device_id.clone(),
            http_status: 200,
            state_jws: new_state_jws,
            service_response_jws: jws,
        };

        info!("Responding to request id {}", r2ps_request_jws.request_id);

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

fn jws_with_jwk(
    data: &str,
    nonce: Option<String>,
    enc: EncryptOption,
    ttl: Option<Duration>,
) -> Result<String, ServiceRequestError> {
    let claims = Claims {
        ver: "1.0".to_string(),
        nonce: nonce.unwrap().to_string(),
        expires_in: ttl.map(to_iso8601_duration),
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

    Ok(token)
}

fn encode_state_jws(
    state: &DeviceHsmState,
    _nonce: Option<String>,
) -> Result<String, ServiceRequestError> {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JOSE".to_string());

    let private_key_pem = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/NIIdRGO+qU2bjxT
tnZuC45gAg6wZ0UGe9nCeM7wc0yhRANCAASnNDG5ct6I/LOK0wpBtRJU4PcDFv6X
0upWOzkadhqcDWTgCYxROhakhPDldczjw0+FuAyGgzQVSng5DbrP+8JB
-----END PRIVATE KEY-----"#;

    let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes()).unwrap();

    let token = encode(&header, &state, &encoding_key).unwrap();

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
            validation.validate_exp = false;
            validation.required_spec_claims.clear();
            validation.insecure_disable_signature_validation();
            match decode::<DeviceHsmState>(&state_jws, &decoding_key, &validation) {
                Ok(service_request_claims) => {
                    debug!("decoded state JWS: {:#?}", service_request_claims);
                    Ok(service_request_claims.claims)
                }
                Err(error) => {
                    error!("Error decoding state JWS: {:#?}", error);
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
fn decode_outer_request_jws(
    outer_request_jws: String,
    client_public_key: &Pem,
) -> Result<OuterRequest, ServiceRequestError> {
    let pem_string = pem::encode(client_public_key);

    match DecodingKey::from_ec_pem(pem_string.as_bytes()) {
        Ok(decoding_key) => {
            let mut validation = Validation::new(Algorithm::ES256);
            validation.validate_exp = false;
            validation.required_spec_claims.clear();
            match decode::<OuterRequest>(&outer_request_jws, &decoding_key, &validation) {
                Ok(service_request_claims) => {
                    debug!("decoded outer request JWS: {:#?}", service_request_claims);
                    Ok(service_request_claims.claims)
                }
                Err(error) => {
                    error!("Error decoding outer request JWS: {:#?}", error);
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
