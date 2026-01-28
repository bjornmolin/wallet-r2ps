use super::ServiceOperation;
use crate::application::pending_auth_spi_port::{LoginSession, PendingAuthSpiPort};
use crate::application::service::r2ps_service::DecryptedData;
use crate::application::session_key_spi_port::{SessionKey, SessionKeySpiPort};
use crate::domain::value_objects::r2ps::{PakeRequestPayload, PakeResponsePayload};
use crate::domain::{
    DefaultCipherSuite, DeviceHsmState, PakeState, R2psRequest, R2psResponse, ServiceRequestError,
    ServiceResponse, to_iso8601_duration,
};
use argon2::password_hash::rand_core::OsRng;
use base64::Engine;
use base64::engine::general_purpose;
use base64::prelude::BASE64_STANDARD;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

pub struct AuthenticateOperation {
    opaque_server_setup: ServerSetup<DefaultCipherSuite>,
    session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
    pending_auth_spi_port: Arc<dyn PendingAuthSpiPort + Send + Sync>,
}

impl AuthenticateOperation {
    pub fn new(
        opaque_server_setup: ServerSetup<DefaultCipherSuite>,
        session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
        pending_auth_spi_port: Arc<dyn PendingAuthSpiPort + Send + Sync>,
    ) -> Self {
        Self {
            opaque_server_setup,
            session_key_spi_port,
            pending_auth_spi_port,
        }
    }
}

impl ServiceOperation for AuthenticateOperation {
    fn execute(
        &self,
        r2ps_request: R2psRequest,
        decrypted_service_data: Option<DecryptedData>,
    ) -> Result<R2psResponse, ServiceRequestError> {
        let start = Instant::now();
        let data =
            decrypted_service_data.ok_or(ServiceRequestError::InvalidServiceRequestFormat)?;
        let pake_payload = PakeRequestPayload::deserialize(data.to_vec()).map_err(|e| {
            warn!("error decoding pake request: {:?}", e);
            ServiceRequestError::InvalidPakeRequestPayload
        })?;

        info!(
            "deserialized pake payload authenticate request data: {}",
            pake_payload.request_data
        );

        let decoded_request_data: Vec<u8> = general_purpose::STANDARD
            .decode(pake_payload.request_data)
            .map_err(|e| {
                warn!("error base64 decoding pake authenticate request: {:?}", e);
                ServiceRequestError::InvalidPakeRequestPayload
            })?;

        match pake_payload.state {
            PakeState::Evaluate => {
                let password_file_serialized = r2ps_request
                    .state
                    .password_file
                    .ok_or(ServiceRequestError::UnknownClient)?;
                let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(
                    &password_file_serialized,
                )
                .map_err(|e| {
                    warn!("error decoding pake request: {:?}", e);
                    ServiceRequestError::InvalidSerializedPasswordFile
                })?;
                let credential_request = CredentialRequest::deserialize(&decoded_request_data)
                    .map_err(|e| {
                        warn!("error decoding pake request: {:?}", e);
                        ServiceRequestError::InvalidAuthenticateRequest
                    })?;

                let mut server_rng = OsRng;
                let context = "RPS-Ops".as_bytes();
                let client = r2ps_request.device_id.as_bytes();
                let server = "https://cloud-wallet.digg.se/rhsm".as_bytes();

                info!(
                    "OPAQUE context: '{}' hex: {}",
                    String::from_utf8_lossy(context),
                    hex::encode(context)
                );
                info!(
                    "OPAQUE client: '{}' hex: {}",
                    String::from_utf8_lossy(client),
                    hex::encode(client)
                );
                info!(
                    "OPAQUE server: '{}' hex: {}",
                    String::from_utf8_lossy(server),
                    hex::encode(server)
                );

                let server_login_parameters = ServerLoginParameters {
                    context: Some(context),
                    identifiers: Identifiers {
                        client: Some(client),
                        server: Some(server),
                    },
                };

                let server_login_start_result = ServerLogin::start(
                    &mut server_rng,
                    &self.opaque_server_setup,
                    Some(password_file),
                    credential_request,
                    r2ps_request.device_id.as_bytes(),
                    server_login_parameters,
                )
                .map_err(|e| {
                    warn!("error decoding pake request: {:?}", e);
                    ServiceRequestError::ServerLoginStartFailed
                })?;

                let credential_response_bytes = server_login_start_result.message.serialize();
                let pake_session_id = r2ps_request
                    .service_request
                    .pake_session_id
                    .clone()
                    .unwrap_or(Uuid::new_v4().to_string());

                self.pending_auth_spi_port.store_pending_auth(
                    pake_session_id.as_str(),
                    &Arc::new(LoginSession::new(server_login_start_result.state)),
                );

                let pake_response = PakeResponsePayload {
                    pake_session_id: Some(pake_session_id),
                    task: None,
                    response_data: Some(BASE64_STANDARD.encode(credential_response_bytes)),
                    message: None,
                    expires_in: None,
                };

                let elapsed = start.elapsed();
                info!("AUTH evaluate time: {} ns", elapsed.as_nanos());

                Ok(R2psResponse {
                    state: r2ps_request.state.clone(),
                    payload: ServiceResponse::Pake(pake_response),
                })
            }
            PakeState::Finalize => {
                let session = self
                    .pending_auth_spi_port
                    .get_pending_auth(
                        r2ps_request
                            .service_request
                            .pake_session_id
                            .clone()
                            .ok_or(ServiceRequestError::UnknownSession)?
                            .as_str(),
                    )
                    .ok_or(ServiceRequestError::InvalidAuthenticateRequest)?;

                let context = "RPS-Ops".as_bytes();
                let client = r2ps_request.device_id.as_bytes();
                let server = "https://cloud-wallet.digg.se/rhsm".as_bytes();
                let server_login_parameters = ServerLoginParameters {
                    context: Some(context),
                    identifiers: Identifiers {
                        client: Some(client),
                        server: Some(server),
                    },
                };

                let server_login = session
                    .take()
                    .ok_or(ServiceRequestError::InvalidAuthenticateRequest)?;
                let result = server_login
                    .finish(
                        CredentialFinalization::deserialize(&decoded_request_data)
                            .map_err(|_| ServiceRequestError::InvalidAuthenticateRequest)?,
                        server_login_parameters,
                    )
                    .map_err(|e| {
                        warn!("could not finish auth request request: {:?}", e);
                        ServiceRequestError::ServerLoginFinishFailed
                    })?;

                info!("SESSION KEY: {:X}", result.session_key);

                let pake_session_id = r2ps_request
                    .service_request
                    .pake_session_id
                    .clone()
                    .ok_or(ServiceRequestError::UnknownSession)?;

                let session_remaining_ttl = self
                    .session_key_spi_port
                    .store(
                        pake_session_id.as_str(),
                        SessionKey::new(result.session_key.to_vec()),
                    )
                    .map_err(|_| ServiceRequestError::InternalServerError)?;

                let msg = br#"{"msg":"OK"}"#.to_vec();
                let pake_response = PakeResponsePayload {
                    pake_session_id: r2ps_request.service_request.pake_session_id.clone(),
                    task: None,
                    response_data: Some(BASE64_STANDARD.encode(&msg)),
                    message: None,
                    expires_in: Some(to_iso8601_duration(session_remaining_ttl)),
                };

                let elapsed = start.elapsed();
                info!("AUTH finalize time: {} ns", elapsed.as_nanos());

                Ok(R2psResponse {
                    state: r2ps_request.state.clone(),
                    payload: ServiceResponse::Pake(pake_response),
                })
            }
        }
    }
}

pub struct PinRegistrationOperation {
    opaque_server_setup: ServerSetup<DefaultCipherSuite>,
}

impl PinRegistrationOperation {
    pub fn new(opaque_server_setup: ServerSetup<DefaultCipherSuite>) -> Self {
        Self {
            opaque_server_setup,
        }
    }
}

impl ServiceOperation for PinRegistrationOperation {
    fn execute(
        &self,
        r2ps_request: R2psRequest,
        decrypted_service_data: Option<DecryptedData>,
    ) -> Result<R2psResponse, ServiceRequestError> {
        let data =
            decrypted_service_data.ok_or(ServiceRequestError::InvalidServiceRequestFormat)?;
        let pake_payload = PakeRequestPayload::deserialize(data.to_vec()).map_err(|e| {
            warn!("error decoding pake registration request: {:?}", e);
            ServiceRequestError::InvalidPakeRequestPayload
        })?;

        info!(
            "deserialized pake payload req={}",
            pake_payload.request_data
        );

        let decoded_request_data: Vec<u8> = general_purpose::STANDARD
            .decode(pake_payload.request_data)
            .map_err(|e| {
                warn!("error base64 decoding pake registration request: {:?}", e);
                ServiceRequestError::InvalidPakeRequestPayload
            })?;

        match pake_payload.state {
            PakeState::Evaluate => {
                let registration_request = RegistrationRequest::deserialize(&decoded_request_data)
                    .map_err(|e| {
                        warn!("invalid registration request evaluate: {:?}", e);
                        ServiceRequestError::InvalidRegistrationRequest
                    })?;

                let server_registration_start_result =
                    ServerRegistration::<DefaultCipherSuite>::start(
                        &self.opaque_server_setup,
                        registration_request,
                        r2ps_request.device_id.as_bytes(),
                    )
                    .map_err(|e| {
                        warn!("invalid registration request evaluate: {:?}", e);
                        ServiceRequestError::ServerRegistrationStartFailed
                    })?;

                info!(
                    "server_registration_start_result: {:?}",
                    server_registration_start_result.message
                );

                let response_data = server_registration_start_result
                    .message
                    .serialize()
                    .to_vec();
                let pake_response = PakeResponsePayload {
                    pake_session_id: None,
                    task: None,
                    response_data: Some(BASE64_STANDARD.encode(response_data)),
                    message: None,
                    expires_in: None,
                };

                Ok(R2psResponse {
                    state: r2ps_request.state,
                    payload: ServiceResponse::Pake(pake_response),
                })
            }
            PakeState::Finalize => {
                let registration_request: RegistrationUpload<DefaultCipherSuite> =
                    RegistrationUpload::deserialize(&decoded_request_data).map_err(|e| {
                        warn!("invalid registration request finalize: {:?}", e);
                        ServiceRequestError::InvalidRegistrationRequest
                    })?;

                let password_file =
                    ServerRegistration::<DefaultCipherSuite>::finish(registration_request);
                let password_file_serialized = password_file.serialize();
                info!("password file: {:?}", hex::encode(password_file_serialized));

                let new_state = DeviceHsmState {
                    client_id: r2ps_request.state.client_id,
                    wallet_id: r2ps_request.state.wallet_id,
                    client_public_key: r2ps_request.state.client_public_key,
                    password_file: Some(password_file_serialized),
                    keys: Vec::new(),
                };

                let msg = br#"{"msg":"OK"}"#.to_vec();
                let pake_response = PakeResponsePayload {
                    pake_session_id: None,
                    task: None,
                    response_data: Some(BASE64_STANDARD.encode(&msg)),
                    message: None,
                    expires_in: None,
                };

                Ok(R2psResponse {
                    state: new_state,
                    payload: ServiceResponse::Pake(pake_response),
                })
            }
        }
    }
}
