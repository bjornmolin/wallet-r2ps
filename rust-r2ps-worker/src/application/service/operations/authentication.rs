use super::{OperationContext, OperationResult, ServiceOperation};
use crate::application::pending_auth_spi_port::{LoginSession, PendingAuthSpiPort};
use crate::application::session_key_spi_port::{SessionKey, SessionKeySpiPort};
use crate::domain::value_objects::r2ps::{PakeRequest, PakeResponse};
use crate::domain::{
    DefaultCipherSuite, InnerResponseData, PakePayloadVector, PasswordFile, ServiceRequestError,
    SessionId,
};
use argon2::password_hash::rand_core::OsRng;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use josekit::jwk::Jwk;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use sha2::Digest;
use std::sync::Arc;
use tracing::{debug, warn};

/// Computes RFC 7638 JWK thumbprint for EC keys
fn compute_jwk_thumbprint(jwk: &Jwk) -> Result<String, ServiceRequestError> {
    let crv = jwk
        .curve()
        .ok_or(ServiceRequestError::InvalidClientPublicKey)?;
    let x = jwk
        .parameter("x")
        .and_then(|v| v.as_str())
        .ok_or(ServiceRequestError::InvalidClientPublicKey)?;
    let y = jwk
        .parameter("y")
        .and_then(|v| v.as_str())
        .ok_or(ServiceRequestError::InvalidClientPublicKey)?;

    // RFC 7638: canonical JSON with fields in lexicographic order
    let thumbprint_input = format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, crv, x, y);

    let mut hasher = sha2::Sha256::new();
    hasher.update(thumbprint_input.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Creates OPAQUE ServerLoginParameters with standardized context and identifiers
fn create_server_login_parameters<'a: 'b, 'b>(
    client_identifier: &'a str,
    server_identifier: &'a str,
) -> ServerLoginParameters<'a, 'b> {
    let context = b"RPS-Ops";
    let client = client_identifier.as_bytes();
    let server = server_identifier.as_bytes();

    debug!(
        "OPAQUE context: '{}' hex: {}",
        String::from_utf8_lossy(context),
        hex::encode(context)
    );
    debug!(
        "OPAQUE client: '{}' hex: {}",
        String::from_utf8_lossy(client),
        hex::encode(client)
    );
    debug!(
        "OPAQUE server: '{}' hex: {}",
        String::from_utf8_lossy(server),
        hex::encode(server)
    );

    ServerLoginParameters {
        context: Some(context),
        identifiers: Identifiers {
            client: Some(client),
            server: Some(server),
        },
    }
}

// AuthenticateStart Operation
pub struct AuthenticateStartOperation {
    opaque_server_setup: ServerSetup<DefaultCipherSuite>,
    pending_auth_spi_port: Arc<dyn PendingAuthSpiPort + Send + Sync>,
    server_identifier: String,
}

impl AuthenticateStartOperation {
    pub fn new(
        opaque_server_setup: ServerSetup<DefaultCipherSuite>,
        pending_auth_spi_port: Arc<dyn PendingAuthSpiPort + Send + Sync>,
        server_identifier: String,
    ) -> Self {
        Self {
            opaque_server_setup,
            pending_auth_spi_port,
            server_identifier,
        }
    }
}

impl ServiceOperation for AuthenticateStartOperation {
    fn execute(&self, context: OperationContext) -> Result<OperationResult, ServiceRequestError> {
        let pake_request = PakeRequest::from_inner_request(context.inner_request)?;

        debug!(
            "deserialized pake payload authenticate request data: {:?}",
            pake_request.data
        );

        // Get password file from device_keys using client_key_id from context
        let password_file_serialized = context
            .state
            .get_password_file(&context.device_kid)
            .ok_or(ServiceRequestError::UnknownClient)?;
        let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(
            password_file_serialized.as_bytes(),
        )
        .map_err(|e| {
            warn!("error decoding pake request: {:?}", e);
            ServiceRequestError::InvalidSerializedPasswordFile
        })?;

        let decoded_request_data = pake_request.data.as_ref();
        let credential_request =
            CredentialRequest::deserialize(&decoded_request_data).map_err(|e| {
                warn!("error decoding pake request: {:?}", e);
                ServiceRequestError::InvalidAuthenticateRequest
            })?;

        // client_key_id (kid from JWS header) is the thumbprint
        let device_kid = &context.device_kid;
        debug!(
            "Using client JWK thumbprint (device kid) for OPAQUE: {}",
            device_kid
        );

        let mut server_rng = OsRng;
        let server_login_parameters =
            create_server_login_parameters(&device_kid, &self.server_identifier);

        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &self.opaque_server_setup,
            Some(password_file),
            credential_request,
            device_kid.as_bytes(),
            server_login_parameters,
        )
        .map_err(|e| {
            warn!("error decoding pake request: {:?}", e);
            ServiceRequestError::ServerLoginStartFailed
        })?;

        let payload_bytes = server_login_start_result.message.serialize();
        let payload = PakePayloadVector::new(payload_bytes.to_vec());

        let session_id = SessionId::new();

        self.pending_auth_spi_port.store_pending_auth(
            &session_id,
            &Arc::new(LoginSession::new(server_login_start_result.state)),
        );

        let payload = PakeResponse {
            task: None,
            data: Some(payload),
        };

        Ok(OperationResult {
            state: context.state,
            data: InnerResponseData::new(payload)?,
            session_id: Some(session_id),
        })
    }
}

// AuthenticateFinish Operation
pub struct AuthenticateFinishOperation {
    pending_auth_spi_port: Arc<dyn PendingAuthSpiPort + Send + Sync>,
    session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
    server_identifier: String,
}

impl AuthenticateFinishOperation {
    pub fn new(
        pending_auth_spi_port: Arc<dyn PendingAuthSpiPort + Send + Sync>,
        session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
        server_identifier: String,
    ) -> Self {
        Self {
            pending_auth_spi_port,
            session_key_spi_port,
            server_identifier,
        }
    }
}

impl ServiceOperation for AuthenticateFinishOperation {
    fn execute(&self, context: OperationContext) -> Result<OperationResult, ServiceRequestError> {
        let pake_request = PakeRequest::from_inner_request(context.inner_request)?;

        let decoded_request_data = pake_request.data.as_ref();

        // Get the pending auth session id which was created in the start phase and sent to the client,
        // which the client now returns back to us to finish the authentication.
        let session_id = context
            .session_id
            .as_ref()
            .ok_or(ServiceRequestError::UnknownSession)?;

        let session = self
            .pending_auth_spi_port
            .get_pending_auth(&session_id)
            .ok_or(ServiceRequestError::UnknownSession)?;

        let device_kid = &context.device_kid;
        debug!(
            "Using client JWK thumbprint (device kid) for OPAQUE: {}",
            device_kid
        );

        let server_login_parameters =
            create_server_login_parameters(device_kid, &self.server_identifier);

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

        let session_key = SessionKey::new(result.session_key.to_vec());
        debug!("Derived shared session key: {:?}", session_key);

        self.session_key_spi_port
            .store(&session_id, session_key)
            .map_err(|_| ServiceRequestError::InternalServerError)?;

        let payload = PakeResponse {
            task: None,
            data: None,
        };

        Ok(OperationResult {
            state: context.state,
            data: InnerResponseData::new(payload)?,
            session_id: Some(session_id.clone()),
        })
    }
}

// RegisterStart Operation
pub struct RegisterStartOperation {
    opaque_server_setup: ServerSetup<DefaultCipherSuite>,
}

impl RegisterStartOperation {
    pub fn new(opaque_server_setup: ServerSetup<DefaultCipherSuite>) -> Self {
        Self {
            opaque_server_setup,
        }
    }
}

impl ServiceOperation for RegisterStartOperation {
    fn execute(&self, context: OperationContext) -> Result<OperationResult, ServiceRequestError> {
        let pake_request = PakeRequest::from_inner_request(context.inner_request)?;

        debug!("deserialized pake request {:?}", pake_request.data);

        let decoded_request_data = pake_request.data.as_ref();

        let registration_request = RegistrationRequest::deserialize(&decoded_request_data)
            .map_err(|e| {
                warn!("invalid registration request evaluate: {:?}", e);
                ServiceRequestError::InvalidRegistrationRequest
            })?;

        // client_key_id (kid from JWS header) is the thumbprint
        let client_thumbprint = &context.device_kid;
        debug!(
            "Using client JWK thumbprint for OPAQUE: {}",
            client_thumbprint
        );

        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            &self.opaque_server_setup,
            registration_request,
            client_thumbprint.as_bytes(),
        )
        .map_err(|e| {
            warn!("invalid registration request evaluate: {:?}", e);
            ServiceRequestError::ServerRegistrationStartFailed
        })?;

        debug!(
            "server_registration_start_result: {:?}",
            server_registration_start_result.message
        );

        let payload_bytes = server_registration_start_result.message.serialize();
        let payload = PakePayloadVector::new(payload_bytes.to_vec());

        let payload = PakeResponse {
            task: None,
            data: Some(payload),
        };

        Ok(OperationResult {
            state: context.state,
            data: InnerResponseData::new(payload)?,
            session_id: context.session_id,
        })
    }
}

// RegisterFinish Operation
pub struct RegisterFinishOperation {
    server_identifier: String,
}

impl RegisterFinishOperation {
    pub fn new(server_identifier: String) -> Self {
        Self { server_identifier }
    }
}

impl ServiceOperation for RegisterFinishOperation {
    fn execute(&self, context: OperationContext) -> Result<OperationResult, ServiceRequestError> {
        let inner_request = context.inner_request;
        let pake_payload = PakeRequest::from_inner_request(inner_request)?;

        let decoded_request_data = pake_payload.data.as_ref();

        let registration_request: RegistrationUpload<DefaultCipherSuite> =
            RegistrationUpload::deserialize(&decoded_request_data).map_err(|e| {
                warn!("invalid registration request finalize: {:?}", e);
                ServiceRequestError::InvalidRegistrationRequest
            })?;

        let password_file = ServerRegistration::<DefaultCipherSuite>::finish(registration_request);
        let password_file_serialized = password_file.serialize();
        debug!(
            "password file: {:?}",
            hex::encode(&password_file_serialized)
        );

        debug!(
            "Storing server identifier used in OPAQUE: {:?}",
            &self.server_identifier
        );

        let mut new_state = context.state;
        new_state.add_password_file(
            &context.device_kid,
            PasswordFile(password_file_serialized),
            self.server_identifier.clone(),
        )?;

        let payload = PakeResponse {
            task: None,
            data: None,
        };

        Ok(OperationResult {
            state: new_state,
            data: InnerResponseData::new(payload)?,
            session_id: context.session_id,
        })
    }
}
