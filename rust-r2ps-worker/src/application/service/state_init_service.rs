use crate::application::StateInitResponseSpiPort;
use crate::domain::{
    DeviceHsmState, DeviceKeyEntry, WorkerServerConfig, StateInitRequest, StateInitResponse,
};
use josekit::jwk::Jwk;
use josekit::jws::ES256;
use josekit::jwt::{self, JwtPayload};
use pem::Pem;
use std::sync::Arc;
use tracing::{debug, error, info};
use uuid::Uuid;

pub struct StateInitService {
    response_spi_port: Arc<dyn StateInitResponseSpiPort + Send + Sync>,
    server_config: WorkerServerConfig,
}

#[derive(Debug)]
pub enum StateInitError {
    InvalidJwk,
    InvalidPublicKey(String),
    SigningError,
    SendError,
}

impl StateInitService {
    pub fn new(
        response_spi_port: Arc<dyn StateInitResponseSpiPort + Send + Sync>,
        server_config: WorkerServerConfig,
    ) -> Self {
        Self {
            response_spi_port,
            server_config,
        }
    }

    /// Initialize a new DeviceHsmState for a client
    pub fn initialize(&self, request: StateInitRequest) -> Result<String, StateInitError> {
        info!("Initializing state for client_id: {}", request.client_id);

        // 1. Convert EcPublicJwk to josekit Jwk
        let device_key = ec_public_jwk_to_jwk(&request.public_key)?;

        // 2. Validate public_key JWK (EC P-256)
        validate_ec_public_jwk(&request.public_key)?;

        // 3. Generate dev_authorization_code
        let dev_auth_code = format!("dac_{}", Uuid::new_v4());
        debug!("Generated dev_authorization_code: {}", dev_auth_code);

        // 4. Create DeviceHsmState
        let state = DeviceHsmState {
            version: 1,
            client_id: request.client_id.clone(),
            device_keys: vec![DeviceKeyEntry {
                public_key: device_key,
                password_files: vec![],
                dev_authorization_code: Some(dev_auth_code.clone()),
            }],
            hsm_keys: vec![],
        };

        debug!("Created initial DeviceHsmState: {:#?}", state);

        // 5. Sign state as JWS using server private key
        let state_jws = sign_state_jws(&state, &self.server_config.server_private_key)?;

        // 6. Create response
        let response = StateInitResponse {
            request_id: request.request_id.clone(),
            client_id: request.client_id,
            state_jws,
            dev_authorization_code: dev_auth_code,
        };

        // 7. Send response via Kafka
        self.response_spi_port.send(response).map_err(|e| {
            error!("Failed to send state init response: {:?}", e);
            StateInitError::SendError
        })?;

        info!(
            "State initialization complete for request_id: {}",
            request.request_id
        );
        Ok(request.request_id)
    }
}

/// Validates EcPublicJwk is EC P-256
fn validate_ec_public_jwk(jwk: &crate::domain::EcPublicJwk) -> Result<(), StateInitError> {
    if jwk.kty != "EC" {
        error!("Invalid JWK: key type must be EC, got: {}", jwk.kty);
        return Err(StateInitError::InvalidJwk);
    }

    if jwk.crv != "P-256" {
        error!("Invalid JWK: curve must be P-256, got: {}", jwk.crv);
        return Err(StateInitError::InvalidJwk);
    }

    if jwk.x.is_empty() || jwk.y.is_empty() {
        error!("Invalid JWK: missing x or y coordinate");
        return Err(StateInitError::InvalidJwk);
    }

    if jwk.kid.is_empty() {
        error!("Invalid JWK: missing kid");
        return Err(StateInitError::InvalidJwk);
    }

    Ok(())
}

/// Converts EcPublicJwk to josekit Jwk
fn ec_public_jwk_to_jwk(ec_jwk: &crate::domain::EcPublicJwk) -> Result<Jwk, StateInitError> {
    let mut jwk = Jwk::new("EC");
    jwk.set_curve(&ec_jwk.crv);
    jwk.set_parameter("x", Some(serde_json::Value::String(ec_jwk.x.clone())))
        .map_err(|_| StateInitError::InvalidJwk)?;
    jwk.set_parameter("y", Some(serde_json::Value::String(ec_jwk.y.clone())))
        .map_err(|_| StateInitError::InvalidJwk)?;
    jwk.set_key_id(&ec_jwk.kid);

    Ok(jwk)
}

/// Signs DeviceHsmState as JWS using server private key
fn sign_state_jws(
    state: &DeviceHsmState,
    server_private_key: &Pem,
) -> Result<String, StateInitError> {
    let pem_string = pem::encode(server_private_key);

    // Create signer from PEM
    let signer = ES256.signer_from_pem(&pem_string).map_err(|e| {
        error!("Failed to create signer from PEM: {:?}", e);
        StateInitError::SigningError
    })?;

    // Create JWT payload from state
    let payload_json = serde_json::to_string(&state).map_err(|e| {
        error!("Failed to serialize state: {:?}", e);
        StateInitError::SigningError
    })?;

    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&payload_json)
        .map_err(|e| {
            error!("Failed to create payload map: {:?}", e);
            StateInitError::SigningError
        })?;

    let payload = JwtPayload::from_map(map).map_err(|e| {
        error!("Failed to create JwtPayload: {:?}", e);
        StateInitError::SigningError
    })?;

    // Create JWS header
    let header = josekit::jws::JwsHeader::new();

    let token = jwt::encode_with_signer(&payload, &header, &signer).map_err(|e| {
        error!("Failed to encode state JWS: {:?}", e);
        StateInitError::SigningError
    })?;

    Ok(token)
}
