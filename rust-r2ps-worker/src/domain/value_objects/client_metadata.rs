use crate::domain::{DefaultCipherSuite, HsmKey, ServiceRequestError};
use generic_array::GenericArray;
use josekit::jwk::Jwk;
use opaque_ke::ServerRegistrationLen;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHsmState {
    pub client_id: String, // device_id or client_id?
    pub wallet_id: String,
    pub client_public_key: Jwk,
    pub password_file: Option<GenericArray<u8, ServerRegistrationLen<DefaultCipherSuite>>>,
    pub keys: Vec<HsmKey>,
}

impl DeviceHsmState {
    pub fn serialize(&self) -> Result<Vec<u8>, ServiceRequestError> {
        match serde_json::to_vec(&self) {
            Ok(payload_vec) => Ok(payload_vec),
            Err(_) => Err(ServiceRequestError::SerializeStateError),
        }
    }
}
