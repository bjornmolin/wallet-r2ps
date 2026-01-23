use super::ServiceOperation;
use crate::application::hsm_spi_port::HsmSpiPort;
use crate::application::service::r2ps_service::DecryptedData;
use crate::domain::{
    CreateKeyServiceData, CreateKeyServiceDataResponse, DeleteKeyServiceData, DeviceHsmState,
    KeyInfo, ListKeysResponse, R2psRequest, R2psResponse, ServiceRequestError, ServiceResponse,
    SignRequest,
};
use std::sync::Arc;
use tracing::info;

pub struct HsmEcdsaSignOperation {
    hsm_spi_port: Arc<dyn HsmSpiPort + Send + Sync>,
}

impl HsmEcdsaSignOperation {
    pub fn new(hsm_spi_port: Arc<dyn HsmSpiPort + Send + Sync>) -> Self {
        Self { hsm_spi_port }
    }
}

impl ServiceOperation for HsmEcdsaSignOperation {
    fn execute(
        &self,
        r2ps_request: R2psRequest,
        decrypted_service_data: Option<DecryptedData>,
    ) -> Result<R2psResponse, ServiceRequestError> {
        let data =
            decrypted_service_data.ok_or(ServiceRequestError::InvalidServiceRequestFormat)?;
        let sign_request = serde_json::from_slice::<SignRequest>(&data)
            .map_err(|_| ServiceRequestError::InvalidServiceRequestFormat)?;

        let hsm_key = r2ps_request
            .state
            .keys
            .iter()
            .find(|key| key.public_key_jwk.kid.eq(&sign_request.kid))
            .cloned()
            .ok_or(ServiceRequestError::UnknownKey)?;

        let raw_sig_bytes = self
            .hsm_spi_port
            .sign(&hsm_key.wrapped_private_key, &sign_request.tbs_hash)
            .map_err(|_| ServiceRequestError::Unknown)?;

        let signature = p256::ecdsa::Signature::from_slice(&raw_sig_bytes)
            .map_err(|_| ServiceRequestError::Unknown)?;
        let asn1_signature: Vec<u8> = signature.to_der().as_bytes().to_vec();

        info!("Hsm Ecdsa asn1_signature: {:?}", asn1_signature);

        Ok(R2psResponse {
            state: r2ps_request.state,
            payload: ServiceResponse::Asn1Signature(asn1_signature),
        })
    }
}

pub struct HsmKeygenOperation {
    hsm_spi_port: Arc<dyn HsmSpiPort + Send + Sync>,
}

impl HsmKeygenOperation {
    pub fn new(hsm_spi_port: Arc<dyn HsmSpiPort + Send + Sync>) -> Self {
        Self { hsm_spi_port }
    }
}

impl ServiceOperation for HsmKeygenOperation {
    fn execute(
        &self,
        r2ps_request: R2psRequest,
        decrypted_service_data: Option<DecryptedData>,
    ) -> Result<R2psResponse, ServiceRequestError> {
        let data =
            decrypted_service_data.ok_or(ServiceRequestError::InvalidServiceRequestFormat)?;
        let payload = serde_json::from_slice::<CreateKeyServiceData>(&data)
            .map_err(|_| ServiceRequestError::InvalidServiceRequestFormat)?;

        let hsm_key = self
            .hsm_spi_port
            .generate_key("foobar", &payload.curve)
            .map_err(|_| ServiceRequestError::Unknown)?;

        let mut new_keys = r2ps_request.state.keys.clone();
        new_keys.push(hsm_key.clone());

        let new_state = DeviceHsmState {
            client_id: r2ps_request.state.client_id,
            wallet_id: r2ps_request.state.wallet_id,
            client_public_key: r2ps_request.state.client_public_key,
            password_file: r2ps_request.state.password_file,
            keys: new_keys,
        };

        Ok(R2psResponse {
            state: new_state,
            payload: ServiceResponse::CreateKey(CreateKeyServiceDataResponse {
                public_key: hsm_key.public_key_jwk,
            }),
        })
    }
}

pub struct HsmDeleteKeyOperation;

impl ServiceOperation for HsmDeleteKeyOperation {
    fn execute(
        &self,
        r2ps_request: R2psRequest,
        decrypted_service_data: Option<DecryptedData>,
    ) -> Result<R2psResponse, ServiceRequestError> {
        let data =
            decrypted_service_data.ok_or(ServiceRequestError::InvalidServiceRequestFormat)?;
        let payload = serde_json::from_slice::<DeleteKeyServiceData>(&data)
            .map_err(|_| ServiceRequestError::InvalidServiceRequestFormat)?;

        let new_state = DeviceHsmState {
            client_id: r2ps_request.state.client_id,
            wallet_id: r2ps_request.state.wallet_id,
            client_public_key: r2ps_request.state.client_public_key,
            password_file: r2ps_request.state.password_file,
            keys: r2ps_request
                .state
                .keys
                .into_iter()
                .filter(|key| key.public_key_jwk.kid != payload.kid)
                .collect(),
        };

        Ok(R2psResponse {
            state: new_state,
            payload: ServiceResponse::DeleteKey(DeleteKeyServiceData { kid: payload.kid }),
        })
    }
}

pub struct HsmListKeysOperation;

impl ServiceOperation for HsmListKeysOperation {
    fn execute(
        &self,
        r2ps_request: R2psRequest,
        _decrypted_service_data: Option<DecryptedData>,
    ) -> Result<R2psResponse, ServiceRequestError> {
        let list_keys = ListKeysResponse {
            key_info: r2ps_request
                .state
                .keys
                .iter()
                .map(|key| KeyInfo {
                    public_key: key.public_key_jwk.clone(),
                    creation_time: Some(key.creation_time.timestamp_millis()),
                })
                .collect(),
        };

        Ok(R2psResponse {
            state: r2ps_request.state,
            payload: ServiceResponse::ListKeys(list_keys),
        })
    }
}
