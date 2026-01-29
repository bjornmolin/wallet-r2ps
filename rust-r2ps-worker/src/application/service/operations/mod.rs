pub mod authentication;
pub mod hsm;
pub mod session;

use crate::application::hsm_spi_port::HsmSpiPort;
use crate::application::pending_auth_spi_port::PendingAuthSpiPort;
use crate::application::service::r2ps_service::DecryptedData;
use crate::application::session_key_spi_port::SessionKeySpiPort;
use crate::domain::{
    DefaultCipherSuite, R2psRequest, R2psResponse, ServiceRequestError, ServiceTypeId,
};
use opaque_ke::ServerSetup;
use std::sync::Arc;
use tracing::debug;

use authentication::{
    AuthenticateFinishOperation, AuthenticateStartOperation, RegisterFinishOperation,
    RegisterStartOperation,
};
use hsm::{HsmDeleteKeyOperation, HsmEcdsaSignOperation, HsmKeygenOperation, HsmListKeysOperation};
use session::SessionEndOperation;

/// Trait for service operations that can be executed
pub trait ServiceOperation {
    fn execute(
        &self,
        r2ps_request: R2psRequest,
        decrypted_service_data: Option<DecryptedData>,
    ) -> Result<R2psResponse, ServiceRequestError>;
}

/// Contains all operation handlers
pub struct OperationDispatcher {
    authenticate_start_op: AuthenticateStartOperation,
    authenticate_finish_op: AuthenticateFinishOperation,
    register_start_op: RegisterStartOperation,
    register_finish_op: RegisterFinishOperation,
    hsm_ecdsa_op: HsmEcdsaSignOperation,
    hsm_keygen_op: HsmKeygenOperation,
    hsm_delete_key_op: HsmDeleteKeyOperation,
    hsm_list_keys_op: HsmListKeysOperation,
    session_end_op: SessionEndOperation,
}

impl OperationDispatcher {
    /// Creates a new OperationDispatcher with all operation handlers initialized
    pub fn from_dependencies(
        server_setup: ServerSetup<DefaultCipherSuite>,
        session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
        hsm_spi_port: Arc<dyn HsmSpiPort + Send + Sync>,
        pending_auth_spi_port: Arc<dyn PendingAuthSpiPort + Send + Sync>,
    ) -> Self {
        Self {
            authenticate_start_op: AuthenticateStartOperation::new(
                server_setup.clone(),
                pending_auth_spi_port.clone(),
            ),
            authenticate_finish_op: AuthenticateFinishOperation::new(
                pending_auth_spi_port.clone(),
                session_key_spi_port.clone(),
            ),
            register_start_op: RegisterStartOperation::new(server_setup.clone()),
            register_finish_op: RegisterFinishOperation::new(),
            hsm_ecdsa_op: HsmEcdsaSignOperation::new(hsm_spi_port.clone()),
            hsm_keygen_op: HsmKeygenOperation::new(hsm_spi_port.clone()),
            hsm_delete_key_op: HsmDeleteKeyOperation,
            hsm_list_keys_op: HsmListKeysOperation,
            session_end_op: SessionEndOperation::new(session_key_spi_port.clone()),
        }
    }

    /// Dispatches the request to the appropriate operation handler
    pub fn dispatch(
        &self,
        r2ps_request: R2psRequest,
        decrypted_service_data: Option<DecryptedData>,
    ) -> Result<R2psResponse, ServiceRequestError> {
        debug!(
            "SERVICE TYPE REQUEST {:?}",
            r2ps_request.service_request.service_type
        );

        match r2ps_request.service_request.service_type {
            ServiceTypeId::AuthenticateStart => self
                .authenticate_start_op
                .execute(r2ps_request, decrypted_service_data),
            ServiceTypeId::AuthenticateFinish => self
                .authenticate_finish_op
                .execute(r2ps_request, decrypted_service_data),
            ServiceTypeId::RegisterStart => self
                .register_start_op
                .execute(r2ps_request, decrypted_service_data),
            ServiceTypeId::RegisterFinish => self
                .register_finish_op
                .execute(r2ps_request, decrypted_service_data),
            ServiceTypeId::HsmEcdsa => self
                .hsm_ecdsa_op
                .execute(r2ps_request, decrypted_service_data),
            ServiceTypeId::HsmEcKeygen => self
                .hsm_keygen_op
                .execute(r2ps_request, decrypted_service_data),
            ServiceTypeId::HsmEcDeleteKey => self
                .hsm_delete_key_op
                .execute(r2ps_request, decrypted_service_data),
            ServiceTypeId::HsmListKeys => self
                .hsm_list_keys_op
                .execute(r2ps_request, decrypted_service_data),
            ServiceTypeId::SessionEnd => self
                .session_end_op
                .execute(r2ps_request, decrypted_service_data),
            ServiceTypeId::PinChange => Err(ServiceRequestError::Unknown),
            ServiceTypeId::HsmEcdh => Err(ServiceRequestError::Unknown),
            ServiceTypeId::SessionContextEnd => Err(ServiceRequestError::Unknown),
            ServiceTypeId::Store => Err(ServiceRequestError::Unknown),
            ServiceTypeId::Retrieve => Err(ServiceRequestError::Unknown),
            ServiceTypeId::Log => Err(ServiceRequestError::Unknown),
            ServiceTypeId::GetLog => Err(ServiceRequestError::Unknown),
            ServiceTypeId::Info => Err(ServiceRequestError::Unknown),
        }
    }
}
