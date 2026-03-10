use crate::application::jose_port;
use crate::application::service::operations::OperationContext;
use crate::application::service::worker_service::context::{ResponseContext, WorkerInput};
use crate::application::service::worker_service::error::{OuterError, UpstreamError, WorkerError};
use crate::application::session_key_spi_port::SessionKeySpiPort;
use crate::domain::value_objects::r2ps::OuterRequest;
use crate::domain::{DeviceHsmState, EcPublicJwk, HsmWorkerRequest};
use std::sync::Arc;
use tracing::info;

/// Handles the decoding of HsmWorkerRequests.
/// This includes verifying the device state JWS, peeking at the outer JWS header
/// for the device public key, and decrypting the inner JWE payload.
pub struct RequestDecoder {
    jose: Arc<dyn jose_port::JosePort>,
    session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
}

impl RequestDecoder {
    pub fn new(
        jose: Arc<dyn jose_port::JosePort>,
        session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
    ) -> Self {
        Self {
            jose,
            session_key_spi_port,
        }
    }

    /// Decodes an `HsmWorkerRequest` into its validated and decrypted parts.
    /// Returns a `WorkerInput` containing both the `OperationContext` (for business logic)
    /// and the `ResponseContext` (for later encoding).
    pub fn decode_request(
        &self,
        hsm_worker_request: HsmWorkerRequest,
    ) -> Result<WorkerInput, WorkerError> {
        let HsmWorkerRequest {
            request_id,
            state_jws,
            outer_request_jws,
        } = hsm_worker_request;

        let state = self.decode_state(state_jws.as_str())?;

        let (device_kid, device_public_key, outer_request) =
            self.decode_outer_request(outer_request_jws.as_str(), &state)?;

        let session_id = outer_request.session_id.clone();
        let session_key = session_id
            .as_ref()
            .and_then(|id| self.session_key_spi_port.get(id));

        let inner_request =
            outer_request.decrypt_inner(self.jose.as_ref(), session_key.as_ref())?;

        info!(
            "Processing request id {} of type {:?}",
            request_id, inner_request.request_type
        );

        let operation_context = OperationContext {
            request_id: request_id.clone(),
            state,
            outer_request,
            inner_request,
            session_id,
            device_kid,
        };

        let response_context = ResponseContext {
            request_id,
            request_type: operation_context.inner_request.request_type,
            session_key,
            device_public_key,
        };

        Ok(WorkerInput {
            operation_context,
            response_context,
        })
    }

    fn decode_state(&self, state_jws: &str) -> Result<DeviceHsmState, UpstreamError> {
        DeviceHsmState::from_jws(state_jws, self.jose.as_ref())
            .map_err(|_| UpstreamError::InvalidStateJws)
    }

    fn decode_outer_request(
        &self,
        outer_request_jws: &str,
        state: &DeviceHsmState,
    ) -> Result<(String, EcPublicJwk, OuterRequest), WorkerError> {
        let device_kid = self
            .jose
            .peek_kid(outer_request_jws)
            .map_err(|_| UpstreamError::OuterJwsInvalid)?
            .ok_or(UpstreamError::OuterJwsMissingKid)?;

        let device_public_key = state
            .find_device_key(&device_kid)
            .ok_or(UpstreamError::UnknownDevice)?
            .public_key
            .clone();

        let outer_request =
            OuterRequest::from_jws(outer_request_jws, self.jose.as_ref(), &device_public_key)?;

        if outer_request.context != "hsm" {
            return Err(OuterError::UnsupportedContext.into());
        }

        Ok((device_kid, device_public_key, outer_request))
    }
}
