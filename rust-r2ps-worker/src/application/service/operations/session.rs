use super::ServiceOperation;
use crate::application::service::r2ps_service::DecryptedData;
use crate::application::session_key_spi_port::SessionKeySpiPort;
use crate::domain::value_objects::r2ps::PakeResponsePayload;
use crate::domain::{R2psRequest, R2psResponse, ServiceRequestError, ServiceResponse};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::Utc;
use std::sync::Arc;

pub struct SessionEndOperation {
    session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>,
}

impl SessionEndOperation {
    pub fn new(session_key_spi_port: Arc<dyn SessionKeySpiPort + Send + Sync>) -> Self {
        Self {
            session_key_spi_port,
        }
    }
}

impl ServiceOperation for SessionEndOperation {
    fn execute(
        &self,
        r2ps_request: R2psRequest,
        _decrypted_service_data: Option<DecryptedData>,
    ) -> Result<R2psResponse, ServiceRequestError> {
        self.session_key_spi_port
            .end_session(
                r2ps_request
                    .service_request
                    .pake_session_id
                    .clone()
                    .unwrap()
                    .as_str(),
            )
            .map_err(|_| ServiceRequestError::UnknownSession)?;

        let msg = br#"{"msg":"OK"}"#.to_vec();
        let pake_response = PakeResponsePayload {
            pake_session_id: r2ps_request.service_request.pake_session_id,
            task: None,
            response_data: Some(BASE64_STANDARD.encode(&msg)),
            message: None,
            session_expiration_time: Some(Utc::now().timestamp_millis()),
        };

        Ok(R2psResponse {
            state: r2ps_request.state,
            payload: ServiceResponse::Pake(pake_response),
        })
    }
}
