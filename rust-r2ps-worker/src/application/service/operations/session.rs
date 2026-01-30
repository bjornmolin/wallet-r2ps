use super::{OperationContext, ServiceOperation};
use crate::application::session_key_spi_port::SessionKeySpiPort;
use crate::domain::value_objects::r2ps::PakeResponsePayload;
use crate::domain::{OuterResponse, R2psResponse, ServiceRequestError};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
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
    fn execute(&self, context: OperationContext) -> Result<R2psResponse, ServiceRequestError> {
        self.session_key_spi_port
            .end_session(
                context
                    .outer_request
                    .pake_session_id
                    .clone()
                    .unwrap()
                    .as_str(),
            )
            .map_err(|_| ServiceRequestError::UnknownSession)?;

        let msg = br#"{"msg":"OK"}"#.to_vec();
        let pake_response = PakeResponsePayload {
            pake_session_id: context.outer_request.pake_session_id,
            task: None,
            response_data: Some(BASE64_STANDARD.encode(&msg)),
            message: None,
            expires_in: None,
        };

        Ok(R2psResponse {
            state: context.state,
            payload: OuterResponse::Pake(pake_response),
        })
    }
}
