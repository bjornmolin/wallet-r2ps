pub mod context;
pub mod decode;
pub mod error;
pub mod response;

#[cfg(test)]
mod tests;

pub use context::{ResponseContext, WorkerInput};
pub use error::WorkerError;

use crate::application::service::operations::OperationDispatcher;
use crate::application::{
    WorkerPorts, WorkerRequestId, WorkerRequestUseCase, WorkerResponseSpiPort, jose_port,
};
use crate::domain::{HsmWorkerRequest, SessionId, WorkerRequestError, WorkerResponse};
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info};

use decode::RequestDecoder;
use response::ResponseBuilder;

/// Orchestrates the processing of requests from Kafka.
pub struct WorkerService {
    worker_response_spi_port: Arc<dyn WorkerResponseSpiPort + Send + Sync>,
    operation_dispatcher: OperationDispatcher,
    request_decoder: RequestDecoder,
    response_builder: ResponseBuilder,
}

impl WorkerService {
    pub fn new(jose: Arc<dyn jose_port::JosePort>, ports: WorkerPorts) -> Self {
        let operation_dispatcher = OperationDispatcher::from_dependencies(
            ports.pake,
            ports.session_key.clone(),
            ports.hsm,
        );

        let request_decoder = RequestDecoder::new(jose.clone(), ports.session_key.clone());

        let response_builder = ResponseBuilder::new(jose.clone(), ports.session_key.clone());

        Self {
            worker_response_spi_port: ports.worker_response,
            operation_dispatcher,
            request_decoder,
            response_builder,
        }
    }
}

impl WorkerRequestUseCase for WorkerService {
    /// The entry point for processing a single request from Kafka.
    /// It handles the end-to-end execution and all error reporting back to the sender.
    fn execute(
        &self,
        hsm_worker_request: HsmWorkerRequest,
    ) -> Result<WorkerRequestId, WorkerRequestError> {
        let start = Instant::now();
        let request_id = hsm_worker_request.request_id.clone();

        let response = match self.process_request(hsm_worker_request) {
            Ok(res) => res,
            Err(err) => {
                let worker_err = err.worker_error();
                error!(
                    "Request {} failed with reason: {:?} (visibility {:?})",
                    request_id, worker_err.reason, worker_err.visibility
                );
                match self.build_error_response(&request_id, err) {
                    Ok(response) => response,
                    Err(build_err) => {
                        error!(
                            "Request {} failed to build error response: {:?}",
                            request_id, build_err
                        );
                        return Err(build_err);
                    }
                }
            }
        };

        self.worker_response_spi_port
            .send(response)
            .map_err(|_| WorkerRequestError::ConnectionError)?;

        info!(
            "Processed request id {} (took {} ms)",
            request_id,
            start.elapsed().as_millis(),
        );

        Ok(request_id)
    }
}

/// Represents an error encountered at a specific stage of the request pipeline.
#[derive(Debug)]
enum ProcessError {
    /// Error occurring before context is established (e.g. Decode)
    WithoutContext(WorkerError),
    /// Error occurring after context is established (e.g. Dispatch or Encode)
    WithContext(WorkerError, Box<ResponseContext>, Option<SessionId>),
}

impl ProcessError {
    /// Returns the underlying `WorkerError`
    fn worker_error(&self) -> &WorkerError {
        match self {
            ProcessError::WithoutContext(err) => err,
            ProcessError::WithContext(err, _, _) => err,
        }
    }
}

impl WorkerService {
    /// The core execution pipeline: Decode -> Dispatch -> Encode.
    fn process_request(&self, request: HsmWorkerRequest) -> Result<WorkerResponse, ProcessError> {
        // Decode
        let WorkerInput {
            operation_context,
            response_context,
        } = self
            .request_decoder
            .decode_request(request)
            .map_err(ProcessError::WithoutContext)?;

        let session_id = operation_context.session_id.clone();

        // Dispatch
        let operation_result = self
            .operation_dispatcher
            .dispatch(operation_context)
            .map_err(|err| {
                ProcessError::WithContext(
                    WorkerError::dispatch(err),
                    Box::new(response_context.clone()),
                    session_id.clone(),
                )
            })?;

        // Encode
        self.response_builder
            .encode_response(operation_result, &response_context)
            .map_err(|err| ProcessError::WithContext(err, Box::new(response_context), session_id))
    }

    fn build_error_response(
        &self,
        request_id: &str,
        err: ProcessError,
    ) -> Result<WorkerResponse, WorkerRequestError> {
        match err {
            ProcessError::WithoutContext(worker_err) => {
                let problem_json = worker_err.to_problem_details_json(request_id);
                Ok(self
                    .response_builder
                    .build_worker_only_error_response(request_id, problem_json))
            }
            ProcessError::WithContext(worker_err, context, session_id) => {
                self.response_builder.build_dispatch_error_response(
                    request_id,
                    context.as_ref(),
                    worker_err,
                    session_id,
                )
            }
        }
    }
}
