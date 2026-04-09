use crate::domain::{HsmWorkerRequest, WorkerRequestError};

pub trait WorkerRequestUseCase {
    fn execute(
        &self,
        hsm_worker_request: HsmWorkerRequest,
    ) -> Result<WorkerRequestId, WorkerRequestError>;
}

pub type WorkerRequestId = String;
