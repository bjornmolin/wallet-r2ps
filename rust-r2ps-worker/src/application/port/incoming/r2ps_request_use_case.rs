use crate::domain::{HsmWorkerRequest, R2psRequestError};

pub trait R2psRequestUseCase {
    fn execute(
        &self,
        hsm_worker_request: HsmWorkerRequest,
    ) -> Result<R2psRequestId, R2psRequestError>;
}

pub type R2psRequestId = String;
