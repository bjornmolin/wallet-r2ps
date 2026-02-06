use crate::domain::{HsmWrapperRequest, R2psRequestError};

pub trait R2psRequestUseCase {
    fn execute(
        &self,
        hsm_wrapper_request: HsmWrapperRequest,
    ) -> Result<R2psRequestId, R2psRequestError>;
}

pub type R2psRequestId = String;
