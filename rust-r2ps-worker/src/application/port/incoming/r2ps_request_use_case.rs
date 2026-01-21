use crate::domain::{R2psRequestError, R2psRequestJws};

pub trait R2psRequestUseCase {
    fn execute(&self, r2ps_request_jws: R2psRequestJws) -> Result<R2psRequestId, R2psRequestError>;
}

pub type R2psRequestId = String;
