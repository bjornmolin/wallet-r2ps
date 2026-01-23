use crate::domain::R2psResponseJws;

pub trait R2psResponseSpiPort {
    fn send(&self, r2ps_response: R2psResponseJws) -> Result<(), R2psResponseError>;
}

#[derive(Debug)]
pub enum R2psResponseError {
    ConnectionError,
    // TODO
}
