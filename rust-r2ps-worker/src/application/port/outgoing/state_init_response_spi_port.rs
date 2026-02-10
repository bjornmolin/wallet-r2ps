use crate::domain::StateInitResponse;

pub trait StateInitResponseSpiPort {
    fn send(&self, response: StateInitResponse) -> Result<(), StateInitResponseError>;
}

#[derive(Debug)]
pub enum StateInitResponseError {
    ConnectionError,
    SerializationError,
}
