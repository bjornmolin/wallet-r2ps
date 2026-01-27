use crate::define_byte_vector;
use std::time::Duration;

define_byte_vector!(SessionKey);

pub trait SessionKeySpiPort {
    fn store(
        &self,
        pake_session_id: &str,
        session_key: SessionKey,
    ) -> Result<Duration, ClientRepositoryError>;
    fn get(&self, pake_session_id: &str) -> Option<SessionKey>;
    fn get_remaining_ttl(&self, pake_session_id: &str) -> Option<Duration>;
    fn end_session(&self, pake_session_id: &str) -> Result<(), ClientRepositoryError>;
}

#[derive(Debug)]
pub enum ClientRepositoryError {
    Unknown,
}
