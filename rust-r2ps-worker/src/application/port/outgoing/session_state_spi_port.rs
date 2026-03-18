use crate::{define_byte_vector, domain::SessionId};
use std::time::Duration;

define_byte_vector!(SessionKey, 4);
define_byte_vector!(PendingLoginState, 8);

#[derive(Clone, Debug)]
pub struct PendingAuthData {
    pub server_login: PendingLoginState,
    pub purpose: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SessionData {
    pub session_key: SessionKey,
    pub purpose: Option<String>,
    pub operation: Option<OngoingOperation>,
}

#[derive(Clone, Debug)]
pub enum OngoingOperation {
    ChangingPin,
}

#[derive(Clone, Debug)]
pub enum SessionState {
    PendingAuth(PendingAuthData),
    Active(SessionData),
}

#[derive(Debug)]
pub enum SessionStateError {
    Unknown,
    UnknownSession,
    InvalidTransition,
}

#[derive(Clone, Debug)]
pub enum SessionTransition {
    CreatePendingAuth {
        pending_state: PendingLoginState,
        purpose: Option<String>,
    },
    Authenticate {
        session_key: SessionKey,
    },
    BeginChangingPin,
    End,
}

pub trait SessionStateSpiPort: Send + Sync {
    fn get(&self, id: &SessionId) -> Option<SessionState>;
    fn apply_transition(
        &self,
        session_id: Option<&SessionId>,
        transition: Option<&SessionTransition>,
    ) -> Result<(), SessionStateError>;
    fn get_remaining_ttl(&self, session_id: Option<&SessionId>) -> Option<Duration>;
}
