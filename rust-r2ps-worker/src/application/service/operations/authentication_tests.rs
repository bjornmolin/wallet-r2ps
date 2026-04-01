use crate::application::port::outgoing::pake_port::{PakeError, PakePort, RegistrationResult};
use crate::application::port::outgoing::session_state_spi_port::{
    PendingAuthData, PendingLoginState, SessionData, SessionKey, SessionState,
};
use crate::application::service::operations::authentication::{
    AuthenticateFinishOperation, AuthenticateStartOperation,
};
use crate::application::service::operations::{OperationContext, ServiceOperation};
use crate::domain::{
    DeviceHsmState, DeviceKeyEntry, EcPublicJwk, InnerRequest, OperationId, OuterRequest,
    PakePayloadVector, PakeRequest, ServiceRequestError, SessionId,
};
use std::sync::{Arc, Mutex};

// -----------------------------------------------------------------------------
// Mock
// -----------------------------------------------------------------------------

struct MockPakePort {
    pub auth_start_called: Mutex<bool>,
    pub auth_finish_called: Mutex<bool>,
}

impl PakePort for MockPakePort {
    fn registration_start(
        &self,
        _request_bytes: &[u8],
        _client_id: &str,
    ) -> Result<PakePayloadVector, PakeError> {
        unimplemented!()
    }

    fn registration_finish(&self, _upload_bytes: &[u8]) -> Result<RegistrationResult, PakeError> {
        unimplemented!()
    }

    fn authentication_start(
        &self,
        _request_bytes: &[u8],
        _password_file_bytes: &[u8],
        _client_id: &str,
    ) -> Result<(PakePayloadVector, PendingLoginState), PakeError> {
        *self.auth_start_called.lock().unwrap() = true;
        Ok((
            PakePayloadVector::new(vec![1]),
            PendingLoginState::new(vec![1]),
        ))
    }

    fn authentication_finish(
        &self,
        _finalization_bytes: &[u8],
        _pending_state: &PendingLoginState,
        _client_id: &str,
    ) -> Result<SessionKey, PakeError> {
        *self.auth_finish_called.lock().unwrap() = true;
        Ok(SessionKey::new(vec![1]))
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn mock_pake_port() -> Arc<MockPakePort> {
    Arc::new(MockPakePort {
        auth_start_called: Mutex::new(false),
        auth_finish_called: Mutex::new(false),
    })
}

fn state_without_password_file() -> DeviceHsmState {
    DeviceHsmState {
        version: 1,
        device_keys: vec![DeviceKeyEntry {
            public_key: EcPublicJwk {
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x: "x".to_string(),
                y: "y".to_string(),
                kid: "device-key-1".to_string(),
            },
            password_files: vec![],
            dev_authorization_code: None,
        }],
        hsm_keys: vec![],
    }
}

fn pake_inner_request(op: OperationId) -> InnerRequest {
    let pake_req = PakeRequest {
        authorization: None,
        purpose: None,
        data: PakePayloadVector::new(vec![1, 2, 3]),
    };
    InnerRequest {
        version: 1,
        request_type: op,
        request_counter: 0,
        data: Some(serde_json::to_string(&pake_req).unwrap()),
    }
}

fn base_context(state: DeviceHsmState, inner_request: InnerRequest) -> OperationContext {
    OperationContext {
        request_id: "test-request".to_string(),
        state,
        outer_request: OuterRequest {
            version: 1,
            session_id: None,
            context: "auth".to_string(),
            inner_jwe: None,
        },
        inner_request,
        session_id: None,
        device_kid: "device-key-1".to_string(),
        session_state: None,
    }
}

// -----------------------------------------------------------------------------
// AuthenticateStartOperation
// -----------------------------------------------------------------------------

#[test]
fn test_authenticate_start_unknown_client_fails() {
    let mock = mock_pake_port();
    let op = AuthenticateStartOperation::new(mock.clone());

    let context = base_context(
        state_without_password_file(),
        pake_inner_request(OperationId::AuthenticateStart),
    );

    let result = op.execute(context);

    assert!(matches!(result, Err(ServiceRequestError::UnknownClient)));
    assert!(!*mock.auth_start_called.lock().unwrap());
}

// -----------------------------------------------------------------------------
// AuthenticateFinishOperation
// -----------------------------------------------------------------------------

#[test]
fn test_authenticate_finish_no_session_id_fails() {
    let mock = mock_pake_port();
    let op = AuthenticateFinishOperation::new(mock.clone());

    let mut context = base_context(
        state_without_password_file(),
        pake_inner_request(OperationId::AuthenticateFinish),
    );
    context.session_id = None;
    context.session_state = Some(SessionState::PendingAuth(PendingAuthData {
        server_login: PendingLoginState::new(vec![1]),
        purpose: None,
    }));

    let result = op.execute(context);

    assert!(matches!(result, Err(ServiceRequestError::UnknownSession)));
    assert!(!*mock.auth_finish_called.lock().unwrap());
}

#[test]
fn test_authenticate_finish_wrong_state_active_fails() {
    let mock = mock_pake_port();
    let op = AuthenticateFinishOperation::new(mock.clone());

    let mut context = base_context(
        state_without_password_file(),
        pake_inner_request(OperationId::AuthenticateFinish),
    );
    context.session_id = Some(SessionId::new());
    context.session_state = Some(SessionState::Active(SessionData {
        session_key: SessionKey::new(vec![1]),
        purpose: None,
        operation: None,
        has_performed_hsm_operation: false,
    }));

    let result = op.execute(context);

    assert!(matches!(result, Err(ServiceRequestError::UnknownSession)));
    assert!(!*mock.auth_finish_called.lock().unwrap());
}

#[test]
fn test_authenticate_finish_no_session_state_fails() {
    let mock = mock_pake_port();
    let op = AuthenticateFinishOperation::new(mock.clone());

    let mut context = base_context(
        state_without_password_file(),
        pake_inner_request(OperationId::AuthenticateFinish),
    );
    context.session_id = Some(SessionId::new());
    context.session_state = None;

    let result = op.execute(context);

    assert!(matches!(result, Err(ServiceRequestError::UnknownSession)));
    assert!(!*mock.auth_finish_called.lock().unwrap());
}
