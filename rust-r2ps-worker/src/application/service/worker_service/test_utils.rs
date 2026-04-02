use crate::application::hsm_spi_port::HsmSpiPort;
use crate::application::jose_port::{JoseError, JosePort, JweDecryptionKey, JweEncryptionKey};
use crate::application::pake_port::{PakeError, PakePort, RegistrationResult};
use crate::application::port::outgoing::session_state_spi_port::{
    SessionKey, SessionState, SessionStateError, SessionStateSpiPort, SessionTransition,
};
use crate::application::{WorkerPorts, WorkerResponseError, WorkerResponseSpiPort};
use crate::domain::value_objects::r2ps::PakePayloadVector;
use crate::domain::{
    Curve, DeviceHsmState, EcPublicJwk, HsmKey, HsmWorkerRequest, OuterRequest, PasswordFile,
    PasswordFileEntry, SessionId, TypedJwe, TypedJws, WorkerResponse,
};
use cryptoki::error::Error as CryptokiError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// --- Jose Mocks ---

pub struct MockJoseDeterministic {
    pub state_json: Vec<u8>,
    pub outer_json: Vec<u8>,
    pub inner_json: Vec<u8>,
    pub inner_kid: String,
    pub fail_sign: bool,
    pub captured_inner_encrypt_payload: Mutex<Vec<Vec<u8>>>,
}

impl MockJoseDeterministic {
    pub fn new(
        state: &DeviceHsmState,
        outer: &OuterRequest,
        inner: &[u8],
        inner_kid: &str,
        fail_sign: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            state_json: serde_json::to_vec(state).unwrap(),
            outer_json: serde_json::to_vec(outer).unwrap(),
            inner_json: inner.to_vec(),
            inner_kid: inner_kid.to_string(),
            fail_sign,
            captured_inner_encrypt_payload: Mutex::new(vec![]),
        })
    }
}

impl JosePort for MockJoseDeterministic {
    fn jws_sign(&self, _payload_json: &[u8]) -> Result<String, JoseError> {
        if self.fail_sign {
            Err(JoseError::SignError)
        } else {
            Ok("signed.outer.response".to_string())
        }
    }
    fn jws_verify_server(&self, _jws: &str) -> Result<Vec<u8>, JoseError> {
        Ok(self.state_json.clone())
    }
    fn jws_verify_device(&self, _jws: &str, _key: &EcPublicJwk) -> Result<Vec<u8>, JoseError> {
        Ok(self.outer_json.clone())
    }
    fn jwe_encrypt(&self, payload: &[u8], _key: JweEncryptionKey<'_>) -> Result<String, JoseError> {
        self.captured_inner_encrypt_payload
            .lock()
            .unwrap()
            .push(payload.to_vec());
        Ok("encrypted.inner.response".to_string())
    }
    fn jwe_decrypt(&self, _jwe: &str, _key: JweDecryptionKey<'_>) -> Result<Vec<u8>, JoseError> {
        Ok(self.inner_json.clone())
    }
    fn peek_kid(&self, compact: &str) -> Result<Option<String>, JoseError> {
        match compact {
            "outer.jws" => Ok(Some("device-kid".to_string())),
            "inner.jwe" => Ok(Some(self.inner_kid.clone())),
            _ => Err(JoseError::InvalidKey),
        }
    }
}

pub struct MockJoseFailing {
    pub sign_count: Mutex<u32>,
}

impl JosePort for MockJoseFailing {
    fn jws_sign(&self, _payload_json: &[u8]) -> Result<String, JoseError> {
        // Succeeds on the first call (signing the inbound state JWS re-seal) then fails on
        // every subsequent call. This exercises the failure path where the service successfully
        // decodes the request but then cannot sign the error response — verifying that the
        // double-failure case (operation error + sign error) is handled gracefully rather than
        // panicking or swallowing the original error.
        let mut n = self.sign_count.lock().unwrap();
        *n += 1;
        if *n == 1 {
            Ok("ok.jws".to_string())
        } else {
            Err(JoseError::SignError)
        }
    }
    fn jws_verify_server(&self, _jws: &str) -> Result<Vec<u8>, JoseError> {
        unimplemented!()
    }
    fn jws_verify_device(&self, _jws: &str, _key: &EcPublicJwk) -> Result<Vec<u8>, JoseError> {
        unimplemented!()
    }
    fn jwe_encrypt(
        &self,
        _payload: &[u8],
        _key: JweEncryptionKey<'_>,
    ) -> Result<String, JoseError> {
        Ok("enc.jwe".to_string())
    }
    fn jwe_decrypt(&self, _jwe: &str, _key: JweDecryptionKey<'_>) -> Result<Vec<u8>, JoseError> {
        unimplemented!()
    }
    fn peek_kid(&self, _compact: &str) -> Result<Option<String>, JoseError> {
        unimplemented!()
    }
}

// --- SPI Mocks ---

pub struct MockSessionStateSpi;
impl SessionStateSpiPort for MockSessionStateSpi {
    fn get(&self, _id: &SessionId) -> Option<SessionState> {
        None
    }
    fn apply_transition(
        &self,
        _session_id: Option<&SessionId>,
        _transition: Option<&SessionTransition>,
    ) -> Result<(), SessionStateError> {
        Ok(())
    }
    fn get_remaining_ttl(&self, _session_id: Option<&SessionId>) -> Option<Duration> {
        Some(Duration::from_secs(30))
    }
}

pub struct MockHsmSpi;
impl HsmSpiPort for MockHsmSpi {
    fn generate_key(
        &self,
        _label: &str,
        _curve: &Curve,
    ) -> Result<HsmKey, Box<dyn std::error::Error>> {
        unimplemented!()
    }
    fn sign(&self, _key: &HsmKey, _sign_payload: &[u8]) -> Result<Vec<u8>, CryptokiError> {
        unimplemented!()
    }
}

pub struct MockPake {
    pub auth_start_succeeds: bool,
}
impl PakePort for MockPake {
    fn registration_start(
        &self,
        _request_bytes: &[u8],
        _client_id: &str,
    ) -> Result<PakePayloadVector, PakeError> {
        Err(PakeError::RegistrationStartFailed)
    }
    fn registration_finish(&self, _upload_bytes: &[u8]) -> Result<RegistrationResult, PakeError> {
        Err(PakeError::InvalidRequest)
    }
    fn authentication_start(
        &self,
        _request_bytes: &[u8],
        _password_file_bytes: &[u8],
        _client_id: &str,
    ) -> Result<
        (
            PakePayloadVector,
            crate::application::port::outgoing::session_state_spi_port::PendingLoginState,
        ),
        PakeError,
    > {
        if self.auth_start_succeeds {
            Ok((
                PakePayloadVector::new(vec![0xAA]),
                crate::application::port::outgoing::session_state_spi_port::PendingLoginState::new(
                    vec![0xBB],
                ),
            ))
        } else {
            Err(PakeError::AuthStartFailed)
        }
    }
    fn authentication_finish(
        &self,
        _finalization_bytes: &[u8],
        _pending_state: &crate::application::port::outgoing::session_state_spi_port::PendingLoginState,
        _client_id: &str,
    ) -> Result<SessionKey, PakeError> {
        Err(PakeError::AuthFinishFailed)
    }
}

pub struct MockWorkerResponseSpi {
    pub responses: Mutex<Vec<WorkerResponse>>,
}
impl MockWorkerResponseSpi {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(vec![]),
        })
    }
}
impl WorkerResponseSpiPort for MockWorkerResponseSpi {
    fn send(&self, worker_response: WorkerResponse) -> Result<(), WorkerResponseError> {
        self.responses.lock().unwrap().push(worker_response);
        Ok(())
    }
}

pub struct FailingWorkerResponseSpi;
impl WorkerResponseSpiPort for FailingWorkerResponseSpi {
    fn send(&self, _worker_response: WorkerResponse) -> Result<(), WorkerResponseError> {
        Err(WorkerResponseError::ConnectionError)
    }
}

pub struct MockSessionStateTransitionErrorSpi {
    pub key: SessionKey,
}
impl SessionStateSpiPort for MockSessionStateTransitionErrorSpi {
    fn get(&self, _id: &SessionId) -> Option<SessionState> {
        Some(SessionState::Active(
            crate::application::port::outgoing::session_state_spi_port::SessionData {
                session_key: self.key.clone(),
                purpose: None,
                operation: None,
                has_performed_hsm_operation: false,
            },
        ))
    }
    fn apply_transition(
        &self,
        _session_id: Option<&SessionId>,
        _transition: Option<&SessionTransition>,
    ) -> Result<(), SessionStateError> {
        Err(SessionStateError::Unknown)
    }
    fn get_remaining_ttl(&self, _session_id: Option<&SessionId>) -> Option<Duration> {
        Some(Duration::from_secs(30))
    }
}

// --- Domain Builders ---

pub fn make_state(device_kid: &str) -> DeviceHsmState {
    make_state_impl(device_kid, vec![])
}

pub fn make_state_with_password_file(device_kid: &str) -> DeviceHsmState {
    make_state_impl(
        device_kid,
        vec![PasswordFileEntry {
            password_file: PasswordFile(vec![1, 2, 3]),
            server_identifier: "server-id".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        }],
    )
}

fn make_state_impl(device_kid: &str, password_files: Vec<PasswordFileEntry>) -> DeviceHsmState {
    DeviceHsmState {
        version: 1,
        device_keys: vec![crate::domain::DeviceKeyEntry {
            public_key: EcPublicJwk {
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x: "x".to_string(),
                y: "y".to_string(),
                kid: device_kid.to_string(),
            },
            password_files,
            dev_authorization_code: None,
        }],
        hsm_keys: vec![],
    }
}

pub fn make_request(request_id: &str) -> HsmWorkerRequest {
    HsmWorkerRequest {
        request_id: request_id.to_string(),
        state_jws: TypedJws::new("state.jws".to_string()),
        outer_request_jws: TypedJws::new("outer.jws".to_string()),
    }
}

pub fn make_outer(context: &str, session_id: Option<SessionId>) -> OuterRequest {
    OuterRequest {
        version: 1,
        session_id,
        context: context.to_string(),
        inner_jwe: Some(TypedJwe::new("inner.jwe".to_string())),
    }
}

pub fn make_ports(worker_response: Arc<dyn WorkerResponseSpiPort + Send + Sync>) -> WorkerPorts {
    WorkerPorts {
        session_state: Arc::new(MockSessionStateSpi),
        hsm: Arc::new(MockHsmSpi),
        worker_response,
        pake: Arc::new(MockPake {
            auth_start_succeeds: false,
        }),
    }
}
