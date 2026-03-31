use crate::application::jose_port::{JoseError, JosePort, JweDecryptionKey, JweEncryptionKey};
use crate::application::service::worker_service::decode::RequestDecoder;
use crate::application::service::worker_service::error::{OuterError, UpstreamError, WorkerError};
use crate::application::service::worker_service::test_utils::{
    make_outer, make_request, make_state,
};
use crate::domain::EcPublicJwk;
use rstest::rstest;
use std::sync::Arc;

struct StubJose {
    /// `None` causes `jws_verify_server` to fail with `VerifyError`.
    server_bytes: Option<Vec<u8>>,
    /// `None` causes `peek_kid` to fail with `InvalidKey`; `Some(None)` returns `Ok(None)`.
    peek_kid_result: Option<Option<String>>,
    /// `None` causes `jws_verify_device` to fail with `VerifyError`.
    device_bytes: Option<Vec<u8>>,
}

impl JosePort for StubJose {
    fn jws_sign(&self, _payload_json: &[u8]) -> Result<String, JoseError> {
        unimplemented!()
    }
    fn jws_verify_server(&self, _jws: &str) -> Result<Vec<u8>, JoseError> {
        self.server_bytes.clone().ok_or(JoseError::VerifyError)
    }
    fn jws_verify_device(&self, _jws: &str, _key: &EcPublicJwk) -> Result<Vec<u8>, JoseError> {
        self.device_bytes.clone().ok_or(JoseError::VerifyError)
    }
    fn jwe_encrypt(
        &self,
        _payload: &[u8],
        _key: JweEncryptionKey<'_>,
    ) -> Result<String, JoseError> {
        unimplemented!()
    }
    fn jwe_decrypt(&self, _jwe: &str, _key: JweDecryptionKey<'_>) -> Result<Vec<u8>, JoseError> {
        unimplemented!()
    }
    fn peek_kid(&self, _compact: &str) -> Result<Option<String>, JoseError> {
        self.peek_kid_result.clone().ok_or(JoseError::InvalidKey)
    }
}

#[rstest]
#[case::server_verify_fails(
    StubJose { server_bytes: None, peek_kid_result: None, device_bytes: None },
    WorkerError::Upstream(UpstreamError::InvalidStateJws),
)]
#[case::peek_kid_returns_none(
    StubJose {
        server_bytes: Some(serde_json::to_vec(&make_state("device-kid")).unwrap()),
        peek_kid_result: Some(None),
        device_bytes: None,
    },
    WorkerError::Upstream(UpstreamError::OuterJwsMissingKid),
)]
#[case::kid_not_in_state(
    StubJose {
        server_bytes: Some(serde_json::to_vec(&make_state("device-kid")).unwrap()),
        peek_kid_result: Some(Some("unknown-kid".to_string())),
        device_bytes: None,
    },
    WorkerError::Upstream(UpstreamError::UnknownDevice),
)]
fn test_decode_outer_error(#[case] stub: StubJose, #[case] expected: WorkerError) {
    let decoder = RequestDecoder::new(Arc::new(stub));
    assert_eq!(
        decoder.decode_outer(make_request("req")).err().unwrap(),
        expected
    );
}

#[test]
fn test_decode_outer_returns_unsupported_context_when_context_is_not_hsm() {
    let state = make_state("device-kid");
    let outer = make_outer("not-hsm", None);
    let jose = Arc::new(StubJose {
        server_bytes: Some(serde_json::to_vec(&state).unwrap()),
        peek_kid_result: Some(Some("device-kid".to_string())),
        device_bytes: Some(serde_json::to_vec(&outer).unwrap()),
    });
    let decoder = RequestDecoder::new(jose);

    assert!(matches!(
        decoder.decode_outer(make_request("req")),
        Err(WorkerError::Outer(OuterError::UnsupportedContext))
    ));
}
