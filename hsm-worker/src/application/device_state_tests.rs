// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

#[cfg(test)]
mod tests {
    use crate::application::device_state::DeviceStateError;
    use crate::application::port::outgoing::jose_port::{JoseError, MockJosePort};
    use crate::domain::DeviceHsmState;

    fn make_state() -> DeviceHsmState {
        DeviceHsmState {
            version: 1,
            device_keys: vec![],
            hsm_keys: vec![],
        }
    }

    #[test]
    fn sign_passes_correct_json_bytes_to_jws_sign() {
        let state = make_state();
        let mut mock = MockJosePort::new();
        mock.expect_jws_sign()
            .withf(|b| b == br#"{"version":1,"device_keys":[],"hsm_keys":[]}"#)
            .returning(|_| Ok("a.b.c".to_string()));

        let result = state.sign(&mock);

        assert_eq!(result.unwrap().as_str(), "a.b.c");
    }

    #[test]
    fn sign_propagates_sign_error() {
        let state = make_state();
        let mut mock = MockJosePort::new();
        mock.expect_jws_sign()
            .returning(|_| Err(JoseError::SignError));

        assert_eq!(state.sign(&mock).unwrap_err(), DeviceStateError::SignError);
    }

    #[test]
    fn from_jws_passes_jws_string_to_verify_server() {
        let bytes = serde_json::to_vec(&make_state()).unwrap();
        let mut mock = MockJosePort::new();
        mock.expect_jws_verify_server()
            .withf(|s| s == "header.payload.sig")
            .returning(move |_| Ok(bytes.clone()));

        assert!(DeviceHsmState::from_jws("header.payload.sig", &mock).is_ok());
    }

    #[test]
    fn from_jws_success_deserializes_state() {
        let expected = make_state();
        let bytes = serde_json::to_vec(&expected).unwrap();
        let mut mock = MockJosePort::new();
        mock.expect_jws_verify_server()
            .returning(move |_| Ok(bytes.clone()));

        let result = DeviceHsmState::from_jws("any.jws.token", &mock).unwrap();

        assert_eq!(result.version, expected.version);
        assert_eq!(result.device_keys.len(), expected.device_keys.len());
        assert_eq!(result.hsm_keys.len(), expected.hsm_keys.len());
    }

    #[test]
    fn from_jws_propagates_verify_error() {
        let mut mock = MockJosePort::new();
        mock.expect_jws_verify_server()
            .returning(|_| Err(JoseError::VerifyError));

        assert_eq!(
            DeviceHsmState::from_jws("any.jws.token", &mock).unwrap_err(),
            DeviceStateError::VerifyError
        );
    }

    #[test]
    fn from_jws_invalid_json_returns_verify_error() {
        let mut mock = MockJosePort::new();
        mock.expect_jws_verify_server()
            .returning(|_| Ok(b"not valid json".to_vec()));

        assert_eq!(
            DeviceHsmState::from_jws("any.jws.token", &mock).unwrap_err(),
            DeviceStateError::VerifyError
        );
    }
}
