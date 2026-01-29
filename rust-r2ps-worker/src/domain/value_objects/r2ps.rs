use crate::domain::DeviceHsmState;
use crate::domain::EcPublicJwk;
use base64::DecodeError;
use josekit::JoseError;
use pem::Pem;
use serde::{Deserialize, Serialize};
use std::string::FromUtf8Error;
use std::time::Duration;
use strum_macros::Display;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct R2psRequestDto {
    pub request_id: String,
    pub wallet_id: String, // remove later? device_id or client_id?
    pub device_id: String, // remove later? device_id or client_id?
    pub state_jws: String,
    pub service_request_jws: String,
}

// Define your output message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct R2psResponseDto {
    pub request_id: String,
    pub wallet_id: String, // remove later? device_id or client_id?
    pub device_id: String, // remove later? device_id or client_id?
    pub http_status: u16,
    pub state_jws: String,
    pub service_response_jws: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct R2psRequestJws {
    pub request_id: String,
    pub wallet_id: String, // remove later? device_id or client_id?
    pub device_id: String, // remove later? device_id or client_id?
    pub state_jws: String,
    pub outer_request_jws: String,
}

// Define your output message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct R2psResponseJws {
    pub request_id: String,
    pub wallet_id: String, // remove later? device_id or client_id?
    pub device_id: String, // remove later? device_id or client_id?
    pub http_status: u16,
    pub state_jws: String,
    pub service_response_jws: String,
}

// Define your output message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct R2psResponse {
    pub state: DeviceHsmState, // change to jws later
    pub payload: OuterResponse,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OuterRequest {
    pub client_id: String,
    pub kid: String,
    pub context: String,
    #[serde(rename = "type")]
    pub service_type: OperationId,
    pub pake_session_id: Option<String>,
    #[serde(rename = "ver")]
    pub version: Option<String>,
    pub nonce: Option<String>,
    pub enc: Option<EncryptOption>,
    pub inner_jwe: Option<super::InnerJwe>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum OuterResponse {
    Pake(PakeResponsePayload),
    CreateKey(CreateKeyServiceDataResponse),
    DeleteKey(DeleteKeyServiceData),
    ListKeys(ListKeysResponse),
    Asn1Signature(Vec<u8>),
}

impl OuterResponse {
    pub fn serialize(&self) -> Result<Vec<u8>, ServiceRequestError> {
        match self {
            Self::Pake(p) => serde_json::to_vec(p),
            Self::CreateKey(p) => serde_json::to_vec(p),
            Self::DeleteKey(p) => serde_json::to_vec(p),
            Self::ListKeys(p) => serde_json::to_vec(p),
            Self::Asn1Signature(p) => return Ok(p.clone()),
        }
        .map_err(|_| ServiceRequestError::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationId {
    AuthenticateStart,
    AuthenticateFinish,
    RegisterStart,
    RegisterFinish,
    PinChange,
    HsmEcdsa,
    HsmEcdh,
    #[serde(rename = "hsm_ec_keygen")]
    HsmEcKeygen,
    #[serde(rename = "hsm_ec_delete_key")]
    HsmEcDeleteKey,
    HsmListKeys,
    SessionEnd,
    SessionContextEnd,
    Store,
    Retrieve,
    Log,
    GetLog,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptOption {
    User,
    Device,
}

impl EncryptOption {
    pub fn as_str(&self) -> &'static str {
        match self {
            EncryptOption::User => "user",
            EncryptOption::Device => "device",
        }
    }
}

impl OperationId {
    pub fn encrypt_option(&self) -> EncryptOption {
        match self {
            OperationId::AuthenticateStart => EncryptOption::Device,
            OperationId::AuthenticateFinish => EncryptOption::Device,
            OperationId::RegisterStart => EncryptOption::Device,
            OperationId::RegisterFinish => EncryptOption::Device,
            OperationId::PinChange => EncryptOption::User,
            OperationId::HsmEcdsa => EncryptOption::User,
            OperationId::HsmEcdh => EncryptOption::User,
            OperationId::HsmEcKeygen => EncryptOption::User,
            OperationId::HsmEcDeleteKey => EncryptOption::User,
            OperationId::HsmListKeys => EncryptOption::User,
            OperationId::SessionEnd => EncryptOption::Device,
            OperationId::SessionContextEnd => EncryptOption::Device,
            OperationId::Store => EncryptOption::User,
            OperationId::Retrieve => EncryptOption::User,
            OperationId::Log => EncryptOption::User,
            OperationId::GetLog => EncryptOption::User,
            OperationId::Info => EncryptOption::User,
        }
    }
}

/// Converts a `std::time::Duration` to an ISO 8601 duration (seconds only)
pub fn to_iso8601_duration(d: Duration) -> iso8601_duration::Duration {
    iso8601_duration::Duration::new(0.0, 0.0, 0.0, 0.0, 0.0, d.as_secs() as f32)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PakeResponsePayload {
    /// The PAKE session ID assigned by the server
    #[serde(rename = "pake_session_id")]
    pub pake_session_id: Option<String>,

    /// The session task recognized by the server bound to this pake session ID
    #[serde(rename = "task")]
    pub task: Option<String>,

    /// PAKE response data as defined by the PAKE state incoming the request
    #[serde(rename = "resp")]
    pub response_data: Option<String>,

    #[serde(rename = "msg")]
    pub message: Option<String>,

    #[serde(rename = "expires_in")]
    pub expires_in: Option<iso8601_duration::Duration>,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone, Display)]
pub enum Curve {
    #[serde(rename = "P-256")]
    #[strum(serialize = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    #[strum(serialize = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    #[strum(serialize = "P-521")]
    P521,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateKeyServiceData {
    pub curve: Curve,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateKeyServiceDataResponse {
    pub public_key: EcPublicJwk,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeleteKeyServiceData {
    pub kid: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListKeysResponse {
    pub key_info: Vec<KeyInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyInfo {
    pub created_at: Option<String>,
    pub public_key: EcPublicJwk,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListKeysRequest {
    // TODO finns någon filteringspayload i Stefans kod....
}

mod base64_serde {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignRequest {
    pub kid: String,
    #[serde(with = "base64_serde")]
    pub tbs_hash: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub ver: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<iso8601_duration::Duration>,
    pub enc: String,
    pub data: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PakeProtocol {
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PakeState {
    Evaluate,
    Finalize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PakeRequestPayload {
    /// Identifies the PAKE protocol
    #[serde(rename = "protocol")]
    pub protocol: PakeProtocol,

    /// Optional authorization data required for initial PIN registrations or PIN resets
    #[serde(rename = "authorization", skip_serializing_if = "Option::is_none")]
    pub authorization: Option<String>,

    #[serde(rename = "task", skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,

    /// The PAKE request data as defined by the PAKE state
    #[serde(rename = "req")]
    pub request_data: String,
}

impl PakeRequestPayload {
    /// Serializes the payload to bytes
    pub fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserializes the payload from bytes
    pub fn deserialize(data: Vec<u8>) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data.as_slice())
    }
}

#[derive(Debug, Clone)]
pub struct R2psServerConfig {
    //pub private_key_jwk: Jwk,
    pub server_public_key: Pem,
    pub server_private_key: Pem,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display)]
pub enum ServiceRequestError {
    JwsError,
    JweError,
    InvalidPakeRequestPayload,
    InvalidRegistrationRequest,
    ServerRegistrationStartFailed,
    ServerLoginStartFailed,
    ServerLoginFinishFailed,
    SerializeResponseError,
    SerializeStateError,
    InvalidServiceRequestFormat,
    InvalidSerializedPasswordFile,
    InvalidAuthenticateRequest,
    UnknownKey,
    UnknownSession,
    UnknownClient,
    InvalidClientPublicKey,
    UnsupportedContext,
    InternalServerError,
    Unknown,
}

impl From<DecodeError> for ServiceRequestError {
    fn from(_: DecodeError) -> Self {
        ServiceRequestError::JweError
    }
}

impl From<FromUtf8Error> for ServiceRequestError {
    fn from(_: FromUtf8Error) -> Self {
        ServiceRequestError::JweError
    }
}

impl From<JoseError> for ServiceRequestError {
    fn from(_: JoseError) -> Self {
        ServiceRequestError::JweError
    }
}

#[derive(Debug)]
pub enum R2psRequestError {
    ConnectionError,
    UnknownClient,
    OuterJwsError,
    DecryptionError,
    EncryptionError,
    UnsupportedContext,
    NotImplemented,
    ServiceError(ServiceRequestError),
    InvalidState,
    UnknownSession,
    InnerJweError,
}
