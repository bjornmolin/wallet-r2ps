// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

pub mod client_metadata;
#[cfg(test)]
mod client_metadata_tests;
pub mod error;
pub mod external;
pub mod hsm;
pub mod state_initialization;

pub use client_metadata::*;
pub use error::ServiceRequestError;
pub use external::{HsmWorkerRequest, HsmWorkerResponse};
pub use hsm::*;
pub use state_initialization::*;

// Re-export shared wire types from hsm-common.
pub use hsm_common::{
    CreateKeyServiceData, CreateKeyServiceDataResponse, Curve, DeleteKeyServiceData, EncryptOption,
    InnerRequest, InnerResponse, KeyInfo, ListKeysRequest, ListKeysResponse, MessageVector,
    OperationId, OuterRequest, OuterResponse, PakePayloadVector, PakeRequest, PakeResponse,
    PakeState, SessionId, SignRequest, SignatureResponse, SignatureVector, Status, TypedJwe,
    TypedJws,
};
