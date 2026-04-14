// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

use axum::extract::{Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use serde::Deserialize;
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

use crate::application::port::outgoing::NoncePort;

pub struct ReplayProtectionState {
    pub nonce_port: Arc<dyn NoncePort>,
    pub nonce_ttl_seconds: u64,
}

#[derive(Deserialize)]
pub struct NonceParams {
    pub nonce: Option<String>,
}

pub async fn replay_protection(
    State(rp): State<Arc<ReplayProtectionState>>,
    Query(params): Query<NonceParams>,
    request: Request,
    next: Next,
) -> Response {
    // Skip GET requests (polling endpoint has no replay risk)
    // Skip /hsm/v1/device-states (state initialization, not subject to replay protection)
    if request.method() == axum::http::Method::GET
        || request.uri().path() == "/hsm/v1/device-states"
    {
        return next.run(request).await;
    }

    let instance = request.uri().path().to_string();

    // 1. Require nonce
    let nonce_str = match &params.nonce {
        Some(n) => n,
        None => {
            warn!("Missing 'nonce' query parameter on {}", instance);
            return super::problem_response(
                StatusCode::BAD_REQUEST,
                "Bad Request",
                Some("Missing required query parameter: 'nonce'."),
                &instance,
            );
        }
    };

    // 2. Validate nonce is a UUID
    if Uuid::parse_str(nonce_str).is_err() {
        warn!("Invalid nonce (not a UUID): {}", nonce_str);
        return super::problem_response(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            Some("The 'nonce' parameter must be a valid UUID."),
            &instance,
        );
    }

    // 3. Check/store nonce in Valkey
    match rp
        .nonce_port
        .try_store(nonce_str, rp.nonce_ttl_seconds)
        .await
    {
        Ok(true) => {} // New nonce, proceed
        Ok(false) => {
            warn!("Duplicate nonce detected: {}", nonce_str);
            return super::problem_response(
                StatusCode::CONFLICT,
                "Duplicate Request",
                Some("This nonce has already been used. Each request must have a unique nonce."),
                &instance,
            );
        }
        Err(e) => {
            tracing::error!("Nonce store error: {}", e);
            return super::problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                Some("Failed to validate request nonce."),
                &instance,
            );
        }
    }

    next.run(request).await
}
