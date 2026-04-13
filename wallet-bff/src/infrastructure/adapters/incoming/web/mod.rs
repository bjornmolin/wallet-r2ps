// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

pub mod handlers;

use axum::Router;
use axum::routing::{get, post};
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use handlers::AppState;

#[derive(OpenApi)]
#[openapi(
    info(title = "wallet-bff", version = "0.1.0"),
    paths(
        handlers::task_response,
        handlers::service,
        handlers::legacy_service,
        handlers::create_state,
    ),
    components(schemas(
        crate::domain::BffRequest,
        crate::domain::NewStateRequestDto,
        crate::domain::NewStateResponseDto,
        crate::domain::AsyncResponseDto,
        crate::domain::AsyncResponseStatus,
        crate::domain::AsyncResponseError,
        crate::domain::EcPublicJwk,
        crate::domain::ProblemDetail,
    ))
)]
struct ApiDoc;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/hsm/v1/openapi.json", ApiDoc::openapi()))
        .route(
            "/hsm/v1/requests/{correlationId}",
            get(handlers::task_response),
        )
        .route("/hsm/v1/requests", post(handlers::service))
        .route("/hsm/v1/operations", post(handlers::legacy_service))
        .route("/hsm/v1/device-states", post(handlers::create_state))
        .with_state(state)
}
