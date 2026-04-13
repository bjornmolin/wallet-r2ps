// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

use std::time::Duration;

use crate::domain::{
    CachedResponse, HsmWorkerRequest, PendingRequestContext, StateInitRequest, StateInitResponse,
};

/// SPI port: load and save device state (JWS) in the state store.
#[async_trait::async_trait]
pub trait DeviceStatePort: Send + Sync {
    async fn save(&self, key: &str, state: &str, ttl_seconds: u64);
    async fn load(&self, key: &str) -> Option<String>;
}

/// SPI port: send worker requests to r2ps-requests.
#[async_trait::async_trait]
pub trait RequestSenderPort: Send + Sync {
    async fn send(&self, request: &HsmWorkerRequest, device_id: &str) -> Result<(), String>;
}

/// SPI port: send state-init requests to state-init-requests.
#[async_trait::async_trait]
pub trait StateInitSenderPort: Send + Sync {
    async fn send(&self, request: &StateInitRequest, device_id: &str) -> Result<(), String>;
}

/// SPI port: load and save pending request context.
#[async_trait::async_trait]
pub trait PendingContextPort: Send + Sync {
    async fn save(&self, request_id: &str, ctx: &PendingRequestContext);
    async fn load(&self, request_id: &str) -> Option<PendingRequestContext>;
}

/// SPI port: store and load cached worker responses for polling.
#[async_trait::async_trait]
pub trait ResponseSinkPort: Send + Sync {
    async fn store(&self, response: &CachedResponse);
    async fn load(&self, request_id: &str) -> Option<CachedResponse>;
}

/// SPI port: in-memory cache for state-init responses, shared between the Kafka consumer
/// and the HTTP request handler that polls for the result.
#[async_trait::async_trait]
pub trait StateInitCachePort: Send + Sync {
    /// Block until a response for `request_id` appears or `timeout` elapses.
    async fn wait_for_response(
        &self,
        request_id: &str,
        timeout: Duration,
    ) -> Option<StateInitResponse>;

    /// Insert a response into the cache.
    async fn put(&self, request_id: String, response: StateInitResponse);
}
