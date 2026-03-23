use crate::domain::{CachedResponse, HsmWorkerRequest, PendingRequestContext, StateInitRequest};

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
