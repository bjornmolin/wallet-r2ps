use crate::domain::WorkerResponse;

/// Use case port for handling incoming worker responses.
#[async_trait::async_trait]
pub trait ResponseUseCase: Send + Sync {
    async fn response_ready(&self, response: WorkerResponse);
    async fn wait_for_response(
        &self,
        request_id: &str,
        timeout_ms: u64,
    ) -> Option<crate::domain::CachedResponse>;
}
