// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::warn;

use crate::application::port::outgoing::StateInitCachePort;
use crate::domain::StateInitResponse;

/// In-memory cache for state-init responses, shared between the consumer thread
/// and the HTTP request handler that polls for the result.
pub struct StateInitResponseCache {
    inner: Arc<Mutex<HashMap<String, StateInitResponse>>>,
}

impl Default for StateInitResponseCache {
    fn default() -> Self {
        Self::new()
    }
}

impl StateInitResponseCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Inherent method — called directly by the Kafka consumer.
    pub async fn put(&self, request_id: String, response: StateInitResponse) {
        self.inner.lock().await.insert(request_id, response);
    }

    /// Polls every 50 ms until the response for `request_id` appears or `timeout` elapses.
    /// Also available via the `StateInitCachePort` trait.
    pub async fn wait_for_response(
        &self,
        request_id: &str,
        timeout: Duration,
    ) -> Option<StateInitResponse> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut map = self.inner.lock().await;
                if let Some(resp) = map.remove(request_id) {
                    return Some(resp);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "Timeout waiting for state-init response for requestId: {}",
                    request_id
                );
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

#[async_trait::async_trait]
impl StateInitCachePort for StateInitResponseCache {
    async fn wait_for_response(
        &self,
        request_id: &str,
        timeout: Duration,
    ) -> Option<StateInitResponse> {
        self.wait_for_response(request_id, timeout).await
    }

    async fn put(&self, request_id: String, response: StateInitResponse) {
        self.put(request_id, response).await
    }
}
