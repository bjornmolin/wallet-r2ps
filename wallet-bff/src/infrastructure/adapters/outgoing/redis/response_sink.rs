// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tracing::error;

use crate::application::port::outgoing::ResponseSinkPort;
use crate::domain::CachedResponse;

pub struct ResponseSinkRedisAdapter {
    conn: ConnectionManager,
    response_ttl_seconds: u64,
}

impl ResponseSinkRedisAdapter {
    pub fn new(conn: ConnectionManager, response_ttl_seconds: u64) -> Self {
        Self {
            conn,
            response_ttl_seconds,
        }
    }
}

#[async_trait::async_trait]
impl ResponseSinkPort for ResponseSinkRedisAdapter {
    async fn store(&self, response: &CachedResponse) {
        let mut conn = self.conn.clone();
        let value = match serde_json::to_string(response) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to serialize CachedResponse: {}", e);
                return;
            }
        };
        if let Err(e) = conn
            .set_ex::<_, _, ()>(&response.request_id, &value, self.response_ttl_seconds)
            .await
        {
            error!(
                "Failed to store response for requestId {}: {}",
                response.request_id, e
            );
        }
    }

    async fn load(&self, request_id: &str) -> Option<CachedResponse> {
        let mut conn = self.conn.clone();
        let raw: Option<String> = match conn.get(request_id).await {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Failed to load response for requestId {}: {}",
                    request_id, e
                );
                return None;
            }
        };
        raw.and_then(|s| match serde_json::from_str(&s) {
            Ok(r) => Some(r),
            Err(e) => {
                error!("Failed to deserialize CachedResponse: {}", e);
                None
            }
        })
    }
}
