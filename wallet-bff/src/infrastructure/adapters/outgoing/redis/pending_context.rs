// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tracing::error;

use crate::application::port::outgoing::PendingContextPort;
use crate::domain::PendingRequestContext;

const KEY_PREFIX: &str = "pending-ctx:";
const PENDING_TTL_SECONDS: u64 = 120;

pub struct PendingContextRedisAdapter {
    conn: ConnectionManager,
}

impl PendingContextRedisAdapter {
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl PendingContextPort for PendingContextRedisAdapter {
    async fn save(&self, request_id: &str, ctx: &PendingRequestContext) {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", KEY_PREFIX, request_id);
        let value = match serde_json::to_string(ctx) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to serialize PendingRequestContext: {}", e);
                return;
            }
        };
        if let Err(e) = conn
            .set_ex::<_, _, ()>(&key, &value, PENDING_TTL_SECONDS)
            .await
        {
            error!("Failed to save pending context for key {}: {}", key, e);
        }
    }

    async fn load(&self, request_id: &str) -> Option<PendingRequestContext> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", KEY_PREFIX, request_id);
        let raw: Option<String> = match conn.get(&key).await {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to load pending context for key {}: {}", key, e);
                return None;
            }
        };
        raw.and_then(|s| match serde_json::from_str(&s) {
            Ok(ctx) => Some(ctx),
            Err(e) => {
                error!("Failed to deserialize PendingRequestContext: {}", e);
                None
            }
        })
    }
}
