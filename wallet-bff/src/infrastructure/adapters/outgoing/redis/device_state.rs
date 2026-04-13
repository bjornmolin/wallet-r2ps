// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tracing::error;

use crate::application::port::outgoing::DeviceStatePort;

pub struct DeviceStateRedisAdapter {
    conn: ConnectionManager,
}

impl DeviceStateRedisAdapter {
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl DeviceStatePort for DeviceStateRedisAdapter {
    async fn save(&self, key: &str, state: &str, ttl_seconds: u64) {
        let mut conn = self.conn.clone();
        if let Err(e) = conn.set_ex::<_, _, ()>(key, state, ttl_seconds).await {
            error!("Failed to save device state for key {}: {}", key, e);
        }
    }

    async fn load(&self, key: &str) -> Option<String> {
        let mut conn = self.conn.clone();
        match conn.get::<_, Option<String>>(key).await {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to load device state for key {}: {}", key, e);
                None
            }
        }
    }
}
