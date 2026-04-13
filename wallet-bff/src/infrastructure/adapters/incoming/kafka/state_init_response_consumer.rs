// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

use rdkafka::ClientConfig;
use rdkafka::Message;
use rdkafka::consumer::{Consumer, StreamConsumer};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::application::port::outgoing::{DeviceStatePort, PendingContextPort};
use crate::domain::StateInitResponse;
use crate::infrastructure::adapters::incoming::kafka::state_init_cache::StateInitResponseCache;

const STATE_INIT_RESPONSES_TOPIC: &str = "state-init-responses";

/// Starts a background task that consumes from state-init-responses, saves device state
/// to Redis, and notifies the in-memory cache so the HTTP handler can return the result.
pub fn start(
    bootstrap_servers: &str,
    group_id: &str,
    device_state_port: Arc<dyn DeviceStatePort>,
    pending_context_port: Arc<dyn PendingContextPort>,
    cache: Arc<StateInitResponseCache>,
) {
    let consumer: StreamConsumer = ClientConfig::new()
        .set("bootstrap.servers", bootstrap_servers)
        .set("group.id", group_id)
        .set("enable.auto.commit", "true")
        .set("auto.offset.reset", "earliest")
        .set("session.timeout.ms", "6000")
        .set("heartbeat.interval.ms", "2000")
        .set("partition.assignment.strategy", "cooperative-sticky")
        .create()
        .expect("Failed to create state-init-responses consumer");

    consumer
        .subscribe(&[STATE_INIT_RESPONSES_TOPIC])
        .expect("Failed to subscribe to state-init-responses");

    info!("Starting state-init-responses consumer");

    tokio::spawn(async move {
        loop {
            match consumer.recv().await {
                Ok(msg) => {
                    let Some(payload) = msg.payload() else {
                        continue;
                    };
                    let response: StateInitResponse = match serde_json::from_slice(payload) {
                        Ok(r) => r,
                        Err(e) => {
                            error!(
                                "Failed to deserialize StateInitResponse: {} - payload: {}",
                                e,
                                String::from_utf8_lossy(payload)
                            );
                            continue;
                        }
                    };

                    info!(
                        "Received state-init response for requestId: {}",
                        response.request_id
                    );

                    let ctx = pending_context_port.load(&response.request_id).await;
                    let Some(ctx) = ctx else {
                        warn!(
                            "No pending context for state-init requestId: {}, ignoring",
                            response.request_id
                        );
                        cache.put(response.request_id.clone(), response).await;
                        continue;
                    };

                    device_state_port
                        .save(&ctx.state_key, &response.state_jws, ctx.ttl_seconds)
                        .await;

                    cache.put(response.request_id.clone(), response).await;
                }
                Err(e) => {
                    error!("Kafka consumer error on state-init-responses: {}", e);
                }
            }
        }
    });
}
