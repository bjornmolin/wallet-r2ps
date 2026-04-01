use redis::Client;
use std::sync::Arc;
use tracing::info;

use crate::application::service::ResponseService;
use crate::infrastructure::adapters::incoming::kafka::{
    r2ps_response_consumer, state_init_cache::StateInitResponseCache, state_init_response_consumer,
};
use crate::infrastructure::adapters::incoming::web::{self, handlers::AppState};
use crate::infrastructure::adapters::outgoing::kafka::request_sender::{
    KafkaRequestSender, KafkaStateInitSender,
};
use crate::infrastructure::adapters::outgoing::redis::{
    device_state::DeviceStateRedisAdapter, pending_context::PendingContextRedisAdapter,
    response_sink::ResponseSinkRedisAdapter,
};
use crate::infrastructure::config::AppConfig;

pub async fn run() {
    let config = AppConfig::new().expect("Failed to load configuration");

    info!(
        "Starting wallet-bff on {}:{}",
        config.server_host, config.server_port
    );

    // Redis
    let redis_client = Client::open(config.redis_url()).expect("Failed to create Redis client");
    let conn_mgr = redis::aio::ConnectionManager::new(redis_client)
        .await
        .expect("Failed to connect to Redis");

    let device_state_port = Arc::new(DeviceStateRedisAdapter::new(conn_mgr.clone()));
    let pending_context_port = Arc::new(PendingContextRedisAdapter::new(conn_mgr.clone()));
    let response_sink_port = Arc::new(ResponseSinkRedisAdapter::new(
        conn_mgr.clone(),
        config.response_ttl_seconds,
    ));

    // Kafka producers
    let request_sender_port = Arc::new(KafkaRequestSender::new(
        &config.kafka_bootstrap_servers,
        &config.kafka_broker_address_family,
    ));
    let state_init_sender_port = Arc::new(KafkaStateInitSender::new(
        &config.kafka_bootstrap_servers,
        &config.kafka_broker_address_family,
    ));

    // Response use case
    let response_service = Arc::new(ResponseService::new(
        device_state_port.clone(),
        pending_context_port.clone(),
        response_sink_port.clone(),
    ));

    // State-init in-memory cache
    let state_init_cache = Arc::new(StateInitResponseCache::new());

    // Start Kafka consumers
    r2ps_response_consumer::start(
        &config.kafka_bootstrap_servers,
        &config.kafka_group_id,
        response_service.clone(),
    );

    state_init_response_consumer::start(
        &config.kafka_bootstrap_servers,
        &config.kafka_group_id,
        device_state_port.clone(),
        pending_context_port.clone(),
        state_init_cache.clone(),
    );

    // Build HTTP router
    let app_state = Arc::new(AppState {
        device_state_port,
        request_sender_port,
        state_init_sender_port,
        pending_context_port,
        response_use_case: response_service,
        state_init_cache,
        serve_sync: config.serve_sync,
        sync_timeout_ms: config.sync_timeout_ms,
        state_init_timeout_ms: config.state_init_timeout_ms,
        response_events_template_url: config.response_events_template_url.clone(),
    });

    let router = web::router(app_state);

    let bind_addr = format!("{}:{}", config.server_host, config.server_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind TCP listener");

    info!("Listening on {}", bind_addr);
    axum::serve(listener, router).await.expect("Server error");
}
