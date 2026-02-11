use crate::application::{R2psService, load_pem_from_base64};
use crate::infrastructure::config::config::AppConfig;
use crate::infrastructure::hsm_wrapper::{HsmWrapper, Pkcs11Config};
use crate::infrastructure::pending_auth_memory_cache::PendingAuthMemoryCache;
use crate::infrastructure::r2ps_response_kafka_message_sender::R2psResponseKafkaMessageSender;
use crate::infrastructure::session_key_memory_cache::SessionKeyMemoryCache;
use crate::infrastructure::{KafkaConfig, R2psRequestKafkaMessageReceiver};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info};

pub mod application;
pub mod domain;
pub mod infrastructure;

// ============ Generate OpenAPI ============
// #[derive(OpenApi)]
// #[openapi(
//     components(schemas(
//         PermitListDto
//     ))
// )]
// pub struct ApiDoc;

pub fn run() {
    // config from env
    let app_config = AppConfig::new().unwrap();

    info!("CONFIG EFTER:{:?}", app_config.clone());

    let cfg = Arc::new(KafkaConfig {
        bootstrap_servers: app_config.kafka_bootstrap_servers,
        broker_address_family: app_config.kafka_broker_address_family,
        group_id: app_config.kafka_group_id,
        group_instance_id: app_config.kafka_group_instance_id,
    });

    // Handle Ctrl+C
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        debug!("Received shutdown signal");
        r.store(false, Ordering::Relaxed);
    })
    .expect("Error setting Ctrl-C handler");

    // init server
    let r2ps_kafka_sender = Arc::new(R2psResponseKafkaMessageSender::new(&cfg));
    let session_key_cache = Arc::new(SessionKeyMemoryCache::new());
    let pending_auth_cache = Arc::new(PendingAuthMemoryCache::new());

    let server_public_key: pem::Pem = load_pem_from_base64(&app_config.server_public_key)
        .expect("Failed to load SERVER_PUBLIC_KEY");
    let server_private_key = load_pem_from_base64(&app_config.server_private_key)
        .expect("Failed to load SERVER_PRIVATE_KEY");

    let hsm_wrapper = Arc::new(
        HsmWrapper::new(Pkcs11Config {
            lib_path: app_config.pkcs11_lib,
            slot_token_label: app_config.pkcs11_slot_token_label,
            so_pin: app_config.pkcs11_so_pin,
            user_pin: app_config.pkcs11_user_pin,
            wrap_key_alias: app_config.pkcs11_wrap_key_alias,
        })
        .unwrap(),
    );
    let r2ps_service = Arc::new(R2psService::new(
        server_public_key,
        server_private_key,
        app_config.server_setup,
        r2ps_kafka_sender,
        session_key_cache,
        hsm_wrapper,
        pending_auth_cache,
    ));

    let r2ps_kafka_receiver = R2psRequestKafkaMessageReceiver::new(r2ps_service, running.clone());
    // start worker i.e. process requests to responses
    let join_handle = r2ps_kafka_receiver.start_worker_thread(cfg.clone());

    info!("HSM worker started");

    // wait until worker thread finish
    let _ = join_handle.join();
}
