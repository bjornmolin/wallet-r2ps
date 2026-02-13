use crate::application::{R2psService, load_pem_from_base64};
use crate::infrastructure::config::app_config::AppConfig;
use crate::infrastructure::hsm_wrapper::HsmWrapper;
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

    let kafka_config: Arc<KafkaConfig> = Arc::new(app_config.clone().into());

    // Handle Ctrl+C
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        debug!("Received shutdown signal");
        r.store(false, Ordering::Relaxed);
    })
    .expect("Error setting Ctrl-C handler");

    // init server
    let r2ps_kafka_sender = Arc::new(R2psResponseKafkaMessageSender::new(&kafka_config));
    let session_key_cache = Arc::new(SessionKeyMemoryCache::new());
    let pending_auth_cache = Arc::new(PendingAuthMemoryCache::new());

    let server_public_key: pem::Pem = load_pem_from_base64(&app_config.server_public_key)
        .expect("Failed to load SERVER_PUBLIC_KEY");
    let server_private_key = load_pem_from_base64(&app_config.server_private_key)
        .expect("Failed to load SERVER_PRIVATE_KEY");

    let hsm_wrapper = Arc::new(HsmWrapper::new(app_config.clone().into()).unwrap());
    let r2ps_service = Arc::new(R2psService::new(
        server_public_key,
        server_private_key,
        app_config.opaque_server_setup.clone(),
        r2ps_kafka_sender,
        session_key_cache,
        hsm_wrapper,
        pending_auth_cache,
        app_config.opaque_context.clone(),
        app_config.opaque_server_identifier.clone(),
    ));

    let r2ps_kafka_receiver = R2psRequestKafkaMessageReceiver::new(r2ps_service, running.clone());
    // start worker i.e. process requests to responses
    let join_handle = r2ps_kafka_receiver.start_worker_thread(kafka_config);

    info!("HSM worker started");

    // wait until worker thread finish
    let _ = join_handle.join();
}
