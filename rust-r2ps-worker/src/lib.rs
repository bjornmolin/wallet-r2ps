use crate::application::{OpaqueConfig, WorkerPorts, WorkerService, load_pem_from_base64};
use crate::infrastructure::config::app_config::AppConfig;
use crate::infrastructure::hsm_wrapper::HsmWrapper;
use crate::infrastructure::pending_auth_memory_cache::PendingAuthMemoryCache;
use crate::infrastructure::r2ps_response_kafka_message_sender::WorkerResponseKafkaSender;
use crate::infrastructure::session_key_memory_cache::SessionKeyMemoryCache;
use crate::infrastructure::{KafkaConfig, WorkerRequestKafkaReceiver};
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

    let server_public_key: pem::Pem = load_pem_from_base64(&app_config.server_public_key)
        .expect("Failed to load SERVER_PUBLIC_KEY");
    let server_private_key = load_pem_from_base64(&app_config.server_private_key)
        .expect("Failed to load SERVER_PRIVATE_KEY");

    let ports = WorkerPorts {
        worker_response: Arc::new(WorkerResponseKafkaSender::new(&kafka_config)),
        session_key: Arc::new(SessionKeyMemoryCache::new()),
        hsm: Arc::new(HsmWrapper::new(app_config.clone().into()).unwrap()),
        pending_auth: Arc::new(PendingAuthMemoryCache::new()),
    };

    let opaque_config: OpaqueConfig = app_config.into();

    let worker_service = Arc::new(WorkerService::new(
        server_public_key,
        server_private_key,
        ports,
        opaque_config,
    ));

    let worker_kafka_receiver = WorkerRequestKafkaReceiver::new(worker_service, running.clone());
    // start worker i.e. process requests to responses
    let join_handle = worker_kafka_receiver.start_worker_thread(kafka_config);

    info!("HSM worker started");

    // wait until worker thread finish
    let _ = join_handle.join();
}
