use crate::application::R2psService;
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
    infrastructure::config::init();
    let cfg = Arc::new(KafkaConfig::init().unwrap());
    let help = KafkaConfig::get_help();
    debug!("{:#?}", help);

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

    let hsm_wrapper = Arc::new(HsmWrapper::new(Pkcs11Config::new_from_env().unwrap()).unwrap());
    let r2ps_service = Arc::new(R2psService::new(
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
