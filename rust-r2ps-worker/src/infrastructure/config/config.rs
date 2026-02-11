use config::{Config, ConfigError, Environment};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server_private_key: String, // base64 env pem (double encoded)
    pub server_public_key: String,  // base64 env pem (double encoded)
    pub server_setup: Option<String>,

    pub pkcs11_lib: String,
    pub pkcs11_slot_token_label: String,
    pub pkcs11_so_pin: Option<String>,
    pub pkcs11_user_pin: Option<String>,
    pub pkcs11_wrap_key_alias: String,
    /// bootstrap servers, comma separated list
    /// https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md
    pub kafka_bootstrap_servers: String,

    /// https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md
    pub kafka_broker_address_family: String,
    pub kafka_group_id: String,
    pub kafka_group_instance_id: String,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();
        Config::builder()
            .set_default("kafka_group_id", "rust-grp")?
            .set_default("kafka_group_instance_id", "consumer-1")?
            .set_default("kafka_broker_address_family", "v4")?
            .add_source(Environment::default())
            .build()?
            .try_deserialize()
    }
}
