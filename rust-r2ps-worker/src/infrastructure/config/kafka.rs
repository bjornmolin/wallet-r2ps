#[derive(Debug, Clone)]
pub struct KafkaConfig {
    pub bootstrap_servers: String,
    pub broker_address_family: String,
    pub group_id: String,
    pub group_instance_id: String,
}
