#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wallet_bff=info,rdkafka=warn,redis=warn".into()),
        )
        .init();

    wallet_bff::run().await;
}
