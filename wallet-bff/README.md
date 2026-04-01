# Wallet BFF

Axum-based REST API (BFF) that forwards requests to the R2PS worker via Kafka and caches state in Valkey.

## Dev tools

Install rust toolchain from [rustup](https://rustup.rs/).

Install the following rust-rdkafka
dependencies ([rdkafka installation instructions](https://github.com/fede1024/rust-rdkafka?tab=readme-ov-file#installation))
to build the project locally:

### Debian/Ubuntu

```bash
apt-get update && apt-get install -y \
    zlib1g zlib1g-dev \
    cmake \
    libssl-dev \
    libsasl2-dev \
    libzstd-dev
```

### OSX

```bash
brew install \
    zlib \
    cmake \
    openssl \
    cyrus-sasl \
    zstd
```

## Build and run

```bash
cargo run
```

## Testing

### Unit tests

```bash
cargo test
```

### Integration tests (Tier 2)

Integration tests use [testcontainers](https://crates.io/crates/testcontainers) to spin up real Kafka and Redis/Valkey containers. They are gated with `#[ignore]` and require Docker.

```bash
# Run all integration tests (serial — shared topic names)
cargo test -- --ignored --test-threads=1

# Run a single integration test
cargo test -- --ignored test_device_state_redis_round_trip

# Run all tests (unit + integration) in one go
cargo test -- --include-ignored --test-threads=1
```
