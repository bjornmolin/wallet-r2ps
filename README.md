# wallet-r2ps

A Dockerized Rust worker designed for R2PS processing with SoftHSM token integration and Kafka messaging.

## Prerequisites

Before you begin, ensure you have the following installed on your machine:

*   **Docker** (v20.10+)
*   **Docker Compose** (v2.0+)
*   **Make** (v4.0+)

## Configuration

The project relies on environment variables stored in `.env` files.

1.  **Environment Files:**
    *   `.env.softhsm`: Configuration for SoftHSM tokens.
    *   `.env.opaque`: Opaque configuration secrets.

    *(Ensure these files are in the root directory and contain valid keys.)*

2.  **Kafka:**
    The worker connects to a local Kafka cluster.
    *   **Bootstrap Servers:** `kafka-1:19092,kafka-2:19092,kafka-3:19092`

3. **Platform specific configuration:**
   *    Create an .env file with custom config.
        Examples can be found in the repo
        [.env_linux](.env_linux) and [.env_mac](.env_mac)

## Usage

This project uses a `Makefile` to simplify common operations.

### Build container images

Build all containers in docker compose

```bash
make build
```

### Start the Service

Start the Kafka initialization and the Rust worker:

```bash
make up
```

### Copy SoftHSM Tokens
   To copy the tokens from the running container to your host machine (useful for debugging or backups):

```bash
make copy-tokens
```

### Verify the Copy
   Check if the directory was populated correctly on the host:

```bash
make verify-tokens
```

### Fix Permissions
   If you encounter "Permission Denied" errors when accessing the softhsm-tokens directory on your host, run this command to match the container's user permissions:

```bash
make fix-permissions
```

### View Logs
   Follow the logs of the Rust worker in real-time:

```bash
make logs
```
### Stop the Service
   Stop the containers:

```bash
make down
```

## Troubleshooting

### Permission Denied on softhsm-tokens
The container runs with a specific User ID (UID) and Group ID (GID). If the host directory ./softhsm-tokens is owned by a different user, you will see permission errors.

Solution: Run make fix-permissions after copying the tokens. This command uses sudo chown to match the current user's UID/GID with the container's expectations.

### Kafka Connection Issues
If the worker fails to start, check that the init-kafka service has completed successfully.

```
make logs
```

### Endpoints

* [Demo java klienten](http://localhost:9000/rhsm-client/)
* [Kafka UI](http://localhost:8080)
