use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use pem::Pem;
use serde::de;
use std::env;
use tracing::{debug, error};

pub fn load_pem_from_base64_env(env_var_name: &str) -> Result<Pem, LoadPemError> {
    match env::var(env_var_name) {
        Ok(pem_b64) => match BASE64_STANDARD.decode(&pem_b64) {
            Ok(decoded_bytes) => match pem::parse(&decoded_bytes) {
                Ok(client_public_key) => Ok(client_public_key),
                Err(_e) => {
                    error!("Invalid PEM in environment variable {}", env_var_name);
                    debug!(
                        "Decoded PEM content: {:?}",
                        String::from_utf8_lossy(&decoded_bytes)
                    );
                    Err(LoadPemError::InvalidPem)
                }
            },
            Err(e) => {
                error!(
                    "Invalid base64 PEM in environment variable {}: {}",
                    env_var_name, e
                );
                Err(LoadPemError::InvalidBase64Pem)
            }
        },
        Err(e) => {
            error!("Invalid environment variable {}: {}", env_var_name, e);
            Err(LoadPemError::EnvError)
        }
    }
}

#[derive(Debug, Clone)]
pub enum LoadPemError {
    InvalidBase64Pem,
    InvalidPem,
    EnvError,
}
