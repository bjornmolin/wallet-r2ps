// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

//! HTTP REST client for the BFF.
//!
//! Endpoints:
//!   POST /hsm/v1/device-states      -> Initialize device, get clientId + authCode
//!   POST /hsm/v1/requests           -> Submit request (sync or async mode)

use anyhow::{bail, Context, Result};
use reqwest::Client;
use std::time::Duration;

use crate::protocol::types::{
    BffNewStateRequest, BffNewStateResponse, BffRequest, BffSyncResponse,
};

pub struct RestClient {
    client: Client,
    base_url: String,
}

impl RestClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// POST /hsm/v1/device-states
    /// Initialize a new device state. Returns clientId and authorization code.
    pub async fn create_device_state(
        &self,
        request: &BffNewStateRequest,
    ) -> Result<BffNewStateResponse> {
        let url = format!("{}/hsm/v1/device-states", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(request)
            .send()
            .await
            .context("POST /device-states failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("POST /device-states failed: {} -- {}", status, body);
        }

        resp.json::<BffNewStateResponse>()
            .await
            .context("Failed to parse BffNewStateResponse")
    }

    /// POST /hsm/v1/requests
    /// Submit a service request. Handles both sync (200) and async (202) responses.
    /// Retries on 404 to handle the race condition where device-states returns
    /// before the state-snapshot consumer has cached the device.
    pub async fn submit_request(
        &self,
        client_id: &str,
        outer_request_jws: &str,
    ) -> Result<BffSyncResponse> {
        let url = format!("{}/hsm/v1/requests", self.base_url);
        let body = BffRequest {
            client_id: client_id.to_string(),
            outer_request_jws: outer_request_jws.to_string(),
        };

        let max_retries = 5;
        let base_delay = Duration::from_millis(200);

        for attempt in 0..=max_retries {
            let resp = self
                .client
                .post(&url)
                .json(&body)
                .send()
                .await
                .context("POST / failed")?;

            if resp.status().is_success() {
                let sync_resp = resp
                    .json::<BffSyncResponse>()
                    .await
                    .context("Failed to parse BffSyncResponse")?;

                // If the BFF returned a pending/async response, poll for completion
                if sync_resp.status == "pending" {
                    if let Some(poll_url) = &sync_resp.result_url {
                        return self.poll_for_result(poll_url).await;
                    }
                }

                return Ok(sync_resp);
            }

            // Retry on 404 (state-snapshot race condition)
            if resp.status().as_u16() == 404 && attempt < max_retries {
                let _ = resp.text().await; // drain body
                tokio::time::sleep(base_delay * (attempt as u32 + 1)).await;
                continue;
            }

            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("POST / failed: {} -- {}", status, text);
        }

        bail!("POST /hsm/v1/requests exhausted retries");
    }

    /// Poll a result URL until the response status is no longer "pending".
    async fn poll_for_result(&self, url: &str) -> Result<BffSyncResponse> {
        let max_polls = 50;
        let poll_interval = Duration::from_millis(200);

        for _ in 0..max_polls {
            tokio::time::sleep(poll_interval).await;
            let resp = self
                .client
                .get(url)
                .send()
                .await
                .context("GET poll request failed")?;

            let body = resp
                .json::<BffSyncResponse>()
                .await
                .context("Failed to parse poll response")?;

            if body.status != "pending" {
                return Ok(body);
            }
        }

        bail!("Polling exhausted for {}", url);
    }
}
