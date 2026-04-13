// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

use crate::domain::WorkerResponse;

pub trait WorkerResponseSpiPort {
    fn send(&self, worker_response: WorkerResponse) -> Result<(), WorkerResponseError>;
}

#[derive(Debug)]
pub enum WorkerResponseError {
    ConnectionError,
    // TODO
}
