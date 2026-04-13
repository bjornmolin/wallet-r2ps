// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

use crate::domain::{HsmWorkerRequest, WorkerRequestError};

pub trait WorkerRequestUseCase {
    fn execute(
        &self,
        hsm_worker_request: HsmWorkerRequest,
    ) -> Result<WorkerRequestId, WorkerRequestError>;
}

pub type WorkerRequestId = String;
