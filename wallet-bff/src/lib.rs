// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

pub mod application;
pub mod domain;
pub mod infrastructure;

pub async fn run() {
    infrastructure::bootstrap::run().await;
}
