// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

#[derive(Debug, Clone)]
pub struct OpaqueConfig {
    pub opaque_server_setup: Option<String>,
    pub opaque_context: String,
    pub opaque_server_identifier: String,
}
