// SPDX-License-Identifier: LicenseRef-StateEngine-Proprietary
//! Constructor signature for se-host's commercial composition, not the public API.
//! The real se_host::embedded_factory function must have this exact type.
use secode_stateengine_api::HostFactory;
use std::sync::Arc;
use tokio::runtime::Handle;

pub type EmbeddedFactoryBuilder = fn(runtime: Handle) -> Arc<dyn HostFactory>;
