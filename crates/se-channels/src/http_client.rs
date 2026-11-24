//! A provider HTTP client built on first use. Building one loads the platform's
//! TLS trust roots, which a host with no connected channel never needs.
use super::{ChannelError, ChannelResult};
use std::sync::OnceLock;

pub(crate) struct LazyClient {
    build: fn() -> reqwest::ClientBuilder,
    client: OnceLock<reqwest::Client>,
}
impl LazyClient {
    pub(crate) const fn new(build: fn() -> reqwest::ClientBuilder) -> Self {
        Self {
            build,
            client: OnceLock::new(),
        }
    }
    /// A client the caller already configured, for the local wire fixture.
    #[cfg(all(target_os = "linux", any(test, feature = "test-fixture")))]
    pub(crate) fn built(client: reqwest::Client) -> Self {
        Self {
            build: reqwest::Client::builder,
            client: OnceLock::from(client),
        }
    }
    /// The configured client. A failed build sends nothing and is retried on
    /// the next call; concurrent first calls may each build, and one is kept.
    pub(crate) fn get(&self) -> ChannelResult<&reqwest::Client> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let built = (self.build)()
            .build()
            .map_err(|_| ChannelError::ProviderUnreachable)?;
        Ok(self.client.get_or_init(|| built))
    }
}
