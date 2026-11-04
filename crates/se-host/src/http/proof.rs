//! Anonymous server authentication only; never credential issuance. Nonces
//! expire after 30 seconds, remain single-use in that window, and have a cap.
use crate::{HostedRouter, client::lease::Deadline};
use se_types::{Result, SeError};
use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(crate) struct Challenges(Mutex<BTreeMap<[u8; 32], Instant>>);
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Challenge {
    pub nonce: [u8; 32],
}
impl HostedRouter {
    pub(crate) async fn local_http_proof(
        &self,
        input: Challenge,
        port: u16,
        deadline: &Deadline,
    ) -> Result<serde_json::Value> {
        self.check_open()?;
        {
            let mut retained = self.execution.http_proofs.0.lock().map_err(|_| {
                se_core::scope::unreadable("HTTP proof challenges", "registry is poisoned")
            })?;
            let now = Instant::now();
            retained.retain(|_, expires| *expires > now);
            if retained.contains_key(&input.nonce) {
                return Err(SeError::invalid(
                    "HTTP proof challenge",
                    "a fresh single-use nonce",
                ));
            }
            if retained.len() >= 64 {
                return Err(SeError::invalid(
                    "HTTP proof capacity",
                    "retry after a retained challenge expires",
                ));
            }
            retained.insert(input.nonce, now + Duration::from_secs(30));
        }
        let context = self.context.clone();
        let image = self.image_sha256;
        self.execution
            .blocking
            .run_owned(deadline, move || {
                context.http_proof(input.nonce, format!("http://127.0.0.1:{port}"), image)
            })
            .await
    }
}
