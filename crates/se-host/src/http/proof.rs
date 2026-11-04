//! Anonymous server authentication only; never credential issuance. Nonces
//! expire after five seconds, remain single-use in that window, and have a cap.
use crate::{HostedRouter, client::lease::Deadline};
use se_types::{Result, SeError};
use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(crate) struct Challenges(Mutex<BTreeMap<[u8; 32], Instant>>);
const NONCE_TTL: Duration = Duration::from_secs(5);
impl Challenges {
    fn remember(&self, nonce: [u8; 32], now: Instant) -> Result<()> {
        let mut retained = self.0.lock().map_err(|_| {
            se_core::scope::unreadable("HTTP proof challenges", "registry is poisoned")
        })?;
        retained.retain(|_, expires| *expires > now);
        if retained.contains_key(&nonce) {
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
        retained.insert(nonce, now + NONCE_TTL);
        Ok(())
    }
}
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
        self.execution
            .http_proofs
            .remember(input.nonce, Instant::now())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonce_capacity_and_replay_retention_expire_within_five_seconds() -> Result<()> {
        let challenges = Challenges::default();
        let now = Instant::now();
        for n in 0..64 {
            challenges.remember([n; 32], now)?;
        }
        assert!(
            challenges
                .remember([64; 32], now + Duration::from_secs(4))
                .is_err()
        );
        assert!(
            challenges
                .remember([0; 32], now + Duration::from_secs(4))
                .is_err()
        );
        challenges.remember([64; 32], now + NONCE_TTL)?;
        assert_eq!(
            challenges
                .0
                .lock()
                .map_err(|_| SeError::invalid("nonce test", "an unpoisoned registry"))?
                .len(),
            1
        );
        Ok(())
    }
}
