//! A detached `never` profile rejects requests that need additional authority.
//! Decision identities are stable across uncertain responses and host recovery.
use super::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

impl LaunchCoordinator {
    pub(in crate::process) async fn deny_secode_approvals(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        let Some(managed) = &work.secode else {
            return Ok(());
        };
        let qualified = managed.current()?;
        qualified.binding(&managed.session, deadline).await?;
        let permissions = qualified
            .control
            .read(
                &["api", "session", &managed.session, "permission"],
                deadline,
            )
            .await?;
        let rows = complete(&permissions)?;
        let mut ids = std::collections::BTreeSet::new();
        for row in rows {
            if row["sessionID"] != managed.session || row["status"] != "pending" {
                return Err(error(
                    "SE Code automatic permission denial",
                    "a request is suspended, malformed or belongs to a different session; no authority was granted",
                ));
            }
            let id = row["id"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control))
                .ok_or_else(|| {
                    error(
                        "SE Code automatic permission denial",
                        "bounded permission ID absent",
                    )
                })?;
            if !ids.insert(id.to_owned()) {
                return Err(error(
                    "SE Code automatic permission denial",
                    "duplicate permission ID",
                ));
            }
            let hash = Sha256::digest(
                format!(
                    "{}/{}/{}",
                    qualified.service.incarnation, managed.session, id
                )
                .as_bytes(),
            );
            let key = se_types::hex_lower(&hash);
            qualified.binding(&managed.session, deadline).await?;
            qualified.control.request(reqwest::Method::POST,
                &["api", "session", &managed.session, "permission", id, "reply"],
                Some(&json!({"reply":"reject", "requestID":format!("req-{key}"), "nonce":format!("nonce-{key}"), "message":"The saved headless profile does not permit interactive approval."})), deadline,
            ).await?;
            qualified.binding(&managed.session, deadline).await?;
        }
        if !ids.is_empty() {
            let after = qualified
                .control
                .read(
                    &["api", "session", &managed.session, "permission"],
                    deadline,
                )
                .await?;
            if complete(&after)?
                .iter()
                .any(|row| row["id"].as_str().is_some_and(|id| ids.contains(id)))
            {
                return Err(error(
                    "SE Code automatic permission denial",
                    "an original request remains pending or suspended after rejection",
                ));
            }
        }
        qualified.binding(&managed.session, deadline).await?;
        Ok(())
    }
}

fn complete(value: &Value) -> Result<&Vec<Value>> {
    if value["hasMore"] != false {
        return Err(error(
            "SE Code permissions",
            "permission inventory is incomplete; no empty or settled result is implied",
        ));
    }
    value["data"]
        .as_array()
        .filter(|rows| rows.len() <= 512)
        .ok_or_else(|| error("SE Code permissions", "bounded permission array absent"))
}
