//! Native machine setup controls are separate from agent data operations.
use super::*;
use se_types::{IdempotencyKey, Result, SeError};
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OwnerInput {
    #[cfg(feature = "remote")]
    Authorize(ssh::Authorization),
    Disconnect {
        alias: String,
        forget: bool,
    },
    Add {
        destination: String,
        alias: String,
        distribution: se_types::NativePath,
    },
    Bootstrap {
        source_host: RemoteHostId,
    },
    MachineIdentity,
    Disable,
    Grants {
        after: Option<RemoteGrantId>,
        limit: u16,
    },
    Revoke {
        grant: RemoteGrantId,
        authority_revision: u64,
        key: IdempotencyKey,
    },
}
impl OwnerInput {
    pub fn requires_terminal(&self) -> bool {
        matches!(
            self,
            Self::Disable | Self::Grants { .. } | Self::Revoke { .. }
        )
    }
    pub fn key(&self) -> Option<&IdempotencyKey> {
        match self {
            Self::Revoke { key, .. } => Some(key),
            _ => None,
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Disconnect { alias, .. } => se_core::ops::remote::validate_alias(alias),
            Self::Add {
                destination,
                alias,
                distribution,
            } => {
                se_core::ops::remote::validate_alias(alias)?;
                if !distribution.to_local()?.is_absolute() {
                    return Err(SeError::invalid(
                        "native distribution",
                        "the calling CLI's absolute executable path",
                    ));
                }
                #[cfg(feature = "remote")]
                ssh::validate_destination(destination)?;
                #[cfg(not(feature = "remote"))]
                let _ = destination;
                Ok(())
            }
            Self::Grants { limit, .. } if !(1..=100).contains(limit) => {
                Err(SeError::invalid("machine session limit", "1..100"))
            }
            Self::Revoke {
                authority_revision, ..
            } if *authority_revision == 0 || *authority_revision > i64::MAX as u64 => Err(
                SeError::invalid("machine authority revision", "a current nonzero revision"),
            ),
            _ => Ok(()),
        }
    }
}
#[cfg(feature = "remote")]
pub(crate) struct OwnerCall {
    pub owner: auth::VerifiedLocalOwner,
    pub input: OwnerInput,
}
