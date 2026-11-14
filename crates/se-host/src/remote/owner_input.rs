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
    PrepareAdd {
        destination: String,
        alias: String,
    },
    Bootstrap {
        source_host: RemoteHostId,
    },
    MachineIdentity,
    #[cfg(feature = "remote")]
    PairingLaunchPermissions {
        alias: String,
        after: Option<RemoteTarget>,
        change: Option<LaunchPermissionChange>,
    },
    #[cfg(feature = "remote")]
    LaunchPermissions(ssh::LaunchPermissionsRequest),
    #[cfg(feature = "remote")]
    PairingPermissions {
        alias: String,
        after: Option<RemoteAgentAddress>,
        change: Option<SourcePermissionChange>,
    },
    #[cfg(feature = "remote")]
    LocalPairingPermissions {
        after: Option<RemoteAgentAddress>,
        change: Option<SourcePermissionChange>,
    },
    #[cfg(feature = "remote")]
    SourcePermissions(ssh::PermissionsRequest),
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
#[cfg(feature = "remote")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPermissionChange {
    pub target: RemoteTarget,
    pub allowed: bool,
    pub expected_revision: Option<u64>,
    pub key: IdempotencyKey,
}
#[cfg(feature = "remote")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePermissionChange {
    pub address: RemoteAgentAddress,
    pub allowed: bool,
    pub expected_revision: Option<u64>,
    pub key: IdempotencyKey,
}
impl OwnerInput {
    #[cfg(feature = "remote")]
    pub(crate) fn initializes_resources(&self) -> bool {
        matches!(
            self,
            Self::Bootstrap { .. } | Self::Add { .. } | Self::PrepareAdd { .. }
        )
    }

    pub fn requires_terminal(&self) -> bool {
        #[cfg(feature = "remote")]
        if matches!(
            self,
            Self::PairingLaunchPermissions { .. }
                | Self::PairingPermissions { .. }
                | Self::LocalPairingPermissions { .. }
        ) {
            return true;
        }
        matches!(
            self,
            Self::Disable | Self::Grants { .. } | Self::Revoke { .. }
        )
    }
    pub fn key(&self) -> Option<&IdempotencyKey> {
        match self {
            #[cfg(feature = "remote")]
            Self::PairingLaunchPermissions {
                change: Some(change),
                ..
            } => Some(&change.key),
            #[cfg(feature = "remote")]
            Self::LaunchPermissions(request) => request.change.as_ref().map(|change| &change.key),
            #[cfg(feature = "remote")]
            Self::PairingPermissions {
                change: Some(change),
                ..
            }
            | Self::LocalPairingPermissions {
                change: Some(change),
                ..
            } => Some(&change.key),
            #[cfg(feature = "remote")]
            Self::SourcePermissions(request) => request.change.as_ref().map(|change| &change.key),
            Self::Revoke { key, .. } => Some(key),
            _ => None,
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            #[cfg(feature = "remote")]
            Self::PairingLaunchPermissions { alias, change, .. } => {
                se_core::ops::remote::validate_alias(alias)?;
                validate_launch_change(change.as_ref())
            }
            #[cfg(feature = "remote")]
            Self::LaunchPermissions(request) => validate_launch_change(request.change.as_ref()),
            #[cfg(feature = "remote")]
            Self::PairingPermissions { alias, change, .. } => {
                se_core::ops::remote::validate_alias(alias)?;
                validate_source_change(change.as_ref())
            }
            #[cfg(feature = "remote")]
            Self::SourcePermissions(request) => validate_source_change(request.change.as_ref()),
            #[cfg(feature = "remote")]
            Self::LocalPairingPermissions { change, .. } => validate_source_change(change.as_ref()),
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
            Self::PrepareAdd { destination, alias } => {
                se_core::ops::remote::validate_alias(alias)?;
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

#[cfg(feature = "remote")]
fn validate_launch_change(change: Option<&LaunchPermissionChange>) -> Result<()> {
    if change.is_some_and(|c| {
        c.expected_revision
            .is_some_and(|r| r == 0 || r > i64::MAX as u64)
    }) {
        return Err(SeError::invalid(
            "launch permission revision",
            "its current nonzero revision, or absent for no consent",
        ));
    }
    Ok(())
}

#[cfg(feature = "remote")]
fn validate_source_change(change: Option<&SourcePermissionChange>) -> Result<()> {
    if change.is_some_and(|change| {
        change
            .expected_revision
            .is_some_and(|r| r == 0 || r > i64::MAX as u64)
    }) {
        return Err(SeError::invalid(
            "source permission revision",
            "its current nonzero revision, or absent for no override",
        ));
    }
    Ok(())
}
