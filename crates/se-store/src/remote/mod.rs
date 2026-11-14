//! Closed remote-security transitions over the existing authoritative writer.
mod apply;
mod changes;
mod launch;
mod launch_continue;
mod launch_permission;
mod model;
pub(crate) use launch::{
    apply as apply_launch, target_owned as launch_target_owned, validate_launch,
};
mod position;
mod receipt;
pub use position::{position_from_payload, position_payload};
pub use receipt::RemoteMessageReceipt;
mod read;
mod source;
pub use crate::return_mail::{
    ContactReceiptQuery, MailContact, MailRoute, MailboxChange, OutgoingReply, PendingContact,
    ReplyPage, ReplyQuery, ReturnAttribution,
};
pub(crate) use crate::return_mail::{apply_mailbox, enqueue_reply, reply_route};
pub use changes::{Change, ChangeKind, ChangePage, ChangeRequest};
pub(crate) use read::grant as grant_at;
pub(crate) use source::{admit_address, admit_source, remember_source};
pub(crate) use source::{pending as source_pending, permission as source_permission};
mod validate;
pub use crate::inventory::{LaunchCandidate, SavedLaunchProfile, TargetFacts};
pub(crate) use apply::{apply, revision};
pub use model::*;
pub(crate) use validate::LaunchAuthority;
pub(crate) use validate::{validate_batch, validate_new_batch};

use crate::{error::*, *};
use rusqlite::{Connection, OptionalExtension};
use serde::de::DeserializeOwned;

pub(crate) fn key(value: &str) -> StoreResult<Vec<u8>> {
    crate::identity::canonical(value)
        .ok_or_else(|| invalid("remote identities require canonical UUIDv7"))
}
pub(crate) fn decode<T: DeserializeOwned>(value: String) -> StoreResult<T> {
    serde_json::from_str(&value).map_err(invalid)
}
pub(crate) fn encode<T: serde::Serialize>(value: &T) -> StoreResult<String> {
    crate::codec::encode(value)
}
pub(crate) fn ready(info: &StoreInfo) -> StoreResult<()> {
    if info.state != StoreState::Ready || info.schema_version < 7 {
        return Err(fail(
            StoreErrorCode::NotReady,
            "remote security requires a ready schema-7 store",
        ));
    }
    Ok(())
}
pub(crate) fn denied() -> Box<StoreError> {
    fail(
        StoreErrorCode::ScopeMismatch,
        "remote authority is absent, expired, revoked or outside the requested scope",
    )
}
