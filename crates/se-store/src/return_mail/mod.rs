//! Durable contact routes, return-mail validation and finite courier queues.
mod sender;
pub(crate) use sender::sender;
mod contact_receipt;
mod mail_routes;
mod mailbox;
mod mailbox_model;
mod push;
mod reply;
mod reply_read;
mod return_validate;

pub use contact_receipt::ContactReceiptQuery;
pub(crate) use mailbox::apply_mailbox;
pub use mailbox_model::*;
pub use push::OutgoingReply;
pub(crate) use reply::{enqueue_reply, reply_route, validate_incoming_reply};
pub use reply_read::{ReplyPage, ReplyQuery};
pub(crate) use return_validate::validate_returns;

use crate::{
    error::*,
    remote::{
        GrantState, MessageAttribution, admit_address, admit_source, decode, denied, encode,
        grant_at, key, ready,
    },
    *,
};
use rusqlite::{Connection, OptionalExtension};
