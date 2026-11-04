//! Exact source correspondence for both native and retained imported mail.
use super::*;
pub(super) enum MessageReference {
    Native(Box<MessageRecord>),
    Retained(EventId),
}
impl MessageReference {
    pub(super) fn event(&self) -> EventId {
        match self {
            Self::Native(value) => value.event.clone(),
            Self::Retained(event) => event.clone(),
        }
    }
}
pub(super) fn lookup<R: ImportSnapshot>(
    cx: &NodeContext,
    read: &mut R,
    id: &MessageId,
) -> StoreResult<MessageReference> {
    match read.message(id.clone())? {
        Read::Present { value } => Ok(MessageReference::Native(Box::new(value))),
        Read::Absent { .. } => {
            let key = format!("owned:messages:message:{id}");
            let owned = event_id(&cx.admission.scope, &key)?;
            let value = require(read.event(owned.clone())?)?;
            if value.header.door != Door::Import
                || !matches!(&value.body,
                EventBody::LegacyRetained { family: ImportFamily::Messages,
                    legacy_id, mapped_id: LegacyTarget::Message(message), .. }
                    if legacy_id==&key && message==id)
            {
                return Err(invalid(
                    "retained source message correspondence has the wrong kind",
                ));
            }
            Ok(MessageReference::Retained(owned))
        }
        Read::Unreadable { reason, .. } => Err(fail(StoreErrorCode::Unreadable, reason)),
        Read::Unknown { what } => Err(fail(StoreErrorCode::Unreadable, what)),
    }
}
