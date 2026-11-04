//! One semantic descriptor derived from the closed event metadata codec.
//! Owning text is added only for comparison, never copied into aux_data.
use super::*;
pub(crate) fn descriptor<T>(
    body: &EventBody<T>,
    text: impl Fn(&T) -> StoreResult<String>,
) -> StoreResult<String> {
    let (kind, mut fields) = metadata(body)?;
    let fields = fields
        .as_object_mut()
        .ok_or_else(|| invalid("closed event metadata must be an object"))?;
    use EventBody::*;
    match body {
        MessageSent { body, .. } | WorkMessageSent { body, .. } => {
            fields.insert("body".into(), json!(text(body)?));
        }
        WorkingStateSet { text: value, .. } => {
            fields.insert("text".into(), json!(text(value)?));
        }
        DecisionProposed {
            statement,
            rationale,
            ..
        } => {
            fields.insert("statement".into(), json!(text(statement)?));
            fields.insert(
                "rationale".into(),
                json!(rationale.as_ref().map(&text).transpose()?),
            );
        }
        DecisionRejected { reason, .. }
        | DecisionRetracted { reason, .. }
        | SessionEnded { reason, .. }
        | SessionRevoked { reason, .. }
        | CredentialRevoked { reason, .. } => {
            fields.insert("reason".into(), json!(text(reason)?));
        }
        SessionTurn { text: value, .. } => {
            fields.remove("turn");
            fields.insert("text".into(), json!(text(value)?));
        }
        CaptureSource { .. } | CaptureProgress { .. } => {
            fields.remove("expected");
        }
        _ => {}
    }
    encode(&(kind, fields))
}
