//! Explicit public projections: never serialize native custody, credential
//! verifiers, private runtime nonces or the raw storage event envelope.
use super::*;
use se_store::StoredText;
use se_types::{Detail, SeError, details};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn text(value: &StoredText) -> Result<Value> {
    let StoredText::Present(value) = value else {
        return Err(scope::unreadable(
            "event payload",
            "content was erased; no complete public body is available",
        ));
    };
    let hash: String = Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(json!({"text":value,"bytes":value.len(),"sha256":hash,"complete":true}))
}
pub(super) fn public<R: Snapshot>(
    event: &StoredEvent,
    read: &mut R,
) -> Result<(&'static str, Value)> {
    use EventBody::*;
    Ok(match &event.body {
        MessageSent { message, recipient, kind, body, refs, reply_to } => ("message.sent", json!({"message_id":message,"to":receipt::actor_ref(read,recipient)?,"kind":kind,"body":text(body)?,"refs":refs,"reply_to":reply_to})),
        WorkingStateSet { agent, text: body, .. } => ("working_state.set", json!({"agent":receipt::named_agent(read,agent)?,"body":text(body)?,"revision":event.revision.value})),
        PrincipalRegistered { principal, name, role, .. } => ("principal.registered", json!({"principal":receipt::actor_ref(read,principal)?,"name":name,"role":role})),
        PrincipalRenamed { principal, name, .. } => ("principal.renamed", json!({"principal":receipt::actor_ref(read,principal)?,"name":name})),
        ProfileSaved { agent, profile, .. } => ("profile.saved", json!({"agent":receipt::named_agent(read,agent)?,"profile":profile})),
        GrantRecorded { principal, key, active, .. } => ("grant.recorded", json!({"principal":receipt::actor_ref(read,principal)?,"key":key,"active":active})),
        DecisionProposed { decision, key, statement, rationale, prior, .. } => ("decision.proposed", json!({"decision_id":decision,"key":key,"statement":text(statement)?,"rationale":rationale.as_ref().map(text).transpose()?,"prior":prior})),
        DecisionRatified { decision, approval, .. } => ("decision.ratified", json!({"decision_id":decision,"approval":approval})),
        DecisionRejected { decision, reason, .. } => ("decision.rejected", json!({"decision_id":decision,"reason":text(reason)?})),
        DecisionRetracted { decision, reason, .. } => ("decision.retracted", json!({"decision_id":decision,"reason":text(reason)?})),
        DecisionSuperseded { prior, replacement, approval, .. } => ("decision.superseded", json!({"prior":prior,"replacement":replacement,"approval":approval})),
        CaptureSuppressed { session, count, reason, .. } => ("capture.suppressed", json!({"session_id":session,"count":count,"reason":reason})),
        // Later-wave event families require their own complete public projection;
        // they cannot expose raw native/credential fields as a shortcut.
        _ => return Err(SeError::new(Detail::FeatureUnavailable(details::FeatureUnavailable {
            subject:"event payload family".into(),
            reason:"This stored event family has no public payload projection in this build.".into(),
            next_step:"Use the supported operation-specific read without exporting private storage fields.".into(),
        }))),
    })
}
