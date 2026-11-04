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
    let hash: String = se_types::hex_lower(&Sha256::digest(value.as_bytes()));
    Ok(json!({"text":value,"bytes":value.len(),"sha256":hash,"complete":true}))
}
pub(super) fn public<R: Snapshot>(
    event: &StoredEvent,
    read: &mut R,
) -> Result<(&'static str, Value)> {
    use EventBody::*;
    Ok(match &event.body {
        MessageSent { message, recipient, kind, body, refs, reply_to } => ("message.sent", json!({"message_id":message,"to":receipt::actor_ref(read,recipient)?,"kind":kind,"body":text(body)?,"refs":refs,"reply_to":reply_to})),
        MessageRead{message,recipient}=>("message.read",json!({"message_id":message,"recipient":receipt::actor_ref(read,recipient)?})),
        MessageDismissed{message,recipient}=>("message.dismissed",json!({"message_id":message,"recipient":receipt::actor_ref(read,recipient)?})),
        MessageDelivered{message,recipient,evidence}=>("message.delivered",json!({"message_id":message,"recipient":receipt::actor_ref(read,recipient)?,"evidence":evidence})),
        MessageSuperseded{message,replacement,..}=>("message.superseded",json!({"message_id":message,"replacement":replacement})),
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
        SessionTurn { session, role: se_store::Role::System, vendor_ref, text: StoredText::Present(body), evidence, .. }
            if vendor_ref.starts_with(se_store::TRANSCRIPT_EVENT_PREFIX) => {
                let record = crate::ops::transcript::Record::decode(body)?;
                record.validate_evidence(evidence)?;
                ("transcript.event", json!({"session_id":session,"metadata":record}))
            }
        SessionTurn { session, provider, vendor_ref, role, text: body, evidence, .. } => {
            let source = match (event.header.door, provider, evidence.path.as_ref()) {
                (se_store::Door::Hook, _, _) => "hook",
                (se_store::Door::Import, _, _) => "node-import",
                (se_store::Door::Host, se_store::Provider::SeCode, None) => "app-server",
                _ => return Err(scope::unreadable("turn provenance", "this adapter cannot infer a capture source from an unlabelled legacy door")),
            };
            let record = scope::require_present(read.session(session.clone()).map_err(|e| store_error(&e))?, "turn's original session metadata", "Restore access to the turn's original session metadata, then reread the same event ID; preserve the recorded session identity.")?;
            let native = record.original.as_deref().unwrap_or(&record.current);
            let SessionPrepared { session: original, provider: original_provider, .. } = &native.body else {
                return Err(scope::unreadable("turn session provenance", "original prepared session metadata is unavailable"));
            };
            if original != session || original_provider != provider {
                return Err(scope::unreadable("turn session provenance", "session or provider differs from the committed turn"));
            }
            let reference = scope::require_present(crate::ops::session_reference::read(read, &record)?, "turn provider reference", "Restore the original actual provider binding.")?;
            let native_ref = reference.as_str();
            let provider = match provider { se_store::Provider::Claude => "claude", se_store::Provider::Codex => "codex", se_store::Provider::SeCode => "secode" };
            let role = match role {
                se_store::Role::User => "user", se_store::Role::Assistant => "assistant",
                _ => return Err(scope::unreadable("turn role", "the public capture family requires an actual user or assistant turn")),
            };
            ("session.turn", json!({"session_id":session,"turn_id":if vendor_ref.is_empty() {None} else {Some(vendor_ref)},"provider":provider,"provider_session":if native_ref.is_empty() {None} else {Some(native_ref)},"role":role,"source":source,"occurred_at":receipt::timestamp(event.header.occurred_at_us)?,"body":text(body)?}))
        }
        CaptureSuppressed { session, count, reason, .. } => ("capture.suppressed", json!({"session_id":session,"count":count,"reason":reason})),
        LegacyRetained{family,legacy_id,bytes,retained_from,..} => {
            let body=bytes.as_ref().map(|content|String::from_utf8(content.bytes.clone()).map_err(|e|scope::unreadable("retained user history",&e.to_string()))).transpose()?;
            ("legacy.retained",json!({"family":family,"legacy_id":legacy_id,"retained_from":retained_from,"body":body.as_ref().map(|body|text(&StoredText::Present(body.clone()))).transpose()?}))
        }
        AliasImported{alias,principal,source,..}=>("alias.imported",json!({"alias":alias,"principal":receipt::actor_ref(read,principal)?,"source":source})),
        ImportStarted{format,policy_version,..}=>("import.started",json!({"format":format,"policy_version":policy_version})),
        ImportProgress{checkpoint,counts}=>("import.progress",json!({"family":checkpoint.family,"source_rows":checkpoint.row_offset,"counts":counts})),
        ImportFinished{counts,complete,..}=>("import.finished",json!({"complete":complete,"counts":counts})),
        ImportUnreadable{family,code,evidence,..}=>("import.unreadable",json!({"family":family,"reason":code,"source_range":evidence})),
        // Later-wave event families require their own complete public projection;
        // they cannot expose raw native/credential fields as a shortcut.
        _ => return Err(SeError::new(Detail::FeatureUnavailable(details::FeatureUnavailable {
            subject:"event payload family".into(),
            reason:"This stored event family has no public payload projection in this build.".into(),
            next_step:"Use the supported operation-specific read without exporting private storage fields.".into(),
        }))),
    })
}
