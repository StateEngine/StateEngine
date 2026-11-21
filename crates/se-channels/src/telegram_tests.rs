use super::*;
use serde_json::json;
type Check = Result<(), Box<dyn std::error::Error>>;
fn user() -> Value {
    json!({"id":42,"is_bot":false,"first_name":"Fixture"})
}
fn chat() -> Value {
    json!({"id":42,"type":"private"})
}
/// Protects: 49 — use the authenticated private sender, never a forwarded author's identity.
#[test]
fn forwarded_text_preserves_actual_private_subject_and_body() -> Check {
    let content = normalize(
        &json!({"message":{"from":user(),"chat":chat(),"text":"literal owner task","forward_origin":{"type":"user","sender_user":{"id":999}}}}),
    )?;
    assert!(
        matches!(content,IncomingContent::Text{phone,text} if phone.subject == 42.into() && phone.private_chat == 42.into() && text=="literal owner task")
    );
    Ok(())
}
/// Protects: 49 — refuse groups, mismatched destinations and bot senders before mail admission.
#[test]
fn nonprivate_or_mismatched_subjects_never_normalize_as_owner_text() -> Check {
    for message in [
        json!({"from":user(),"chat":{"id":-42,"type":"group"},"text":"group task"}),
        json!({"from":user(),"chat":{"id":43,"type":"private"},"text":"other chat"}),
        json!({"from":{"id":42,"is_bot":true,"first_name":"Bot"},"chat":chat(),"text":"bot task"}),
    ] {
        assert!(matches!(
            normalize(&json!({"message":message}))?,
            IncomingContent::Unsupported
        ));
    }
    Ok(())
}
/// Protects: 49 — retain private identity for explicit attachment refusal without treating captions as saved work.
#[test]
fn attachment_caption_is_not_silently_saved_as_the_attachment_contents() -> Check {
    let content = normalize(
        &json!({"message":{"from":user(),"chat":chat(),"photo":[{"file_id":"fixture"}],"caption":"this is not the file"}}),
    )?;
    assert!(
        matches!(content,IncomingContent::UnsupportedPrivate{phone} if phone.subject == 42.into())
    );
    Ok(())
}
/// Protects: 49 — bind callback identity to its actual private caller rather than the bot's message author.
#[test]
fn private_callback_uses_caller_and_checks_destination() -> Check {
    let mut callback = json!({"from":user(),"message":{"from":{"is_bot":true},"chat":chat()},"id":"fixture-callback","data":"r:cha-11111111111111111111111111111111"});
    assert!(
        matches!(normalize(&json!({"callback_query":callback.clone()}))?,IncomingContent::Callback{phone,..} if phone.subject == 42.into())
    );
    callback["message"]["chat"]["id"] = json!(43);
    assert!(matches!(
        normalize(&json!({"callback_query":callback}))?,
        IncomingContent::Unsupported
    ));
    Ok(())
}
