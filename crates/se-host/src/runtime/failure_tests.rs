use super::failure::{PendingWrites, WriteIdentity};
use se_types::{Code, EventId, IdempotencyKey, RenderCx, Retry};
type Check = Result<(), Box<dyn std::error::Error>>;

#[test]
fn busy_write_returns_the_refused_requests_replay_identity() -> Check {
    for keyed in [true, false] {
        let registry = PendingWrites::new(1);
        let first = WriteIdentity {
            operation: "message.send",
            natural_key: None,
            key: Some(IdempotencyKey::new("occupying-request")?),
            natural_events: Vec::new(),
        };
        registry.register(&first)?;
        let original = WriteIdentity {
            operation: if keyed {
                "message.send"
            } else {
                "message.read"
            },
            natural_key: (!keyed).then(|| "original-natural-marker".into()),
            key: keyed
                .then(|| IdempotencyKey::new("refused-original-key"))
                .transpose()?,
            natural_events: if keyed {
                Vec::new()
            } else {
                vec![EventId::from_parts(1, [7; 10])?]
            },
        };
        let refused = registry
            .register(&original)
            .err()
            .ok_or("occupied admission accepted a new request")?;
        assert_eq!(refused.code(), Code::StoreBusy);
        assert_eq!(refused.body.retry(), &Retry::AfterReread);
        let wire = serde_json::to_value(&refused.body)?;
        assert_eq!(wire["retry"]["kind"], "after_reread");
        assert_eq!(wire["detail"]["operation"], original.operation);
        assert_eq!(
            wire["detail"]["key"],
            serde_json::to_value(original.key.as_ref().map(ToString::to_string))?
        );
        assert_eq!(
            wire["detail"]["natural_events"],
            serde_json::to_value(&original.natural_events)?
        );
        let remedy = refused.body.remedy(&RenderCx::default())?;
        assert!(
            remedy.text.contains("refused-original-key")
                || (!keyed
                    && remedy
                        .text
                        .contains(&original.natural_events[0].to_string()))
        );
        // The refused identity neither replaced the unresolved request nor
        // occupied a slot; the exact same identity is admissible after settlement.
        assert_eq!(registry.describe()?.len(), 1);
        registry.resolve(&first)?;
        registry.register(&original)?;
        assert_eq!(registry.describe()?.len(), 1);
        registry.resolve(&original)?;
        assert!(registry.describe()?.is_empty());
    }
    Ok(())
}
