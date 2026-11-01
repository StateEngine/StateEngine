use se_types::{ConfigPreviousSource, ConfigPreviousValue};
use serde_json::{Value, json};
type Check = Result<(), Box<dyn std::error::Error>>;

/// Protects: first-grant effective false remains distinguishable from stored false and stored JSON null at the public receipt boundary, without wrapping or coercing the prior value.
#[test]
fn prior_value_and_source_round_trip_without_loss() -> Check {
    for (value, source, name) in [
        (Value::Bool(false), ConfigPreviousSource::Default, "default"),
        (Value::Bool(false), ConfigPreviousSource::Stored, "stored"),
        (Value::Null, ConfigPreviousSource::Stored, "stored"),
        (
            Value::String("chosen-model".into()),
            ConfigPreviousSource::Stored,
            "stored",
        ),
    ] {
        let prior = ConfigPreviousValue {
            value: value.clone(),
            source,
        };
        let wire = serde_json::to_value(&prior)?;
        assert_eq!(wire, json!({"value":value,"source":name}));
        assert_eq!(serde_json::from_value::<ConfigPreviousValue>(wire)?, prior);
    }
    Ok(())
}

/// Protects: a receipt reader refuses missing, unknown or conflicting provenance instead of silently interpreting a legacy absence or guessed origin as the effective default.
#[test]
fn invalid_or_ambiguous_prior_provenance_refuses() {
    for wire in [
        json!({"value":false}),
        json!({"source":"stored"}),
        json!({"value":false,"source":"unknown"}),
        json!({"state":"absent","checked":"grant"}),
        json!({"value":false,"source":"default","origin":"stored"}),
    ] {
        assert!(
            serde_json::from_value::<ConfigPreviousValue>(wire.clone()).is_err(),
            "ambiguous provenance accepted: {wire}"
        );
    }
}
