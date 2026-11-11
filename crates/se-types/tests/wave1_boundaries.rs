use se_types::{
    AgentId, AtlasRootId, BootId, Cursor, DecisionId, EventId, Generation, HostGeneration, HumanId,
    IndexEpochId, LaunchId, LifecycleId, MessageId, ObservationId, Omission, OmissionReason, Page,
    ProjectId, Sequence, SessionId, Sha256, Source, StopReason, StoreId, Window, WindowFields,
};
use serde_json::{Value, json};
use std::{error::Error, num::NonZeroU32};
type Check = Result<(), Box<dyn Error>>;

/// Protects: C1 — canonical storage bytes round-trip without minting legacy keys.
#[test]
#[expect(
    clippy::cognitive_complexity,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn typed_ids_keep_canonical_bytes_and_legacy_spelling_distinct() -> Check {
    macro_rules! canonical {
        ($($kind:ty),+ $(,)?) => {$(
            let id = <$kind>::from_parts(0x0192_f3b5_0000, [0xab; 10])?;
            let bytes = id.canonical_bytes()?.ok_or("missing canonical bytes")?;
            assert_eq!(bytes[6] >> 4, 7);
            assert_eq!(bytes[8] >> 6, 2);
            assert_eq!(<$kind>::from_bytes(bytes)?, id);
            let decoded: $kind = serde_json::from_str(&serde_json::to_string(&id)?)?;
            assert_eq!(decoded.canonical_bytes()?, Some(bytes));
            let mut wrong_version = bytes;
            wrong_version[6] = (wrong_version[6] & 15) | 0x40;
            assert!(<$kind>::from_bytes(wrong_version).is_err());
            let mut wrong_variant = bytes;
            wrong_variant[8] &= 0x3f;
            assert!(<$kind>::from_bytes(wrong_variant).is_err());
            assert!(<$kind>::from_parts(1 << 48, [0; 10]).is_err());
        )+};
    }
    canonical!(
        ProjectId,
        AgentId,
        HumanId,
        SessionId,
        MessageId,
        DecisionId,
        EventId,
        LaunchId,
        ObservationId,
        StoreId,
        LifecycleId,
        AtlasRootId,
        IndexEpochId
    );
    let legacy = AgentId::from_legacy("agt-0000-0000-0000")?;
    assert_eq!(legacy.canonical_bytes()?, None);
    assert_eq!(serde_json::to_value(&legacy)?, "agt-0000-0000-0000");
    assert_eq!(
        MessageId::from_legacy("msg-deadbeef")?.canonical_bytes()?,
        None
    );
    assert_eq!(
        ProjectId::from_legacy("ordinary-project")?.canonical_bytes()?,
        None
    );
    assert!(
        serde_json::from_value::<AgentId>(json!("hu_0192f3b5-0000-7000-8000-000000000001"))
            .is_err()
    );
    assert!(serde_json::from_value::<ProjectId>(json!("agt-0000-0000-0000")).is_err());
    Ok(())
}

/// Protects: C1 — persisted generations and opaque/hash schemas match input limits.
#[test]
#[expect(
    clippy::cognitive_complexity,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn persisted_value_limits_agree_with_their_wire_schemas() -> Check {
    for value in [
        json!(0),
        json!(-1),
        json!(i64::MAX as u64 + 1),
        json!(u64::MAX),
    ] {
        assert!(serde_json::from_value::<Generation>(value.clone()).is_err());
        assert!(serde_json::from_value::<HostGeneration>(value).is_err());
    }
    for value in [1, i64::MAX as u64] {
        assert_eq!(Generation::new(value)?.get(), value);
        assert_eq!(HostGeneration::new(value)?.get(), value);
    }
    assert_eq!(Generation::new(1)?.successor()?.get(), 2);
    assert!(Generation::new(i64::MAX as u64)?.successor().is_err());
    assert!(HostGeneration::new(i64::MAX as u64)?.successor().is_err());
    for schema in [
        serde_json::to_value(schemars::schema_for!(Generation))?,
        serde_json::to_value(schemars::schema_for!(HostGeneration))?,
    ] {
        assert_eq!(schema["minimum"], 1);
        assert_eq!(schema["maximum"], i64::MAX);
    }
    for value in ["", "has space", "line\n", "\u{7f}", "é"] {
        assert!(Cursor::new(value).is_err());
        assert!(serde_json::from_value::<Cursor>(json!(value)).is_err());
    }
    let full = "!".repeat(4096);
    assert_eq!(Cursor::new(full.clone())?.as_str(), full);
    assert!(Cursor::new(format!("{full}!")).is_err());
    let schema = serde_json::to_value(schemars::schema_for!(Cursor))?;
    assert_eq!(schema["minLength"], 1);
    assert_eq!(schema["maxLength"], 4096);
    assert_eq!(schema["pattern"], "^[!-~]+$");
    let schema = serde_json::to_value(schemars::schema_for!(BootId))?;
    assert_eq!(schema["maxLength"], 256);
    let hash = Sha256::parse_hex(&"ab".repeat(32))?;
    assert_eq!(serde_json::to_value(hash)?, "ab".repeat(32));
    assert!(Sha256::parse_hex(&"AB".repeat(32)).is_err());
    assert!(Sha256::parse_hex(&"a".repeat(63)).is_err());
    let schema = serde_json::to_value(schemars::schema_for!(Sha256))?;
    assert_eq!(schema["minLength"], 64);
    assert_eq!(schema["maxLength"], 64);
    assert_eq!(schema["pattern"], "^[0-9a-f]{64}$");
    Ok(())
}

/// Bug: 893e06c — producer pages omitted continuation for unknown-count limits.
#[test]
fn unknown_count_limit_pages_cannot_lose_their_continuation() -> Check {
    for reason in [OmissionReason::Limit, OmissionReason::Budget] {
        let window = Window::new(WindowFields {
            source: Source::Configuration {
                location: "review fixture".into(),
            },
            from: Sequence::ZERO,
            to: Sequence::new(2)?,
            start_cursor: Some(Cursor::new("c.start")?),
            end_cursor: Some(Cursor::new("c.end")?),
            returned: 1,
            limit: NonZeroU32::MIN,
            bytes: 1,
            max_bytes: NonZeroU32::new(32).ok_or("byte limit")?,
            omitted_before: Omission::None,
            omitted_after: Omission::Unknown { reason },
            unreadable: 0,
            stop_reason: if reason == OmissionReason::Limit {
                StopReason::ItemLimit
            } else {
                StopReason::ByteLimit
            },
        })?;
        assert!(Page::new(vec!["row"], window.clone(), None).is_err());
        assert!(Page::new(vec!["row"], window.clone(), Some(Cursor::new("c.start")?)).is_err());
        let page = Page::new(vec!["row"], window, Some(Cursor::new("c.end")?))?;
        let wire = serde_json::to_value(page)?;
        assert_eq!(wire["window"]["complete"], false);
        assert_eq!(wire["window"]["omitted"]["count"], Value::Null);
        let decoded: Page<String> = serde_json::from_value(wire.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, wire);
        let mut missing = wire;
        missing["next"] = Value::Null;
        // Wire counts have no before/after direction. Retain incompleteness;
        // the production builder above enforces next for known remaining rows.
        let partial: Page<String> = serde_json::from_value(missing)?;
        assert!(!partial.window().complete());
        assert_eq!(partial.window().exit_code(true), 2);
    }
    // Error payloads expose a cursor, never the store's numeric retained position.
    let detail: se_types::Detail = serde_json::from_value(json!({
        "code":"cursor-expired", "detail":{"oldest_available":"c.oldest"}
    }))?;
    assert_eq!(
        serde_json::to_value(detail)?["detail"]["oldest_available"],
        "c.oldest"
    );
    assert!(
        serde_json::from_value::<se_types::Detail>(json!({
            "code":"cursor-expired", "detail":{"oldest_available":4182}
        }))
        .is_err()
    );
    Ok(())
}

/// Bug: 31c0ef5 — a legal page with omissions before its range could not decode.
#[test]
fn pages_with_only_prior_omissions_roundtrip_without_a_next_cursor() -> Check {
    for reason in [OmissionReason::Limit, OmissionReason::Budget] {
        let window = Window::new(WindowFields {
            source: Source::Configuration {
                location: "review fixture".into(),
            },
            from: Sequence::new(3)?,
            to: Sequence::new(4)?,
            start_cursor: Some(Cursor::new("c.start")?),
            end_cursor: Some(Cursor::new("c.end")?),
            returned: 1,
            limit: NonZeroU32::MIN,
            bytes: 1,
            max_bytes: NonZeroU32::new(32).ok_or("byte limit")?,
            omitted_before: Omission::Known {
                count: 3.try_into()?,
                reason,
            },
            omitted_after: Omission::None,
            unreadable: 0,
            stop_reason: StopReason::Exhausted,
        })?;
        let page = Page::new(vec!["row"], window, None)?;
        let wire = serde_json::to_value(page)?;
        let round: Page<String> = serde_json::from_value(wire.clone())?;
        assert_eq!(serde_json::to_value(&round)?, wire);
        assert!(round.next().is_none());
        assert!(!round.window().complete());
        assert_eq!(round.window().exit_code(true), 2);
        assert_eq!(round.window().omitted().count, Some(3));
    }
    Ok(())
}
