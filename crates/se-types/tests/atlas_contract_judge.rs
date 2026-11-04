//! Shared ingress checks apply to CLI, MCP and either harness without host code.
use se_types::{AgentId, EventId, ProjectId, code::*};
use std::error::Error;
type Check = Result<(), Box<dyn Error>>;
fn record() -> Result<FeedRecord, Box<dyn Error>> {
    Ok(FeedRecord {
        pointer: RecordPointer {
            key: RecordKey::new("decision/key")?,
            kind: RecordKind::Decision,
            source_event: EventId::from_parts(1, [1; 10])?,
        },
        project: ProjectId::from_parts(1, [2; 10])?,
        actor: None,
        occurred_unix_ms: 0,
        title: "decision".into(),
        visibility: RecordVisibility::Restricted { audience: None },
        body: "why".into(),
        body_truncated: false,
        mentions: vec![],
    })
}
#[test]
fn record_feed_preserves_unresolved_visibility_and_rejects_cross_project() -> Check {
    let r = record()?;
    r.validate()?;
    assert!(matches!(
        r.visibility,
        RecordVisibility::Restricted { audience: None }
    ));
    let mut feed = RecordFeed {
        project: r.project.clone(),
        after: None,
        through: r.pointer.source_event.clone(),
        changes: vec![RecordFeedChange::Upsert(r)],
        complete: true,
    };
    feed.validate()?;
    feed.changes.push(RecordFeedChange::Remove {
        project: ProjectId::from_parts(2, [3; 10])?,
        key: RecordKey::new("other")?,
    });
    assert!(feed.validate().is_err());
    Ok(())
}
#[test]
fn feed_bounds_apply_to_real_utf8_bytes_and_sorted_distinct_audience() -> Check {
    let mut r = record()?;
    r.title = "é".repeat(81);
    assert!(r.validate().is_err());
    r.title.clear();
    r.body = "x".repeat(65537);
    assert!(r.validate().is_err());
    r.body.clear();
    let key = AtlasPrincipal::Agent(AgentId::from_parts(1, [4; 10])?);
    r.visibility = RecordVisibility::Restricted {
        audience: Some(vec![key.clone(), key]),
    };
    assert!(r.validate().is_err());
    r.visibility = RecordVisibility::Restricted { audience: None };
    r.body = "x".repeat(32769);
    let other = record()?;
    let feed = RecordFeed {
        project: r.project.clone(),
        after: None,
        through: r.pointer.source_event.clone(),
        changes: vec![
            RecordFeedChange::Upsert(r),
            RecordFeedChange::Upsert(FeedRecord {
                body: "x".repeat(32768),
                ..other
            }),
        ],
        complete: false,
    };
    assert!(feed.validate().is_err());
    Ok(())
}
#[test]
fn portable_path_constructor_and_wire_refuse_aliases() -> Check {
    for bad in [
        "/a",
        "../a",
        "a/../b",
        "a:stream",
        "a/NUL.txt",
        "a/COM¹.rs",
        "a/conin$",
        "a/trailing.",
        "a/trailing ",
        "a\\b",
    ] {
        assert!(RelativePath::new(bad).is_err(), "accepted {bad:?}");
        assert!(serde_json::from_value::<RelativePath>(serde_json::json!(bad)).is_err());
    }
    for good in ["src/main.rs", "src/CONTEXT.rs", "café/代码.rs"] {
        RelativePath::new(good)?;
    }
    Ok(())
}
#[test]
fn hit_body_wire_preserves_unknown_agreement_and_checks_size() -> Check {
    let origin = BodyOrigin::AuthoritativeRecord(record()?.pointer);
    let body = HitBody::new(origin, "one\ntwo".into(), false)?;
    let mut wire = serde_json::to_value(body)?;
    assert_eq!(wire["complete"], false);
    wire["text"] = serde_json::json!("x\n".repeat(41));
    assert!(serde_json::from_value::<HitBody>(wire.clone()).is_err());
    wire["text"] = serde_json::json!("x".repeat(12289));
    assert!(serde_json::from_value::<HitBody>(wire).is_err());
    Ok(())
}
