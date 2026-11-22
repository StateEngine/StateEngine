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
fn since_text_reads_durations_times_commits_and_unix_millis() -> Check {
    for (text, ago) in [
        ("30s", 30_000),
        ("10m", 600_000),
        ("2h", 7_200_000),
        ("7d", 604_800_000),
    ] {
        let baseline = ChangeBaseline::from_text(text)?;
        assert!(
            matches!(baseline, ChangeBaseline::RelativeMillis(ms) if ms == ago),
            "{text}: {baseline:?}"
        );
        // A cursor digests the query; a relative baseline must not move with the clock.
        let again = serde_json::to_vec(&ChangeBaseline::from_text(text)?)?;
        assert_eq!(serde_json::to_vec(&baseline)?, again, "{text}");
    }
    let iso = ChangeBaseline::from_text("2026-11-20T09:30Z")?;
    assert!(matches!(
        iso,
        ChangeBaseline::ObservedUnixMillis(1_795_167_000_000)
    ));
    for prefix in ["1234567", "abcdef1", "123456789012"] {
        let baseline = ChangeBaseline::from_text(prefix)?;
        assert!(
            matches!(&baseline, ChangeBaseline::ObservedCommitPrefix(p) if p == prefix),
            "{prefix}: {baseline:?}"
        );
    }
    let millis = ChangeBaseline::from_text("1700000000000")?;
    assert!(matches!(
        millis,
        ChangeBaseline::ObservedUnixMillis(1_700_000_000_000)
    ));
    let sha = "0123456789abcdef0123456789abcdef01234567";
    assert!(matches!(
        ChangeBaseline::from_text(sha)?,
        ChangeBaseline::ObservedCommit(GitObjectId::Sha1(_))
    ));
    for bad in ["nope", "10x", "m", ""] {
        let error = ChangeBaseline::from_text(bad)
            .err()
            .ok_or_else(|| format!("accepted {bad:?}"))?;
        assert_eq!(error.body.class().exit_code(), 64, "{bad:?}: {error}");
    }
    Ok(())
}
#[test]
fn since_wire_accepts_typed_text_and_resolves_relative_against_now() -> Check {
    let text: ChangeBaseline = serde_json::from_value(serde_json::json!("10m"))?;
    assert!(matches!(text, ChangeBaseline::RelativeMillis(600_000)));
    assert!(serde_json::from_value::<ChangeBaseline>(serde_json::json!("nope")).is_err());
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let resolved = text
        .resolve_unix_millis()
        .ok_or("relative did not resolve")?;
    assert!(
        (now - 600_000 - 5_000..=now - 600_000 + 5_000).contains(&resolved),
        "{resolved} vs {now}"
    );
    let absolute = ChangeBaseline::ObservedUnixMillis(42);
    assert_eq!(absolute.resolve_unix_millis(), Some(42));
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
