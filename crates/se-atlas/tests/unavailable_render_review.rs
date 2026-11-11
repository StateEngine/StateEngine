//! Unavailable reads stay distinguishable through each compact page consumer.
use se_atlas::render;
use se_types::{ProjectId, Read, code::*};

type Check = Result<(), Box<dyn std::error::Error>>;

fn answer<T>(data: Read<T>) -> Result<Answer<Read<T>>, Box<dyn std::error::Error>> {
    Ok(Answer {
        index: IndexSummary {
            project: ProjectId::from_parts(1, [1; 10])?,
            root: RootId::from_parts(1, [2; 10])?,
            epoch: None,
            generation: None,
            state: IndexState::NotBuilt,
            coverage: serde_json::from_value(serde_json::json!({
                "discovered_files":0,"indexed_files":0,"partial_files":0,
                "deferred_files":0,"failed_files":0,"discovery_complete":false,
                "stale_files":0,"resolved_references":0,"name_only_references":0,
                "watched_directories":0,"unwatched_directories":0,
                "watch_discovery_complete":false,"watch_stats_started":null,
                "watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]
            }))?,
            memory: None,
        },
        snapshot_advanced: false,
        epoch_retired: false,
        data,
    })
}

fn check(read: Read<()>, expected: &str) -> Check {
    let outputs = [
        render::refs(
            &answer(read.clone().map(|()| panic!("unavailable value")))?,
            4096,
        )?,
        render::impact(
            &answer(read.clone().map(|()| panic!("unavailable value")))?,
            4096,
        )?,
        render::changes(
            &answer(read.clone().map(|()| panic!("unavailable value")))?,
            4096,
        )?,
        render::outline(&answer(read.map(|()| panic!("unavailable value")))?, 4096)?,
    ];
    for output in outputs {
        assert!(
            output.contains(expected),
            "lost unavailable state: {output}"
        );
        assert!(
            !output.contains('\u{1b}'),
            "unescaped terminal control: {output}"
        );
        for other in ["absent:", "unknown:", "unreadable source:"] {
            if !expected.starts_with(other) {
                assert!(!output.contains(other), "invented read state: {output}");
            }
        }
    }
    Ok(())
}

#[test]
fn absent_pages_preserve_checked_absence() -> Check {
    check(
        Read::Absent {
            checked: "checked\u{1b}[31m".into(),
        },
        "absent: checked\\u{1b}[31m",
    )
}

#[test]
fn unknown_pages_do_not_become_absent_or_empty_success() -> Check {
    check(
        Read::Unknown {
            what: "not observed\n".into(),
        },
        "unknown: not observed\\n",
    )
}

#[test]
fn unreadable_pages_preserve_source_and_failure_reason() -> Check {
    check(
        Read::Unreadable {
            source: "source".into(),
            reason: "denied\t".into(),
            error: None,
        },
        "unreadable source: denied\\t",
    )
}
