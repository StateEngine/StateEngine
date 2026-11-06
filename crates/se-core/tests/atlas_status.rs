use se_core::ops::status::atlas_view;
use se_types::{
    Read, SeError,
    code::{IndexState, IndexSummary},
};

fn summary() -> Result<IndexSummary, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(serde_json::json!({
        "project":"prj_00000000-0001-7000-8000-000000000001",
        "root":"aroot_00000000-0001-7000-8000-000000000001",
        "epoch":null,"generation":1,"state":"Current",
        "coverage":{
            "discovered_files":3,"indexed_files":3,"partial_files":0,"deferred_files":0,
            "failed_files":0,"discovery_complete":true,"stale_files":0,
            "resolved_references":1,"name_only_references":0,"watched_directories":1,
            "unwatched_directories":0,"watch_discovery_complete":true,
            "watch_stats_started":null,"watch_activation_attempts":1,
            "watch_limited_activations":0,"reasons":[]
        }
    }))?)
}
#[test]
fn published_current_index_never_hides_partial_file_or_watch_coverage()
-> Result<(), Box<dyn std::error::Error>> {
    let complete = summary()?;
    assert_eq!(
        atlas_view(Ok(Read::Present {
            value: complete.clone()
        }))
        .state,
        "current"
    );
    for index in 0..6 {
        let mut partial = complete.clone();
        match index {
            0 => partial.coverage.partial_files = 1,
            1 => partial.coverage.failed_files = 1,
            2 => partial.coverage.deferred_files = 1,
            3 => partial.coverage.stale_files = 1,
            4 => partial.coverage.discovery_complete = false,
            _ => partial.coverage.unwatched_directories = 1,
        }
        let view = atlas_view(Ok(Read::Present {
            value: partial.clone(),
        }));
        assert_eq!(view.state, "partial");
        assert_eq!(view.summary, Some(partial));
    }
    Ok(())
}
#[test]
fn preparing_unavailable_and_unreadable_are_distinct_from_current_and_disabled()
-> Result<(), Box<dyn std::error::Error>> {
    let view = atlas_view(Ok(Read::Unknown {
        what: "Opening registered roots".into(),
    }));
    assert_eq!(view.state, "preparing");
    assert_eq!(view.reason.as_deref(), Some("Opening registered roots"));
    let view = atlas_view(Ok(Read::Absent {
        checked: "No installed controller".into(),
    }));
    assert_eq!(view.state, "unavailable");
    assert!(view.summary.is_none());
    let view = atlas_view(Err(SeError::invalid(
        "Atlas catalogue",
        "an unpoisoned metadata lock",
    )));
    assert_eq!(view.state, "unreadable");
    assert!(view.reason.is_some());
    let mut opening = summary()?;
    opening.state = IndexState::Opening;
    let opening = atlas_view(Ok(Read::Present { value: opening }));
    assert_eq!(opening.state, "preparing");
    assert!(
        opening
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not available"))
    );
    let mut disabled = summary()?;
    disabled.state = IndexState::Disabled;
    disabled.coverage.discovery_complete = false;
    assert_eq!(
        atlas_view(Ok(Read::Present { value: disabled })).state,
        "disabled"
    );
    Ok(())
}
#[test]
fn bare_atlas_is_help_and_keeps_all_five_typed_queries() -> Result<(), Box<dyn std::error::Error>> {
    use se_core::ops::{self, AnyOp};
    let matches = ops::cli_command().try_get_matches_from(["se", "atlas"])?;
    let AnyOp::MetaHelp(help) = ops::from_matches(&matches)? else {
        panic!("bare atlas is not help")
    };
    assert_eq!(help.path, ["atlas"]);
    for command in ["find", "refs", "impact", "changes", "outline"] {
        let mut args = vec!["se", "atlas", command];
        if command != "changes" {
            args.push("good.js");
        } else {
            args.extend(["--since", "unused-help-cursor"]);
        }
        args.push("--help");
        let matches = ops::cli_command().try_get_matches_from(args)?;
        assert_eq!(ops::selected_meta(&matches)?.name, "meta.help");
    }
    Ok(())
}
