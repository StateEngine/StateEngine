use super::*;

#[test]
fn parse_init_envelope_refuses_unrecognized_outcomes() {
    let bad_project = br#"{"schema":"se.init/v1","outcome":"unexpected","project":{"id":"prj_01000000-0000-7000-8000-000000000001","name":"demo","root":"/srv/repo"},"agent":{"id":"ag_01000000-0000-7000-8000-000000000002","name":"w","outcome":"created"}}"#;
    assert!(parse_init_envelope(bad_project).is_err());

    let bad_agent = br#"{"schema":"se.init/v1","outcome":"created","project":{"id":"prj_01000000-0000-7000-8000-000000000001","name":"demo","root":"/srv/repo"},"agent":{"id":"ag_01000000-0000-7000-8000-000000000002","name":"w","outcome":"maybe"}}"#;
    assert!(parse_init_envelope(bad_agent).is_err());
}

#[test]
fn exit_code_is_two_on_partial_progress_and_one_without_progress() {
    let mut report = InitReport {
        complete: false,
        alias: "box".into(),
        destination: "box".into(),
        remote_path: "/srv/repo".into(),
        host: None,
        project: None,
        agent: None,
        launch_allowed: false,
        phases: vec![PhaseReport {
            phase: "prepare_local",
            status: "failed",
            detail: "boom".into(),
        }],
        error: None,
        remedy: Some("fix it".into()),
    };
    assert_eq!(exit_code_for(&report), 1);
    report.phases.insert(
        0,
        PhaseReport {
            phase: "prepare_local",
            status: "ok",
            detail: "ok".into(),
        },
    );
    assert_eq!(exit_code_for(&report), 2);
}

#[test]
fn human_output_escapes_control_chars_and_includes_remedy_and_rerun() -> io::Result<()> {
    let report = InitReport {
        complete: false,
        alias: "box".into(),
        destination: "box".into(),
        remote_path: "/srv/repo".into(),
        host: None,
        project: None,
        agent: None,
        launch_allowed: false,
        phases: vec![
            PhaseReport {
                phase: "prepare_local",
                status: "ok",
                detail: "verified".into(),
            },
            PhaseReport {
                phase: "init_remote_project",
                status: "failed",
                detail: "peer \u{1b}[31mboom".into(),
            },
        ],
        error: None,
        remedy: Some("fix \u{1b}[1mnow".into()),
    };
    let mut out = Vec::new();
    write_human(&report, &mut out)?;
    let rendered = String::from_utf8_lossy(&out);
    assert!(
        !rendered.contains('\u{1b}'),
        "raw escape leaked: {rendered:?}"
    );
    assert!(rendered.contains("Remedy:"), "remedy missing: {rendered}");
    assert!(
        rendered.contains(
            "Next: resolve the reported error, then rerun your original `se remote init` command to continue from the completed phases."
        ),
        "rerun next step missing: {rendered}"
    );
    Ok(())
}

#[test]
fn human_output_rerun_uses_shell_safe_plain_instruction_for_windows_paths() -> io::Result<()> {
    let report = InitReport {
        complete: false,
        alias: "build".into(),
        destination: "dev@build-box".into(),
        remote_path: r"C:\work\my repo".into(),
        host: None,
        project: None,
        agent: None,
        launch_allowed: false,
        phases: vec![
            PhaseReport {
                phase: "prepare_local",
                status: "ok",
                detail: "verified".into(),
            },
            PhaseReport {
                phase: "grant_launch_permission",
                status: "failed",
                detail: "timeout".into(),
            },
        ],
        error: None,
        remedy: Some("retry when reachable".into()),
    };
    let mut out = Vec::new();
    write_human(&report, &mut out)?;
    let rendered = String::from_utf8_lossy(&out);
    assert_eq!(
        rendered.lines().find(|line| line.starts_with("Next:")),
        Some(
            "Next: resolve the reported error, then rerun your original `se remote init` command to continue from the completed phases."
        )
    );
    Ok(())
}
