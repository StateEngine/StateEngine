use se_host::{HarnessRequest, SessionIdentity, claude};
use se_proc::{
    ContainmentRequirement, LaunchMode, LaunchPolicy, NetworkPolicy, OptionalHardening, WritePolicy,
};
use se_types::{Body, IdempotencyKey, NativePath, ProviderSessionId, Read, Secret};

#[test]
fn transcript_directory_matches_native_claude_long_slug_vectors()
-> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;
    let conversation = ProviderSessionId::new("01234567-89ab-4cde-8f01-23456789abcd")?;
    // Values independently read from Claude 2.1.318's native slug convention.
    let cases = [
        (format!("/r/{}", "a".repeat(197)), format!("-r-{}", "a".repeat(197))),
        (format!("/r/{}", "a".repeat(198)), format!("-r-{}-7yt9zg", "a".repeat(197))),
        (format!("C:\\work\\{}😀", "long_".repeat(50)), "C--work-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-lo-oqe50p".into()),
        (format!("/tmp/{}", "😀".repeat(98)), format!("-tmp{}-24ezzn", "-".repeat(196))),
    ];
    for (cwd, slug) in cases {
        let path = claude::transcript_path(Path::new("config"), Path::new(&cwd), &conversation);
        assert_eq!(
            path,
            Path::new("config")
                .join("projects")
                .join(slug)
                .join(format!("{conversation}.jsonl"))
        );
    }
    Ok(())
}

#[test]
fn window_task_cannot_supply_claude_options_on_new_or_resumed_launches()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::current_dir()?;
    let conversation = ProviderSessionId::new("01234567-89ab-4cde-8f01-23456789abcd")?;
    let task = "--dangerously-skip-permissions --permission-mode bypassPermissions";
    let request = HarnessRequest {
        identity: SessionIdentity {
            project: se_types::ProjectId::from_parts(1_700_000_000_000, [1; 10])?,
            agent: se_types::AgentId::from_parts(1_700_000_000_000, [2; 10])?,
            session: se_types::SessionId::from_parts(1_700_000_000_000, [3; 10])?,
        },
        executable: NativePath::from_local(directory.join("claude"))?,
        cwd: NativePath::from_local(directory.clone())?,
        profile: se_store::Profile {
            provider: se_store::Provider::Claude,
            model: Some("configured-model".into()),
            permission: se_store::PermissionProfile::WorkspaceWrite,
            named_profile: "default".into(),
            effort: None,
        },
        policy: LaunchPolicy {
            containment: ContainmentRequirement::BestAvailable,
            writes: WritePolicy::ReadOnly {
                scratch: directory.clone(),
            },
            network: NetworkPolicy::Allow,
            hardening: OptionalHardening::Off,
        },
        mode: LaunchMode::Window,
        resume: Read::Absent {
            checked: "new launch".into(),
        },
        initial_input: Body::new(task)?,
        launch_credential: Secret::new(vec![1; 32])?,
        mcp_bearer: Secret::new(vec![2; 32])?,
        key: IdempotencyKey::new("leading-dash-task")?,
    };
    for resume in [false, true] {
        let launch = claude::ClaudeLaunch {
            request: &request,
            se_executable: &directory.join("se"),
            state_home: &directory,
            launch_directory: &directory,
            mcp_port: 21345,
            conversation: &conversation,
            resume,
        };
        let invocation = claude::invocation(&launch, Vec::new())?;
        let args: Vec<_> = invocation
            .arguments
            .iter()
            .map(|a| a.to_string_lossy())
            .collect();
        let guard = args
            .iter()
            .position(|arg| arg == "--")
            .ok_or("missing prompt guard")?;
        assert_eq!(&args[guard + 1..], &[task]);
        assert!(
            !args[..guard]
                .iter()
                .any(|a| a.contains("bypassPermissions"))
        );
        for flag in [
            "--permission-mode",
            "--model",
            if resume { "--resume" } else { "--session-id" },
        ] {
            assert!(args[..guard].iter().any(|a| a == flag));
        }
        assert!(
            args[..guard]
                .windows(2)
                .any(|a| a == ["--permission-mode", "acceptEdits"])
        );
    }
    Ok(())
}
