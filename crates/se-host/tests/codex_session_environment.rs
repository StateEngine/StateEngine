#![cfg(feature = "listener")]
use se_core::config_policy::{Approval, EffectiveSandbox, ResolvedProfile};
use se_host::{HarnessRequest, SessionIdentity, codex_input};
use se_proc::{
    ContainmentRequirement, LaunchMode, LaunchPolicy, NetworkPolicy, OptionalHardening, WritePolicy,
};
use se_types::{Body, IdempotencyKey, NativePath, Read, Secret};

#[test]
fn external_stdio_gets_only_the_new_public_session_in_both_surfaces()
-> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let mut request = HarnessRequest {
        identity: SessionIdentity {
            project: se_types::ProjectId::from_parts(1_700_000_000_000, [1; 10])?,
            agent: se_types::AgentId::from_parts(1_700_000_000_000, [2; 10])?,
            session: se_types::SessionId::from_parts(1_700_000_000_000, [3; 10])?,
        },
        executable: NativePath::from_local(cwd.join("codex"))?,
        cwd: NativePath::from_local(cwd.clone())?,
        profile: se_store::Profile {
            provider: se_store::Provider::Codex,
            model: None,
            permission: se_store::PermissionProfile::WorkspaceWrite,
            named_profile: "default".into(),
            effort: None,
        },
        policy: LaunchPolicy {
            containment: ContainmentRequirement::BestAvailable,
            writes: WritePolicy::Workspace {
                roots: vec![cwd.clone()],
                scratch: cwd.join("launch"),
            },
            network: NetworkPolicy::Offline,
            hardening: OptionalHardening::Off,
        },
        mode: LaunchMode::Headless,
        resume: Read::Absent {
            checked: "new launch".into(),
        },
        transcript_roots: Vec::new(),
        replay: None,
        initial_input: Body::new("Read your context.")?,
        launch_credential: Secret::new(b"sec1.never-in-environment".to_vec())?,
        mcp_bearer: Secret::new(b"sels-never-in-environment".to_vec())?,
        key: IdempotencyKey::new("fresh-public-session")?,
    };
    let resolved = ResolvedProfile {
        name: "default".into(),
        sandbox: EffectiveSandbox::WorkspaceWrite,
        approval: Approval::Never,
        network: false,
        bypass: false,
    };
    for mode in [LaunchMode::Headless, LaunchMode::Window] {
        request.mode = mode;
        let launch = codex_input::CodexLaunch {
            request: &request,
            resolved: &resolved,
            mcp_port: 21345,
            socket: None,
        };
        let invocation = codex_input::invocation(
            &launch,
            vec![
                ("se_session".into(), "another-session".into()),
                ("STATEENGINE_AGENT_ID".into(), "another-agent".into()),
                ("SECODE_STATEENGINE_BEARER".into(), "another-secret".into()),
                ("CODEX_HOME".into(), "existing-provider-home".into()),
            ],
        )?;
        assert_eq!(
            invocation.environment.entries,
            vec![
                ("CODEX_HOME".into(), "existing-provider-home".into()),
                (
                    "SE_SESSION".into(),
                    request.identity.session.as_str().into()
                ),
            ]
        );
        let params = codex_input::thread(&launch)?.1;
        assert_eq!(params["approvalPolicy"], "never");
        assert_eq!(params["sandbox"], "workspace-write");
        assert_eq!(
            params["config"]["sandbox_workspace_write"]["network_access"],
            false
        );
    }
    Ok(())
}
