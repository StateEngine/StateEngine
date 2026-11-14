//! Public per-launch DTO controls after warm version qualification.
//! These do not claim authenticated attach, network or native Windows evidence.
#![cfg(all(feature = "listener", unix))]
#[path = "support/codex_probe_fixture.rs"]
mod fixture;
use fixture::{Check, Fixture, context};
use se_config::config_policy::{ConfigFile, Provider};
use se_host::{
    Harness, HarnessRequest, SessionIdentity,
    codex_input::{self, CodexLaunch},
};
use se_proc::{
    ContainmentRequirement, LaunchMode, LaunchPolicy, NetworkPolicy, OptionalHardening, WritePolicy,
};
use se_types::{Body, IdempotencyKey, NativePath, ProviderSessionId, Read, Secret};
use serde_json::json;

fn request(f: &Fixture, sequence: u8) -> Check<HarnessRequest> {
    Ok(HarnessRequest {
        identity: SessionIdentity {
            project: se_types::ProjectId::from_parts(1_700_000_000_000, [1; 10])?,
            agent: se_types::AgentId::from_parts(1_700_000_000_000, [2; 10])?,
            session: se_types::SessionId::from_parts(1_700_000_000_000, [sequence; 10])?,
        },
        executable: NativePath::from_local(f.image.clone())?,
        cwd: NativePath::from_local(f.root.clone())?,
        profile: se_store::Profile {
            provider: se_store::Provider::Codex,
            model: Some("fixture-model".into()),
            permission: se_store::PermissionProfile::WorkspaceWrite,
            harness: None,
            named_profile: "default".into(),
            effort: Some("high".into()),
        },
        policy: LaunchPolicy {
            containment: ContainmentRequirement::BestAvailable,
            writes: WritePolicy::Workspace {
                roots: vec![f.root.clone()],
                scratch: f.root.clone(),
            },
            network: NetworkPolicy::Offline,
            hardening: OptionalHardening::Off,
        },
        mode: LaunchMode::Headless,
        resume: Read::Absent {
            checked: "fresh fixture request".into(),
        },
        transcript_roots: vec![],
        replay: None,
        initial_input: Body::new("One synthetic fixture turn.")?,
        launch_credential: Secret::new(
            format!("sec1.synthetic-fixture-pin-{sequence}").into_bytes(),
        )?,
        mcp_bearer: Secret::new(format!("sels-synthetic-fixture-bearer-{sequence}").into_bytes())?,
        key: IdempotencyKey::new(format!("synthetic-fixture-request-{sequence}"))?,
    })
}

#[test]
fn warm_version_does_not_reuse_session_credentials_or_launch_configuration() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    f.direct(&harness, &f.image)?;
    f.direct(&harness, &f.image)?;
    assert_eq!(f.children()?, 1);
    let resolved = ConfigFile::default().resolve_profile("default", Provider::Codex, true)?;
    let mut prior_path = None;
    let mut prior_params = None;
    for sequence in [3, 4] {
        let request = request(&f, sequence)?;
        let config = f
            .runtime
            .block_on(harness.configuration(&request, context()?))?;
        assert_eq!(config.ephemeral_files.len(), 1);
        let file = &config.ephemeral_files[0];
        let path = file.path.to_local()?;
        assert_ne!(prior_path.as_ref(), Some(&path));
        let saved: serde_json::Value = serde_json::from_slice(file.contents.expose())?;
        assert_eq!(saved["session"], request.identity.session.as_str());
        prior_path = Some(path);
        let invocation = f
            .runtime
            .block_on(harness.invocation(&request, context()?))?;
        assert!(
            invocation
                .environment
                .entries
                .iter()
                .any(|(key, value)| key == "SE_SESSION"
                    && value == request.identity.session.as_str())
        );
        let plan = CodexLaunch {
            request: &request,
            resolved: &resolved,
            mcp_port: 21345,
            socket: None,
        };
        let (method, params) = codex_input::thread(&plan)?;
        assert_eq!(method, "thread/start");
        let headers = &params["config"]["mcp_servers.stateengine"]["http_headers"];
        assert_eq!(
            headers["Authorization"],
            format!("Bearer sels-synthetic-fixture-bearer-{sequence}")
        );
        assert_eq!(
            headers["X-StateEngine-Session-Proof"],
            format!("sec1.synthetic-fixture-pin-{sequence}")
        );
        let public = format!(
            "{:?}{:?}",
            invocation.arguments, invocation.environment.entries
        );
        for secret in [&request.launch_credential, &request.mcp_bearer] {
            let text = std::str::from_utf8(secret.expose())?;
            assert!(
                !public.contains(text),
                "per-launch authority must stay out of argv/environment"
            );
            assert!(!std::str::from_utf8(file.contents.expose())?.contains(text));
        }
        if let Some(previous) = prior_params {
            assert_ne!(params, previous);
        }
        prior_params = Some(params);
    }
    assert_eq!(
        f.children()?,
        1,
        "DTO refresh must not be confused with another version child"
    );
    f.cleanup()
}

#[test]
fn warm_version_does_not_bypass_current_policy_or_unreadable_resume_checks() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    f.direct(&harness, &f.image)?;
    f.direct(&harness, &f.image)?;
    let mut request = request(&f, 5)?;
    request.profile.named_profile = "missing-profile".into();
    assert!(
        f.runtime
            .block_on(harness.configuration(&request, context()?))
            .is_err()
    );
    assert!(
        f.runtime
            .block_on(harness.invocation(&request, context()?))
            .is_err()
    );
    request.profile.named_profile = "default".into();
    request.policy.network = NetworkPolicy::Allow;
    assert!(
        f.runtime
            .block_on(harness.configuration(&request, context()?))
            .is_err()
    );
    assert!(
        f.runtime
            .block_on(harness.invocation(&request, context()?))
            .is_err()
    );
    request.policy.network = NetworkPolicy::Offline;
    request.resume = Read::Unknown {
        what: "saved conversation was not witnessed".into(),
    };
    assert!(
        f.runtime
            .block_on(harness.configuration(&request, context()?))
            .is_err()
    );
    assert_eq!(f.children()?, 1);
    f.cleanup()
}

#[test]
fn warm_version_is_not_an_acknowledgment_of_thread_or_effective_policy() -> Check {
    let f = Fixture::new()?;
    let harness = f.harness();
    f.direct(&harness, &f.image)?;
    f.direct(&harness, &f.image)?;
    let mut request = request(&f, 6)?;
    request.resume = Read::Present {
        value: ProviderSessionId::new("fixture-thread-1")?,
    };
    let resolved = ConfigFile::default().resolve_profile("default", Provider::Codex, true)?;
    let plan = CodexLaunch {
        request: &request,
        resolved: &resolved,
        mcp_port: 21345,
        socket: None,
    };
    let (method, params) = codex_input::thread(&plan)?;
    assert_eq!(method, "thread/resume");
    assert_eq!(params["threadId"], "fixture-thread-1");
    let reply = json!({"thread":{"id":"fixture-thread-1"}, "cwd":f.root,
        "approvalPolicy":"never", "sandbox":{"type":"workspaceWrite", "writableRoots":[],
            "networkAccess":false, "excludeTmpdirEnvVar":true, "excludeSlashTmp":true}});
    assert_eq!(
        codex_input::verify_thread(&plan, &reply)?.as_str(),
        "fixture-thread-1"
    );
    for field in ["thread", "cwd", "approvalPolicy", "sandbox"] {
        let mut absent = reply.clone();
        absent
            .as_object_mut()
            .ok_or("fixture reply object absent")?
            .remove(field);
        assert!(
            codex_input::verify_thread(&plan, &absent).is_err(),
            "missing {field} acknowledgment must refuse"
        );
    }
    for (field, changed) in [
        ("thread", json!({"id":"fixture-thread-2"})),
        ("approvalPolicy", json!("on-request")),
        ("sandbox", json!({"type":"dangerFullAccess"})),
    ] {
        let mut mismatch = reply.clone();
        mismatch[field] = changed;
        assert!(
            codex_input::verify_thread(&plan, &mismatch).is_err(),
            "changed {field} must refuse"
        );
    }
    assert_eq!(f.children()?, 1);
    f.cleanup()
}
