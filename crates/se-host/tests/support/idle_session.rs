//! A real, fifteen-minute session capability in an explicitly owned stopped home.
use se_store::*;
use se_types::{AgentId, HumanId, Read, SessionId};
use sha2::{Digest, Sha256};
use std::{error::Error, fs, io::Write, path::Path, str::FromStr, time::Duration};
#[path = "../../../se-store/tests/support/store_fixture.rs"]
mod fixture;

pub fn prepare(home: &Path, init: &Path) -> Result<(), Box<dyn Error>> {
    let init: serde_json::Value = serde_json::from_slice(&fs::read(init)?)?;
    let text = |field: &str| {
        init.pointer(field)
            .and_then(|v| v.as_str())
            .ok_or("init field absent")
    };
    let options = StoreOptions {
        state_directory: home.into(),
        busy_timeout: Duration::from_secs(5),
    };
    let Read::Present { value: reader } = SqliteFactory::open_reader(&options)? else {
        return Err("owned store absent".into());
    };
    let store = reader.info()?.id;
    let agent = AgentId::from_str(text("/agent/id")?)?;
    // Fixture normally removes its own home on Drop. This is an external CLI
    // home and must survive both this helper and the subsequent native runtime.
    let f = std::mem::ManuallyDrop::new(fixture::Fixture {
        home: home.into(),
        options,
        store: store.clone(),
        owner: HumanId::from_str(text("/owner/human_id")?)?,
        project: text("/project/id")?.parse()?,
        a: agent.clone(),
        b: agent.clone(),
    });
    let lease = fixture::Lease::acquire(home, LeaseMode::DirectClient, Some(store))?;
    let Read::Present { value: mut direct } = SqliteFactory::open_direct(&f.options, &*lease)?
    else {
        return Err("owned direct store absent".into());
    };
    let token = se_proc::random_secret().map_err(|e| format!("entropy: {e:?}"))?;
    let session = SessionId::from_parts(1_700_000_000_000, [73; 10])?;
    let credential = RecordId::from_parts(1_700_000_000_001, [51; 10])?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("idle-session-setup")?),
            vec![
                EventBody::SessionPrepared {
                    session: session.clone(),
                    agent,
                    provider: Provider::Codex,
                    surface: None,
                    native_ref: "idle-session-test".into(),
                    consent: Consent::Capture,
                    generation: 1,
                    expected: Expected::Absent,
                },
                EventBody::CredentialIssued {
                    credential,
                    session: session.clone(),
                    purpose: "session".into(),
                    secret_sha256: Sha256::digest(token.expose()).into(),
                    expires_at_us: now + 900_000_000,
                    activation_deadline_us: now + 60_000_000,
                    expected: Expected::Absent,
                },
                EventBody::SessionActivated {
                    session: session.clone(),
                    expected: fixture::revision(1)?,
                    incumbent: None,
                    process: None,
                    containment: ContainmentFact::NotLaunched,
                    witnesses: vec![],
                },
                EventBody::CredentialActivated {
                    credential,
                    session,
                    expected: fixture::revision(1)?,
                    first_request: RecordId::from_parts(1_700_000_000_002, [52; 10])?,
                },
            ],
        )?,
        &*lease,
    )?;
    direct.close()?;
    let files = se_proc::NativeStateFiles::open(home)?;
    let mut stage = files.create_staging(home)?;
    stage.file.write_all(token.expose())?;
    stage.file.sync_all()?;
    drop(stage.file);
    files.publish_no_replace(&stage.path, &home.join("idle-session-credential"))?;
    Ok(())
}
