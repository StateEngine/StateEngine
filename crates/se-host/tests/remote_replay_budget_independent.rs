//! Protects: an accepted small watch page must advance past an escaped provider preview or explicitly refuse.
#![cfg(feature = "remote")]
use se_store::remote::*;
use se_store::*;
use se_types::remote::*;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "only native session setup helpers are used")]
mod capture;
fn rev(n: u64) -> Result<Revision, Box<dyn std::error::Error>> {
    Ok(Revision {
        value: std::num::NonZeroU64::new(n).ok_or("zero revision")?,
    })
}
fn now() -> Result<i64, Box<dyn std::error::Error>> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_micros()
        .try_into()?)
}
fn setup(
    f: &Fixture,
    d: &mut SqliteDirect,
    l: &Lease,
) -> Result<GrantRecord, Box<dyn std::error::Error>> {
    let at = now()?;
    let scope = RemoteScope {
        targets: vec![RemoteTarget {
            project: f.project.clone(),
            agent: f.a.clone(),
        }],
        verbs: vec![RemoteVerb::List, RemoteVerb::Watch, RemoteVerb::Send],
    };
    let host = RemoteHostId(se_types::Sha256::from_bytes([22; 32]));
    let grant = GrantRecord {
        grant: RemoteGrantId::from_parts(1_700_000_000_000, [24; 10])?,
        principal: RemotePrincipalId::from_parts(1_700_000_000_000, [25; 10])?,
        device: RemoteDeviceId::from_parts(1_700_000_000_000, [26; 10])?,
        credential_sha256: CredentialDigest([27; 32]),
        host,
        store: f.store.clone(),
        subject: RemoteSubject::Machine {
            host: RemoteHostId(se_types::Sha256::from_bytes([28; 32])),
        },
        scope,
        issued_at_us: at,
        last_use_at_us: at,
        expires_at_us: at + GRANT_INACTIVITY_US,
        authority_revision: rev(1)?,
        lease_revision: rev(1)?,
        state: GrantState::Active,
    };
    d.append(
        f.batch(
            f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
            Some(request("connect")?),
            vec![EventBody::RemoteSecurity {
                transition: SecurityTransition::Connect {
                    grant: Box::new(grant.clone()),
                },
            }],
        )?,
        l,
    )?;
    d.append(
        f.batch(
            f.owner_project(),
            Some(request("profile")?),
            vec![EventBody::ProfileSaved {
                agent: f.a.clone(),
                profile: Profile {
                    provider: Provider::Claude,
                    model: None,
                    permission: PermissionProfile::WorkspaceWrite,
                    named_profile: "workspace-write".into(),
                    effort: None,
                },
                expected: Expected::Absent,
            }],
        )?,
        l,
    )?;
    Ok(grant)
}

/// Bug: a valid JSON-escaped preview exceeds the accepted minimum page budget and returns endless empty success.
#[test]
fn accepted_watch_budget_advances_or_refuses_escaped_turn() -> Check {
    let f = Fixture::new()?;
    let (mut d, l) = f.direct()?;
    let g = setup(&f, &mut d, &l)?;
    let session = capture::session()?;
    let source = capture::record()?;
    capture::active(&f, &mut d, &l, &session, source)?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut phase = reader.read_phase()?;
    let before = phase.remote_changes(
        &g.grant,
        rev(1)?,
        &g.scope.targets[0],
        ChangeRequest {
            after: None,
            limit: 100,
            budget: 65536,
        },
        now()?,
    )?;
    phase.close()?;
    let text = "\"".repeat(512);
    let evidence = text.as_bytes();
    std::fs::write(f.home.join("transcript.jsonl"), evidence)?;
    let mut captured = capture::capture(
        &f,
        &session,
        source,
        b"first",
        0,
        1,
        "escaped-provider-item",
    )?;
    use sha2::{Digest, Sha256};
    for event in &mut captured.events {
        match &mut event.body {
            EventBody::SessionTurn {
                text: body,
                evidence: proof,
                ..
            } => {
                *body = InputText::Inline(text.clone());
                proof.length = evidence.len() as u64;
                proof.sha256 = Some(Sha256::digest(evidence).into());
            }
            EventBody::CaptureProgress { new_offset, .. } => *new_offset = evidence.len() as u64,
            _ => {}
        }
    }
    d.append(captured, &*l)?;
    let mut phase = reader.read_phase()?;
    let large = phase.remote_changes(
        &g.grant,
        rev(1)?,
        &g.scope.targets[0],
        ChangeRequest {
            after: before.through.as_ref(),
            limit: 100,
            budget: 65536,
        },
        now()?,
    )?;
    assert!(large.changes.iter().any(|c|matches!(&c.kind,ChangeKind::Durable(RemoteDurableEvent::Turn {preview,..}) if preview.text==text)));
    let mut stuck = 0;
    for _ in 0..3 {
        let page = phase.remote_changes(
            &g.grant,
            rev(1)?,
            &g.scope.targets[0],
            ChangeRequest {
                after: before.through.as_ref(),
                limit: 100,
                budget: 1024,
            },
            now()?,
        );
        if let Ok(page) = page {
            println!(
                "accepted minimum budget: changes={}, more={}, cursor_unchanged={}",
                page.changes.len(),
                page.more,
                page.through == before.through
            );
            if page.changes.is_empty() && page.more && page.through == before.through {
                stuck += 1;
            }
        }
    }
    phase.close()?;
    d.close()?;
    assert_eq!(
        stuck, 0,
        "accepted watch budget repeatedly succeeds without consuming or explicitly refusing the next valid provider turn"
    );
    Ok(())
}
