//! Public protected-receipt reader controls; final OS closure is a CLI concern.
#![cfg(any(target_os = "linux", windows))]
#[path = "support/wave2_host_fixture.rs"]
mod support;
use se_host::{
    EndpointRecord, HostKind, IpcEndpoint,
    client::closure::{self, RuntimeClosure},
};
use se_types::{API_VERSION, Generation, HostGeneration, IdempotencyKey, NativePath};
use std::io::Write;
use support::*;

fn endpoint(f: &Fixture) -> Result<EndpointRecord, Box<dyn std::error::Error>> {
    Ok(EndpointRecord {
        schema: 1,
        #[cfg(unix)]
        address: IpcEndpoint::UnixSocket(NativePath::from_local(f.home.join("unused.sock"))?),
        #[cfg(windows)]
        address: IpcEndpoint::WindowsPipe("unused-closure-reader-control".into()),
        epoch: start(f)?.epoch,
        generation: Generation::new(1)?,
        kind: HostKind::EmbeddedSecode,
        listener_port: None,
        api: API_VERSION,
        package_version: "0.0.1".into(),
        image_sha256: se_types::Sha256::from_bytes([0; 32]),
    })
}
fn publish(f: &Fixture, bytes: &[u8]) -> Check {
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut staged = files.create_staging(&f.options.state_directory)?;
    staged.file.write_all(bytes)?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(
        &staged.path,
        &f.options.state_directory.join("runtime-close.json"),
    )?;
    Ok(())
}
#[test]
fn protected_receipt_requires_original_key_epoch_and_generation_without_promoting_incomplete_facts()
-> Check {
    let f = Fixture::new()?;
    let files = Files(se_proc::NativeStateFiles::open(&f.options.state_directory)?);
    assert!(closure::read(&files, &f.options.state_directory)?.is_none());
    let endpoint = endpoint(&f)?;
    let key = IdempotencyKey::new("original-stop")?;
    let record = RuntimeClosure {
        schema: 1,
        epoch: endpoint.epoch.clone(),
        generation: endpoint.generation,
        key: key.clone(),
        resources_closed: false,
        stops: vec![],
        pending: vec!["retained writer".into()],
    };
    publish(&f, &serde_json::to_vec(&record)?)?;
    let observed = closure::read(&files, &f.options.state_directory)?.ok_or("receipt absent")?;
    assert!(observed.matches(&endpoint, &key));
    assert!(!observed.resources_closed);
    assert_eq!(observed.pending, ["retained writer"]);
    assert!(!observed.matches(&endpoint, &IdempotencyKey::new("different-stop")?));
    let mut changed = endpoint.clone();
    changed.generation = Generation::new(2)?;
    assert!(!observed.matches(&changed, &key));
    changed = endpoint.clone();
    changed.epoch.generation = HostGeneration::new(2)?;
    assert!(!observed.matches(&changed, &key));
    changed = endpoint.clone();
    let mut owner = changed.epoch.owner.fields().clone();
    owner.argv_sha256 = se_types::Sha256::from_bytes([91; 32]);
    changed.epoch.owner = se_types::ProcessInstance::from_observation(owner)?;
    assert!(
        !observed.matches(&changed, &key),
        "epoch owner drift was ignored"
    );
    let other = Fixture::new()?;
    let mut unsupported = record;
    unsupported.schema = 99;
    publish(&other, &serde_json::to_vec(&unsupported)?)?;
    let other_files = Files(se_proc::NativeStateFiles::open(
        &other.options.state_directory,
    )?);
    let refused = closure::read(&other_files, &other.options.state_directory)
        .err()
        .ok_or("unknown schema accepted")?;
    assert!(refused.to_string().contains("unsupported schema"));
    Ok(())
}
#[test]
fn malformed_oversized_and_unknown_schema_are_unreadable_instead_of_absent() -> Check {
    for bytes in [
        b"{broken".to_vec(),
        vec![b' '; 1_048_577],
        br#"{"schema":99}"#.to_vec(),
    ] {
        let f = Fixture::new()?;
        let files = Files(se_proc::NativeStateFiles::open(&f.options.state_directory)?);
        publish(&f, &bytes)?;
        assert!(
            closure::read(&files, &f.options.state_directory).is_err(),
            "damaged receipt became absent or complete"
        );
    }
    Ok(())
}
