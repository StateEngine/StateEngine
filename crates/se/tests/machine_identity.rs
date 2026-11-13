//! Independent native consumers of the production CLI adapter and shared core policy.
#[allow(
    dead_code,
    reason = "Only the production identity/file adapter subset is exercised here."
)]
#[path = "../src/route/files.rs"]
mod files;
#[allow(
    dead_code,
    reason = "These tests drive the concrete production machine-identity entry."
)]
#[path = "../src/route/identity.rs"]
mod identity;
use se_core::machine_identity::MACHINE_IDENTITY_FILE;
use se_proc::NativeStateFiles;
use se_types::{MachineId, Read};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};
type Check = Result<(), Box<dyn std::error::Error>>;
const CHILD: &str = "machine_identity_child";
struct Home(PathBuf);
impl Home {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        se_proc::initialize_file_creation_owner()?;
        let root = loop {
            let candidate = std::env::temp_dir().join(format!(
                "se-test-machine-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            let mut builder = fs::DirBuilder::new();
            let directory = builder.recursive(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                directory.mode(0o700);
            }
            match directory.create(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        };
        let home = Self(root);
        drop(NativeStateFiles::create(&home.state())?);
        Ok(home)
    }
    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
    fn record(&self) -> PathBuf {
        self.state().join(MACHINE_IDENTITY_FILE)
    }
    fn files(&self) -> Result<files::Files, Box<dyn std::error::Error>> {
        Ok(files::Files::open(&self.state())?)
    }
    fn publish(&self, bytes: &[u8]) -> Check {
        let native = NativeStateFiles::open(&self.state())?;
        let mut stage = native.create_staging(&self.state())?;
        stage.file.write_all(bytes)?;
        stage.file.sync_all()?;
        drop(stage.file);
        native.publish_no_replace(&stage.path, &self.record())?;
        Ok(())
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!(
                "remove owned identity fixture {}: {error}",
                self.0.display()
            );
        }
    }
}
fn readback(home: &Home) -> Result<(MachineId, Vec<u8>), Box<dyn std::error::Error>> {
    let bytes = fs::read(home.record())?;
    let value: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(value["schema"], "stateengine-machine/v1");
    assert_eq!(value.as_object().ok_or("record is not an object")?.len(), 2);
    let text = value["machine_id"]
        .as_str()
        .ok_or("record omitted machine ID")?;
    Ok((MachineId::new(text)?, bytes))
}
fn exact_inventory(home: &Home) -> Check {
    let names = fs::read_dir(home.state())?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        names,
        vec![std::ffi::OsString::from(MACHINE_IDENTITY_FILE)],
        "publication left staging objects or extra identity records"
    );
    Ok(())
}
fn wait_file(path: &Path) -> Check {
    let until = Instant::now() + Duration::from_secs(10);
    while !path.try_exists()? {
        if Instant::now() >= until {
            return Err(format!("owned identity child did not publish {}", path.display()).into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

/// Protects: machine identity create-once — repeated installer/init entry and startup readback retain the same protected random identity and exact record bytes across independent native opens.
#[test]
fn initialization_persists_one_identity_without_replacing_it() -> Check {
    let home = Home::new()?;
    let id = identity::ensure_machine_identity(&home.state())?;
    let (outside, bytes) = readback(&home)?;
    assert_eq!(outside, id);
    for _ in 0..8 {
        assert_eq!(identity::ensure_machine_identity(&home.state())?, id);
        assert_eq!(identity::require_machine(&home.files()?)?, id);
        assert_eq!(fs::read(home.record())?, bytes);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let before = fs::metadata(home.record())?;
        identity::ensure_machine_identity(&home.state())?;
        let after = fs::metadata(home.record())?;
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(after.mode() & 0o077, 0, "identity record is not owner-only");
    }
    assert!(
        NativeStateFiles::open(&home.state())?
            .readback(&home.record())?
            .is_some()
    );
    exact_inventory(&home)?;
    let other = Home::new()?;
    assert_ne!(identity::ensure_machine_identity(&other.state())?, id);
    Ok(())
}

/// Protects: machine identity startup — missing identity remains named absence and runtime refuses with the init remedy without creating any identity or staging object.
#[test]
fn runtime_absence_refuses_without_allocating_an_identity() -> Check {
    let home = Home::new()?;
    assert!(matches!(
        identity::machine(&home.files()?)?,
        Read::Absent { .. }
    ));
    let error = identity::require_machine(&home.files()?)
        .err()
        .ok_or("runtime invented a missing machine identity")?;
    assert!(
        error
            .to_string()
            .contains("machine identity missing; run se init"),
        "{error}"
    );
    assert!(!home.record().try_exists()?);
    assert_eq!(fs::read_dir(home.state())?.count(), 0);
    Ok(())
}

/// Protects: machine identity corruption — malformed, empty, oversized, invalid-ID and wrong-schema records refuse unchanged; init and runtime never regenerate over existing bytes.
#[test]
fn corrupted_records_are_preserved_without_regeneration() -> Check {
    let records = vec![
        Vec::new(),
        b"null".to_vec(),
        b"{broken".to_vec(),
        vec![b'x'; 1025],
        serde_json::to_vec(&json!({"schema":"stateengine-machine/v2","machine_id":"existing"}))?,
        serde_json::to_vec(&json!({"schema":"stateengine-machine/v1","machine_id":""}))?,
        serde_json::to_vec(&json!({"schema":"stateengine-machine/v1"}))?,
        serde_json::to_vec(
            &json!({"schema":"stateengine-machine/v1","machine_id":"existing","extra":true}),
        )?,
    ];
    for bytes in records {
        let home = Home::new()?;
        home.publish(&bytes)?;
        let native = home.files()?;
        assert!(
            identity::machine(&native).is_err(),
            "corrupt record became a read fact: {bytes:?}"
        );
        assert!(identity::require_machine(&native).is_err());
        assert!(
            identity::ensure_machine_identity(&home.state()).is_err(),
            "init replaced corrupt bytes: {bytes:?}"
        );
        assert_eq!(fs::read(home.record())?, bytes);
        exact_inventory(&home)?;
    }
    Ok(())
}

/// Protects: machine identity read failures — a directory occupying the record path remains a nonregular-source refusal and never authorizes regeneration or replacement.
#[test]
fn nonregular_identity_is_never_treated_as_absence() -> Check {
    let home = Home::new()?;
    drop(NativeStateFiles::create(&home.record())?);
    assert!(identity::machine(&home.files()?).is_err());
    let error = identity::require_machine(&home.files()?)
        .err()
        .ok_or("nonregular identity was accepted")?;
    assert!(!error.to_string().contains("machine identity missing"));
    assert!(identity::ensure_machine_identity(&home.state()).is_err());
    assert!(home.record().is_dir());
    assert_eq!(fs::read_dir(home.record())?.count(), 0);
    Ok(())
}

/// Protects: machine identity native custody — an unsafe or unreadable existing record is a failure, never absence that authorizes regenerating an identity.
#[cfg(unix)]
#[test]
fn unreadable_identity_is_distinct_from_absence_and_never_repaired() -> Check {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new()?;
    let original = identity::ensure_machine_identity(&home.state())?;
    let bytes = fs::read(home.record())?;
    fs::set_permissions(home.record(), fs::Permissions::from_mode(0o0))?;
    let result = (|| -> Check {
        assert!(identity::machine(&home.files()?).is_err());
        let error = identity::require_machine(&home.files()?)
            .err()
            .ok_or("unreadable machine identity was accepted")?;
        assert!(!error.to_string().contains("machine identity missing"));
        assert!(identity::ensure_machine_identity(&home.state()).is_err());
        assert_eq!(fs::metadata(home.record())?.permissions().mode() & 0o777, 0);
        Ok(())
    })();
    fs::set_permissions(home.record(), fs::Permissions::from_mode(0o600))?;
    result?;
    assert_eq!(identity::require_machine(&home.files()?)?, original);
    assert_eq!(fs::read(home.record())?, bytes);
    Ok(())
}

/// Protects: machine identity concurrent publication — explicitly driven subprocess uses the real production native adapter, never a fake read/publication port.
#[test]
#[ignore = "explicitly spawned by the native concurrent first-create consumer"]
fn machine_identity_child() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let args: Vec<_> = std::env::args_os().collect();
    let index = args
        .last()
        .ok_or("child index")?
        .to_str()
        .ok_or("index UTF8")?;
    let root = PathBuf::from(
        args.get(args.len().checked_sub(3).ok_or("child args")?)
            .ok_or("root")?,
    );
    fs::write(root.join(format!("ready-{index}")), b"native child ready")?;
    wait_file(&root.join("go"))?;
    let id = identity::ensure_machine_identity(&root.join("state"))?;
    fs::write(
        root.join(format!("result-{index}.json")),
        serde_json::to_vec(&id)?,
    )?;
    Ok(())
}
struct Children {
    children: Vec<Child>,
    root: PathBuf,
}
impl Drop for Children {
    fn drop(&mut self) {
        if let Err(error) = fs::write(self.root.join("go"), b"release owned children") {
            eprintln!("release owned identity children: {error}");
        }
        for child in &mut self.children {
            if let Err(error) = child.wait() {
                eprintln!("join owned identity child {}: {error}", child.id());
            }
        }
    }
}

/// Protects: machine identity concurrent first create — eight independent native processes publish into one measured-absent home and all return the same permanent winner without staging residue.
#[test]
fn concurrent_initializers_converge_on_one_permanent_winner() -> Check {
    let home = Home::new()?;
    let mut owned = Children {
        children: vec![],
        root: home.0.clone(),
    };
    for number in 0..8 {
        let log = fs::File::create(home.0.join(format!("child-{number}.log")))?;
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD, "--ignored", "--nocapture", "--skip"])
            .arg(&home.0)
            .arg("--skip")
            .arg(number.to_string())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?;
        owned.children.push(child);
    }
    for number in 0..8 {
        wait_file(&home.0.join(format!("ready-{number}")))?;
    }
    assert!(
        !home.record().try_exists()?,
        "child started publication before the common release"
    );
    fs::write(home.0.join("go"), b"start first publication")?;
    for (number, child) in owned.children.iter_mut().enumerate() {
        let status = child.wait()?;
        assert!(
            status.success(),
            "owned initializer {number} failed: {}",
            fs::read_to_string(home.0.join(format!("child-{number}.log")))?
        );
    }
    let (id, bytes) = readback(&home)?;
    for number in 0..8 {
        let observed: MachineId =
            serde_json::from_slice(&fs::read(home.0.join(format!("result-{number}.json")))?)?;
        assert_eq!(
            observed, id,
            "concurrent initializer returned its unpublished candidate"
        );
    }
    assert_eq!(identity::ensure_machine_identity(&home.state())?, id);
    assert_eq!(fs::read(home.record())?, bytes);
    exact_inventory(&home)?;
    Ok(())
}
