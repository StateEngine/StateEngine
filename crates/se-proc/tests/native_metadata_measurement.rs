//! Development observer for the native identity operations used by admission.
use se_proc::{NativeFileIdentity, NativeStateFiles};
use serde_json::json;
use std::{error::Error, io::Write, path::Path, time::Instant};
#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn measure_native_metadata_validation() -> Result<(), Box<dyn Error>> {
    se_proc::initialize_file_creation_owner()?;
    let home = directory::private_directory()?;
    let root = home.join("state");
    let files = NativeStateFiles::create(&root)?;
    let mut stage = files.create_staging(&root)?;
    stage.file.write_all(b"synthetic metadata measurement")?;
    stage.file.sync_all()?;
    drop(stage.file);
    let path = root.join("state.db");
    files.publish_no_replace(&stage.path, &path)?;
    let pin = files.pin_metadata(&path)?.ok_or("metadata pin absent")?;
    let original = NativeFileIdentity::observe(&path)?;
    let mut rows = Vec::new();
    for _ in 0..100 {
        let start = Instant::now();
        pin.validate_path(&path)?;
        let pin_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        let metadata = files.inspect_metadata(&path)?.ok_or("metadata absent")?;
        let metadata_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        let observed = NativeFileIdentity::observe(&path)?;
        let identity_ms = start.elapsed().as_secs_f64() * 1000.0;
        if observed != original || !metadata.is_file() {
            return Err("native identity changed during observation".into());
        }
        rows.push(
            json!({"pin_ms":pin_ms,"protected_metadata_ms":metadata_ms,"identity_ms":identity_ms}),
        );
    }
    let report = json!({"platform":std::env::consts::OS,"samples":rows});
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/judge-diagnostics");
    std::fs::create_dir_all(&out)?;
    std::fs::write(
        out.join("native-metadata.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
