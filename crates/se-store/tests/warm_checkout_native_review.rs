//! External file changes judge native custody across warm, cold and recycle paths.
#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use std::{fs, io, path::Path, process::Command};
#[path = "support/store_fixture.rs"]
mod fixture;
#[path = "support/native_read_identity.rs"]
mod native;
use fixture::*;

fn ready() -> Result<(Fixture, ReadPhasePool), Box<dyn std::error::Error>> {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let (writer, lease) = f.direct()?;
    writer.close()?;
    drop(lease);
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let pool = reader.phase_pool(native::open_identity)?;
    Ok((f, pool))
}

fn mutate(
    action: &str,
    path: &Path,
    saved: &Path,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../se/tests/review_warm_checkout/mutate.py");
    let output = Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg("-B")
        .arg(script)
        .arg(action)
        .arg(path)
        .arg(saved)
        .output()?;
    assert!(
        output.status.success(),
        "external mutation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert!(result["state"] == "completed" || result["state"] == "native-denied");
    println!("external mutation {action}: {result}");
    Ok(result)
}

fn refused(pool: &ReadPhasePool, expected: StoreErrorCode) -> Check {
    for _ in 0..3 {
        let error = pool
            .read_phase()
            .err()
            .ok_or("changed native custody was admitted")?;
        assert_eq!(error.code, expected, "{error}");
    }
    Ok(())
}

fn closed(pool: &ReadPhasePool, path: &Path) -> Check {
    pool.read_phase()?.close()?;
    pool.close()?;
    assert_eq!(
        pool.read_phase()
            .err()
            .ok_or("sealed pool admitted work")?
            .code,
        StoreErrorCode::NotReady
    );
    let moved = path.with_file_name("closed.db");
    fs::rename(path, &moved)?;
    fs::rename(&moved, path)?;
    println!("PASS closed native database renamed after all pooled handles retired");
    Ok(())
}

#[test]
fn warm_and_cold_checkout_refuse_external_file_and_root_security_drift() -> Check {
    for warm in [false, true] {
        for root in [false, true] {
            let (f, pool) = ready()?;
            let path = f.options.state_directory.join("state.db");
            if warm {
                pool.read_phase()?.close()?;
            }
            let target = if root {
                &f.options.state_directory
            } else {
                &path
            };
            let saved = f.home.join("original-security");
            mutate("loosen", target, &saved)?;
            let result = refused(&pool, StoreErrorCode::LocationUnsafe);
            let restoration = mutate("restore", target, &saved);
            restoration?;
            result?;
            closed(&pool, &path)?;
            println!("PASS fresh native security warm={warm} root={root}");
        }
    }
    Ok(())
}

#[test]
fn warm_and_cold_checkout_refuse_external_hard_links() -> Check {
    for warm in [false, true] {
        let (f, pool) = ready()?;
        let path = f.options.state_directory.join("state.db");
        if warm {
            pool.read_phase()?.close()?;
        }
        let link = f.options.state_directory.join("outside-link.db");
        mutate("link", &path, &link)?;
        let result = refused(&pool, StoreErrorCode::LocationUnsafe);
        let restoration = mutate("unlink", &path, &link);
        restoration?;
        result?;
        closed(&pool, &path)?;
        println!("PASS fresh native link count warm={warm}");
    }
    Ok(())
}

#[test]
fn warm_and_cold_checkout_preserve_the_original_native_file_identity() -> Check {
    for warm in [false, true] {
        let (f, pool) = ready()?;
        let path = f.options.state_directory.join("state.db");
        let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
        let mut stage = files.create_staging(&f.options.state_directory)?;
        io::copy(&mut fs::File::open(&path)?, &mut stage.file)?;
        drop(stage.file);
        files.publish_no_replace(&stage.path, &path.with_file_name("replacement.db"))?;
        if warm {
            pool.read_phase()?.close()?;
        }
        let saved = path.with_file_name("original.db");
        let observation = mutate("swap", &path, &saved)?;
        if observation["state"] == "native-denied" {
            assert!(
                cfg!(windows) && warm,
                "cold/native identity pin unexpectedly denied replacement"
            );
            println!("PASS warm replacement was denied by retained native SQL custody");
        } else {
            let a = se_proc::NativeSourcePin::open(&path)?.ok_or("replacement missing")?;
            let b = se_proc::NativeSourcePin::open(&saved)?.ok_or("original missing")?;
            assert_ne!(a.identity(), b.identity());
            drop((a, b));
            let result = refused(&pool, StoreErrorCode::SourceChanged);
            let restoration = mutate("unswap", &path, &saved);
            restoration?;
            result?;
            println!("PASS replaced native file refused warm={warm}");
        }
        closed(&pool, &path)?;
    }
    Ok(())
}

#[test]
fn external_security_drift_after_snapshot_is_refused_at_recycle() -> Check {
    let (f, pool) = ready()?;
    let path = f.options.state_directory.join("state.db");
    pool.read_phase()?.close()?;
    let phase = pool.read_phase()?;
    let saved = f.home.join("original-security");
    mutate("loosen", &path, &saved)?;
    let result = phase.close();
    let restoration = mutate("restore", &path, &saved);
    restoration?;
    assert_eq!(
        result
            .err()
            .ok_or("recycle accepted changed security")?
            .code,
        StoreErrorCode::LocationUnsafe
    );
    closed(&pool, &path)?;
    println!("PASS external post-snapshot security drift refused at recycle");
    Ok(())
}
