//! Independent execution-boundary controls. Each case uses a fresh private image.
use se_host::client;
use std::{fs, path::PathBuf, process::Command, time::Duration};
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ORIGINAL: &[u8] = b"QUALIFIED_IMAGE_ORIGINAL";
const REPLACED: &[u8] = b"QUALIFIED_IMAGE_REPLACED";

type Prepared = se_proc::NativeExecutableInvocation;
fn qualify(path: &std::path::Path) -> Check<Prepared> {
    Ok(se_proc::NativeExecutablePin::open(path)?
        .ok_or("qualified file absent")?
        .prepare()?)
}
async fn invoke(prepared: Prepared, bound: &crate::client::lease::Deadline) -> Check<Vec<u8>> {
    Ok(se_host::secode_process::probe::command(prepared, &[], bound).await?)
}
fn creation_command(prepared: &Prepared) -> Check<(Command, se_proc::NativeExecutableCreation)> {
    Ok(prepared.command()?)
}

struct Fixture {
    root: PathBuf,
    image: PathBuf,
    replacement: PathBuf,
}
impl Fixture {
    fn new() -> Check<Self> {
        let mut nonce = [0; 16];
        se_proc::fill_entropy(&mut nonce)?;
        let root =
            std::env::temp_dir().join(format!("execution-review-{}", se_types::hex_lower(&nonce)));
        let mut creation = se_proc::NativeDirectoryCreation::begin();
        drop(creation.create(&root)?);
        let root = se_proc::canonicalize_path(&root)?;
        let image = root.join(if cfg!(windows) {
            "helper.exe"
        } else {
            "helper"
        });
        let replacement = root.join(if cfg!(windows) {
            "replacement.exe"
        } else {
            "replacement"
        });
        let helper_source = root.join("helper.rs");
        fs::write(
            &helper_source,
            include_str!("support/execution_image_fixture.rs"),
        )?;
        let compiled = Command::new("rustc")
            .arg("--edition=2024")
            .arg("--crate-name=execution_fixture")
            .arg(&helper_source)
            .arg("-o")
            .arg(&image)
            .output()?;
        assert!(
            compiled.status.success(),
            "native helper compilation failed: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let mut bytes = fs::read(&image)?;
        assert_eq!(ORIGINAL.len(), REPLACED.len());
        let mut edits = 0;
        for offset in 0..=bytes.len().saturating_sub(ORIGINAL.len()) {
            if &bytes[offset..offset + ORIGINAL.len()] == ORIGINAL {
                bytes[offset..offset + ORIGINAL.len()].copy_from_slice(REPLACED);
                edits += 1;
            }
        }
        assert!(edits > 0, "compiled helper has no marker");
        fs::write(&replacement, bytes)?;
        std::fs::File::options()
            .write(true)
            .open(&replacement)?
            .set_times(std::fs::FileTimes::new().set_modified(fs::metadata(&image)?.modified()?))?;
        fs::set_permissions(&replacement, fs::metadata(&image)?.permissions())?;
        assert_eq!(
            fs::metadata(&replacement)?.len(),
            fs::metadata(&image)?.len()
        );
        Ok(Self {
            root,
            image,
            replacement,
        })
    }
    fn original(&self, bytes: &[u8]) {
        assert!(
            bytes.windows(ORIGINAL.len()).any(|v| v == ORIGINAL),
            "qualified helper did not execute: {}",
            String::from_utf8_lossy(bytes)
        );
        assert!(
            !bytes.windows(REPLACED.len()).any(|v| v == REPLACED),
            "replacement executed"
        );
        assert!(
            String::from_utf8_lossy(bytes).contains(&self.image.to_string_lossy().to_string()),
            "original argv zero was lost"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root) {
            eprintln!("owned fixture directory retained: {error}");
        }
    }
}
fn runtime() -> Check<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
fn deadline() -> Check<crate::client::lease::Deadline> {
    Ok(crate::client::lease::Deadline::from_options(
        &crate::client::ClientOptions {
            expected_generation: None,
            timeout: Duration::from_secs(10),
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    )?)
}

#[test]
fn qualified_native_command_preserves_argv_zero() -> Check {
    let f = Fixture::new()?;
    let prepared = qualify(&f.image)?;
    let bytes = runtime()?.block_on(invoke(prepared, &deadline()?))?;
    f.original(&bytes);
    Ok(())
}

#[test]
fn replacement_after_qualification_never_executes() -> Check {
    let f = Fixture::new()?;
    let prepared = qualify(&f.image)?;
    fs::rename(&f.replacement, &f.image)?;
    let result = runtime()?.block_on(invoke(prepared, &deadline()?));
    // A refusal before execution is safe; it is not a successful helper result.
    if let Ok(bytes) = result {
        f.original(&bytes);
    }
    Ok(())
}

#[test]
fn creation_keeps_the_qualified_image_across_pathname_replacement() -> Check {
    let f = Fixture::new()?;
    let prepared = qualify(&f.image)?;
    let (mut command, guard) = creation_command(&prepared)?;
    let replaced = fs::rename(&f.replacement, &f.image);
    if cfg!(windows) {
        assert!(
            replaced.is_err(),
            "Windows image replacement was not excluded during creation"
        );
    } else {
        replaced?;
    }
    let output = command.output()?;
    assert!(
        output.status.success(),
        "qualified child failed: {:?}",
        output.status
    );
    f.original(&output.stdout);
    drop(guard);
    Ok(())
}

#[test]
fn provider_update_is_allowed_after_creation_finishes() -> Check {
    let f = Fixture::new()?;
    let prepared = qualify(&f.image)?;
    let bytes = runtime()?.block_on(invoke(prepared, &deadline()?))?;
    f.original(&bytes);
    fs::rename(&f.replacement, &f.image)?;
    let output = Command::new(&f.image).output()?;
    assert!(output.status.success());
    assert!(
        output.stdout.windows(REPLACED.len()).any(|v| v == REPLACED),
        "ordinary package update was not executed afterward"
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn writable_image_handle_prevents_qualified_execution_on_windows() -> Check {
    let f = Fixture::new()?;
    let prepared = qualify(&f.image)?;
    let writer = std::fs::File::options().write(true).open(&f.image)?;
    assert!(
        runtime()?.block_on(invoke(prepared, &deadline()?)).is_err(),
        "a writable image was accepted during process creation"
    );
    drop(writer);
    Ok(())
}
