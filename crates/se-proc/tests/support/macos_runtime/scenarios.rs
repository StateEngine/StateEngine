use super::*;
use std::{
    fs::File,
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
};
struct Host {
    child: Child,
    pin: native::Pin,
    log: PathBuf,
}
impl Drop for Host {
    fn drop(&mut self) {
        let result = (|| -> Check {
            if self.child.try_wait()?.is_none() {
                native::cleanup(&self.pin)?;
                wait(|| Ok(self.child.try_wait()?.is_some()))?;
            }
            Ok(())
        })();
        if let Err(e) = &result {
            eprintln!("retained exact fixture host: {e}");
        }
        if result.is_err() || std::thread::panicking() {
            self.report();
        }
    }
}
impl Host {
    fn report(&self) {
        match fs::read_to_string(&self.log) {
            Ok(log) => eprintln!("native host transcript {}:\n{log}", self.log.display()),
            Err(e) => eprintln!(
                "native host transcript unreadable {}: {e}",
                self.log.display()
            ),
        }
    }
}
fn spawn_host(home: &Home, mode: &str, library: Option<&Path>) -> Check<Host> {
    let log = File::create(home.0.join("host.log"))?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "fixture::scenarios::detached_host",
            "--ignored",
            "--nocapture",
        ])
        .env("SE_MACOS_JUDGE_ROOT", &home.0)
        .env("SE_MACOS_CASE", mode)
        .env("SE_MACOS_AMBIENT", "host-only-value")
        .env("SE_MACOS_HELPER", lifecycle::helper()?)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    if let Some(library) = library {
        command.env("DYLD_INSERT_LIBRARIES", library);
    }
    let child = command.spawn()?;
    let pin = native::pin(ProcessId(child.id()))?;
    let host = Host {
        child,
        pin,
        log: home.0.join("host.log"),
    };
    json(home.0.join("pin-host.json"), &host.pin)?;
    Ok(host)
}
fn joined(host: &mut Host) -> Check {
    let mut status = None;
    if let Err(e) = wait(|| {
        status = host.child.try_wait()?;
        Ok(status.is_some())
    }) {
        host.report();
        return Err(e);
    }
    if !status.ok_or("host status absent")?.success() {
        host.report();
        return Err("native fixture host failed; inspect retained host.log".into());
    }
    Ok(())
}
fn closed(root: &Path, who: &str) -> Check {
    let pin = native::read_pin(root, who)?;
    wait(|| Ok(!native::live(&pin)?))
}
pub fn host_case(home: &Home, mode: &str, library: Option<&Path>) -> Check {
    let mut child = spawn_host(home, mode, library)?;
    if library.is_some() {
        wait(|| Ok(home.0.join("fault-result.json").exists()))?;
        let pin = native::read_pin(&home.0, "provider")?;
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(home.0.join("fault-result.json"))?)?;
        assert_eq!(
            report["dispatched"], false,
            "native fault authorized a signal"
        );
        assert_eq!(
            report["complete"], false,
            "native fault manufactured exit proof"
        );
        assert!(
            native::live(&pin)?,
            "fault path signalled the original native instance"
        );
        fs::write(home.0.join("continue"), b"continue")?;
    }
    joined(&mut child)?;
    closed(&home.0, "provider")?;
    if home.0.join("pin-child.json").exists() {
        closed(&home.0, "child")?;
    }
    Ok(())
}
pub fn authorization_eof(home: &Home) -> Check {
    let mut child = spawn_host(home, "eof", None)?;
    joined(&mut child)?;
    closed(&home.0, "helper")?;
    assert!(
        !home.0.join("executions").exists(),
        "authorization EOF executed the provider"
    );
    Ok(())
}
pub fn strict_refusals(home: &Home) -> Check {
    fs::write(home.0.join("sentinel"), b"100")?;
    let runtime = lifecycle::open(&home.0)?;
    let capability = runtime.capabilities().map_err(error)?;
    assert!(matches!(
        capability.kernel_scope,
        Capability::Unavailable { .. }
    ));
    assert!(matches!(capability.window, Capability::Unavailable { .. }));
    for (containment, mode) in [
        (ContainmentRequirement::KernelScope, LaunchMode::Headless),
        (ContainmentRequirement::TrackedTree, LaunchMode::Window),
    ] {
        assert!(lifecycle::prepare(&runtime, &home.0, containment, mode).is_err());
    }
    assert!(!home.0.join("executions").exists());
    assert!(!home.0.join("pin-helper.json").exists());
    Ok(())
}
fn observe_child(
    runtime: &NativeProcessRuntime,
    process: &OwnedProcess,
    root: &Path,
    escape: bool,
) -> Check {
    wait(|| Ok(root.join("pin-child.json").exists()))?;
    let child = native::read_pin(root, "child")?;
    // First account for the child while the original root anchors its group.
    wait(|| {
        Ok(runtime
            .observe(process)
            .map_err(error)?
            .scope
            .remaining
            .known_live
            .contains(&child.identity))
    })?;
    if escape {
        fs::write(root.join("escape"), b"escape")?;
        wait(|| Ok(root.join("escaped").exists()))?;
        let observed = runtime.observe(process).map_err(error)?;
        assert!(
            observed
                .scope
                .remaining
                .known_live
                .contains(&child.identity)
        );
        assert!(matches!(
            observed.scope.remaining.extent,
            EnumerationExtent::Partial { .. }
        ));
        assert!(observed.scope.exit_basis.is_none());
        assert!(native::live(&child)?);
    }
    Ok(())
}
pub fn cold(home: &Home, mode: &str) -> Check {
    let mut child = spawn_host(home, mode, None)?;
    joined(&mut child)?; // the first runtime process is now gone, not merely dropped.
    let record: ProcessRecord = serde_json::from_slice(&fs::read(home.0.join("record.json"))?)?;
    let original_execs = fs::read(home.0.join("executions"))?;
    let runtime = lifecycle::runtime()?;
    let generation = GenerationId::new(2)?;
    let plan = runtime
        .plan_recovery(RecoverySource::Record(Box::new(record.clone())))
        .map_err(error)?;
    let recovered = runtime.recover(plan, generation).map_err(error)?;
    if mode == "cold-root-exited" {
        assert!(
            matches!(recovered, RecoveryOutcome::Unproved { .. }),
            "cold reconciliation forgot a known live escaped child"
        );
        assert!(native::live(&native::read_pin(&home.0, "child")?)?);
        native::cleanup(&native::read_pin(&home.0, "child")?)?;
    } else {
        let RecoveryOutcome::Recovered {
            process,
            record: adopted,
        } = recovered
        else {
            return Err("live original birth was not adopted".into());
        };
        assert_eq!(adopted.root, record.root);
        assert_eq!(adopted.generation, generation);
        if mode == "cold-escaped" {
            let child = native::read_pin(&home.0, "child")?;
            let observed = runtime.observe(&process).map_err(error)?;
            assert!(
                observed
                    .scope
                    .remaining
                    .known_live
                    .contains(&child.identity)
            );
            let result = escaped_stop(&runtime, &process, generation, &home.0)?;
            assert!(
                !matches!(result, StopObservation::Complete(_)),
                "cold stop erased an observed escape"
            );
            assert!(native::live(&child)?);
            native::cleanup(&child)?;
        } else {
            lifecycle::close(&runtime, &process, generation)?;
        }
        closed(&home.0, "provider")?;
    }
    assert_eq!(
        fs::read(home.0.join("executions"))?,
        original_execs,
        "cold recovery created a new provider birth"
    );
    assert!(runtime.arena_snapshot().map_err(error)?.entries.len() <= 1);
    // Records predating tracked history never grant a cold empty-scope witness.
    let mut legacy = record;
    let legacy_runtime = lifecycle::runtime()?;
    let mut value = serde_json::to_value(&legacy)?;
    value
        .as_object_mut()
        .ok_or("record must be an object")?
        .remove("tracked_obligations");
    legacy = serde_json::from_value(value)?;
    let plan = legacy_runtime
        .plan_recovery(RecoverySource::Record(Box::new(legacy)))
        .map_err(error)?;
    assert!(matches!(
        legacy_runtime.recover(plan, generation).map_err(error)?,
        RecoveryOutcome::Unproved { .. }
    ));
    Ok(())
}
#[test]
#[ignore = "private host: parent observes its native effects and joins it"]
fn detached_host() -> Check {
    let root = root()?;
    let mode = std::env::var("SE_MACOS_CASE")?;
    let sentinel = lifecycle::sentinel(&root)?;
    fs::write(root.join("sentinel"), sentinel.as_raw_fd().to_string())?;
    let runtime = lifecycle::open(&root)?;
    if mode == "eof" {
        let (_ticket, _process, _checkpoint) = lifecycle::begin(&runtime, &root)?;
        // No Rust destructor cancels the child; only native channel EOF authorizes refusal.
        std::process::exit(0);
    }
    let descendants = matches!(
        mode.as_str(),
        "descendant" | "escape" | "cold-escaped" | "cold-root-exited"
    );
    if descendants {
        fs::write(root.join("make-child"), b"child")?;
    }
    let launched = lifecycle::launch(&runtime, &root)?;
    let process = &launched.process;
    let generation = launched.record.generation;
    let pin = native::read_pin(&root, "provider")?;
    if descendants {
        observe_child(&runtime, process, &root, mode != "descendant")?;
    }
    if mode.starts_with("cold") {
        let observed = runtime.observe(process).map_err(error)?;
        // Describe, observations and snapshots must all retain already-observed history.
        let described = runtime.describe(process).map_err(error)?;
        let snap = runtime.arena_snapshot().map_err(error)?;
        assert_eq!(described.root, observed.record.root);
        assert_eq!(
            serde_json::to_value(&described)?["tracked_obligations"],
            serde_json::to_value(&observed.record)?["tracked_obligations"]
        );
        let saved = snap
            .entries
            .first()
            .and_then(|e| e.record.as_ref())
            .ok_or("snapshot lost record")?;
        assert_eq!(saved.root, described.root);
        assert_eq!(
            serde_json::to_value(saved)?["tracked_obligations"],
            serde_json::to_value(&described)?["tracked_obligations"]
        );
        json(root.join("record.json"), &described)?;
        if mode == "cold-root-exited" {
            fs::write(root.join("exit-root"), b"exit")?;
            wait(|| Ok(!native::live(&pin)?))?;
        }
        std::process::exit(0);
    }
    if matches!(
        mode.as_str(),
        "replacement" | "denied" | "short" | "zero" | "enumeration"
    ) {
        fs::write(root.join("fault-pid"), pin.identity.pid.0.to_string())?;
        fs::write(root.join("fault"), mode.as_bytes())?;
        let stop = runtime
            .prepare_stop(process, generation, until())
            .map_err(error)?;
        let attempt = runtime.request_stop(stop);
        let dispatched = matches!(&attempt, Ok(value) if value.dispatch.is_ok());
        let complete = matches!(
            runtime.witness_exit(process),
            Ok(StopObservation::Complete(_))
        );
        json(
            root.join("fault-result.json"),
            &serde_json::json!({"dispatched":dispatched,"complete":complete}),
        )?;
        wait(|| Ok(root.join("continue").exists()))?;
        fs::remove_file(root.join("fault"))?;
    }
    if mode == "launch" {
        let wrong = GenerationId::new(2)?;
        assert!(runtime.prepare_stop(process, wrong, until()).is_err());
        assert!(
            runtime
                .prepare_stop(process, generation, Instant::now())
                .is_err()
        );
        assert!(native::live(&pin)?);
        let expiry = Instant::now() + Duration::from_millis(50);
        let expiring = runtime
            .prepare_stop(process, generation, expiry)
            .map_err(error)?;
        std::thread::sleep(
            expiry.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
        );
        assert!(
            runtime
                .request_stop(expiring)
                .map_err(error)?
                .dispatch
                .is_err()
        );
        assert!(
            native::live(&pin)?,
            "expired token signalled the original birth"
        );
        let superseded = runtime
            .prepare_stop(process, generation, until())
            .map_err(error)?;
        let _current = runtime
            .prepare_stop(process, generation, until())
            .map_err(error)?;
        assert!(
            runtime
                .request_stop(superseded)
                .map_err(error)?
                .dispatch
                .is_err()
        );
        assert!(
            native::live(&pin)?,
            "superseded token signalled the original birth"
        );
        let proof: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("provider.json"))?)?;
        assert_eq!(proof["input"], "selected provider input");
        assert_eq!(proof["inherited_descriptor"], false);
        assert_eq!(proof["ambient_inherited"], false);
        assert_eq!(
            proof["cwd"],
            root.to_str().ok_or("fixture path is not UTF-8")?
        );
        wait(|| {
            Ok(
                fs::read_to_string(root.join("output"))?.contains("SELECTED-PROVIDER-OUTPUT")
                    && fs::read_to_string(root.join("error"))?.contains("SELECTED-PROVIDER-ERROR"),
            )
        })?;
    }
    if mode == "escape" {
        let result = escaped_stop(&runtime, process, generation, &root)?;
        assert!(
            !matches!(result, StopObservation::Complete(_)),
            "ordinary stop forgot the escaped obligation"
        );
        let child = native::read_pin(&root, "child")?;
        assert!(native::live(&child)?);
        native::cleanup(&child)?;
    } else {
        lifecycle::close(&runtime, process, generation)?;
    }
    Ok(())
}
pub fn fault_library(home: &Home) -> Check<PathBuf> {
    let source = home.0.join("native-fault.c");
    let library = home.0.join("native-fault.dylib");
    fs::write(&source, include_str!("fault.c"))?;
    let output = Command::new("/usr/bin/cc")
        .args(["-dynamiclib", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(&library)
        .arg("-lproc")
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "native boundary fixture compile: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(library)
}

fn escaped_stop(
    runtime: &NativeProcessRuntime,
    process: &OwnedProcess,
    generation: GenerationId,
    root: &Path,
) -> Check<StopObservation> {
    let prepared = runtime
        .prepare_stop(process, generation, until())
        .map_err(error)?;
    runtime
        .request_stop(prepared)
        .map_err(error)?
        .dispatch
        .map_err(error)?;
    closed(root, "provider")?;
    Ok(runtime.witness_exit(process).map_err(error)?)
}
