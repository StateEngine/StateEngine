#![cfg(any(target_os = "linux", windows))]
use se_proc::{ProcErrorCode, ProcessId, ProcessRead, read_process, read_process_command};
use se_types::MachineId;
use std::time::{Duration, Instant};

type Check = Result<(), Box<dyn std::error::Error>>;

#[cfg(target_os = "linux")]
#[test]
fn a_complete_native_ancestry_read_can_report_zero_descendants() -> Check {
    let ProcessRead::Present(live) = read_process(
        MachineId::new("command-test")?,
        ProcessId(std::process::id()),
    )
    .map_err(|error| format!("{error:?}"))?
    else {
        return Err("current native process absent".into());
    };
    let descendants =
        se_proc::read_process_descendants(&live.identity, Instant::now() + Duration::from_secs(5))
            .map_err(|error| format!("{error:?}"))?;
    assert!(
        descendants.is_empty(),
        "this owned test process started no children"
    );
    Ok(())
}

#[test]
fn command_is_read_from_the_exact_live_native_instance() -> Check {
    let ProcessRead::Present(live) = read_process(
        MachineId::new("command-test")?,
        ProcessId(std::process::id()),
    )
    .map_err(|error| format!("{error:?}"))?
    else {
        return Err("current native process absent".into());
    };
    let command = read_process_command(&live.identity, Instant::now() + Duration::from_secs(2))
        .map_err(|error| format!("{error:?}"))?
        .ok_or("current process exited")?;
    assert!(!command.is_empty());
    #[cfg(windows)]
    assert!(command.starts_with("executable only: "));
    #[cfg(target_os = "linux")]
    assert!(command.contains("process_command"), "{command}");
    Ok(())
}

#[test]
fn changed_image_and_elapsed_deadline_are_errors_not_no_jobs() -> Check {
    let ProcessRead::Present(live) = read_process(
        MachineId::new("command-test")?,
        ProcessId(std::process::id()),
    )
    .map_err(|error| format!("{error:?}"))?
    else {
        return Err("current native process absent".into());
    };
    let mut wrong = live.identity.clone();
    wrong.image.push("another-image");
    let failure = read_process_command(&wrong, Instant::now() + Duration::from_secs(2))
        .err()
        .ok_or("wrong native image accepted")?;
    assert_eq!(failure.code, ProcErrorCode::IdentityChanged);
    assert!(read_process_command(&live.identity, Instant::now()).is_err());
    Ok(())
}
