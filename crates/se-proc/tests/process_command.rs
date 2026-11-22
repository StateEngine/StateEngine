#![cfg(any(target_os = "linux", windows))]
use se_proc::{
    ProcErrorCode, ProcessId, ProcessRead, StartIdentity, read_process, read_process_command,
};
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
fn a_new_image_keeps_the_birth_but_a_changed_birth_or_elapsed_deadline_is_an_error() -> Check {
    let ProcessRead::Present(live) = read_process(
        MachineId::new("command-test")?,
        ProcessId(std::process::id()),
    )
    .map_err(|error| format!("{error:?}"))?
    else {
        return Err("current native process absent".into());
    };
    // The image is a recorded fact, not identity: an in-place update changes it.
    let mut replaced = live.identity.clone();
    replaced.image.push("another-image");
    let command = read_process_command(&replaced, Instant::now() + Duration::from_secs(2))
        .map_err(|error| format!("same birth with a new image refused: {error:?}"))?;
    assert_eq!(
        command,
        read_process_command(&live.identity, Instant::now() + Duration::from_secs(2))
            .map_err(|error| format!("{error:?}"))?,
        "the same process reads the same command"
    );
    let mut reborn = live.identity.clone();
    reborn.start = match reborn.start {
        StartIdentity::Linux { start_ticks } => StartIdentity::Linux {
            start_ticks: start_ticks + 1,
        },
        StartIdentity::Windows { creation_filetime } => StartIdentity::Windows {
            creation_filetime: creation_filetime + 1,
        },
        StartIdentity::MacOs {
            seconds,
            microseconds,
        } => StartIdentity::MacOs {
            seconds: seconds + 1,
            microseconds,
        },
    };
    let failure = read_process_command(&reborn, Instant::now() + Duration::from_secs(2))
        .err()
        .ok_or("a different native birth was accepted")?;
    assert_eq!(failure.code, ProcErrorCode::IdentityChanged);
    assert!(read_process_command(&live.identity, Instant::now()).is_err());
    Ok(())
}
