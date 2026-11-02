//! Public native error contracts: concrete facts and trait-object causes survive refactoring.
use se_proc::native_ipc::{IpcNativeError, IpcNativeErrorCode};
use se_proc::{
    CheckpointError, FileOwnerError, NativeEntropyError, OwnerProbeError, StateFileError,
    StateFileErrorCode,
};
use std::{error::Error, io, path::PathBuf};

fn same_source(error: &dyn Error, original: &io::Error) {
    let cause = error.source().and_then(|e| e.downcast_ref::<io::Error>());
    assert!(
        cause.is_some_and(|cause| std::ptr::eq(cause, original)),
        "native source was lost or replaced"
    );
    assert_eq!(
        cause.and_then(io::Error::raw_os_error),
        original.raw_os_error()
    );
}

#[test]
fn owner_errors_retain_operation_and_original_native_cause() {
    let creation = FileOwnerError {
        operation: "initialize owner",
        source: io::Error::from_raw_os_error(5),
    };
    assert_eq!(
        creation.to_string(),
        format!("initialize owner: {}", creation.source)
    );
    same_source(&creation, &creation.source);
    let probe = OwnerProbeError {
        operation: "observe owner",
        source: io::Error::new(io::ErrorKind::PermissionDenied, "owner inaccessible"),
    };
    assert_eq!(probe.to_string(), "observe owner: owner inaccessible");
    same_source(&probe, &probe.source);
}

#[test]
fn file_refusals_remain_distinct_from_native_read_failures() {
    for code in [
        StateFileErrorCode::AlreadyExists,
        StateFileErrorCode::Unreadable,
        StateFileErrorCode::LocationUnsafe,
        StateFileErrorCode::SourceChanged,
        StateFileErrorCode::Unsupported,
    ] {
        let mut error = StateFileError {
            code,
            operation: "read protected file",
            path: PathBuf::from("private/state.db"),
            source: None,
        };
        let prefix = format!("read protected file at {}: {code:?}", error.path.display());
        assert_eq!(error.to_string(), prefix);
        assert!(error.source().is_none(), "refusal invented a native cause");
        error.source = Some(io::Error::new(
            io::ErrorKind::NotFound,
            "native file absent",
        ));
        assert_eq!(error.to_string(), format!("{prefix}: native file absent"));
        if let Some(source) = &error.source {
            same_source(&error, source);
        }
        assert_eq!(error.code, code);
    }
}

#[test]
fn ipc_codes_and_original_native_causes_are_preserved() {
    for code in [
        IpcNativeErrorCode::AlreadyExists,
        IpcNativeErrorCode::Unreadable,
        IpcNativeErrorCode::UnsafeEndpoint,
        IpcNativeErrorCode::PeerChanged,
        IpcNativeErrorCode::TimedOut,
        IpcNativeErrorCode::Cancelled,
        IpcNativeErrorCode::Unsupported,
    ] {
        let error = IpcNativeError {
            code,
            operation: "connect local endpoint",
            source: io::Error::other("native detail"),
        };
        assert_eq!(
            error.to_string(),
            format!("connect local endpoint: {code:?}: native detail")
        );
        assert_eq!(error.code, code);
        same_source(&error, &error.source);
    }
}

#[test]
fn reason_and_signed_entropy_status_remain_sourceless() {
    let error = CheckpointError {
        reason: "unresolved process observation".into(),
    };
    assert_eq!(error.to_string(), "unresolved process observation");
    assert!(error.source().is_none());
    for native_code in [None, Some(-1073741823), Some(5)] {
        let error = NativeEntropyError {
            operation: "fill entropy",
            native_code,
        };
        assert_eq!(
            error.to_string(),
            format!("fill entropy failed (native code {native_code:?}); no secret allocated")
        );
        assert_eq!(error.native_code, native_code);
        assert!(
            error.source().is_none(),
            "native status was recast as an invented I/O cause"
        );
    }
}

#[cfg(windows)]
#[test]
fn path_commit_phase_and_uninstall_cleanup_debt_survive_error_formatting() {
    use se_proc::{PathUpdateError, PathUpdatePhase, UninstallNativeError};
    for phase in [
        PathUpdatePhase::NotCommitted,
        PathUpdatePhase::Unknown,
        PathUpdatePhase::Committed,
    ] {
        let error = PathUpdateError {
            operation: "update user PATH",
            phase,
            source: io::Error::other("registry failure"),
        };
        assert_eq!(
            error.to_string(),
            format!("update user PATH ({phase:?}): registry failure")
        );
        assert_eq!(error.phase, phase);
        same_source(&error, &error.source);
    }
    let pending_paths = vec![
        PathBuf::from("private/helper.exe"),
        PathBuf::from("private/handoff"),
    ];
    let error = UninstallNativeError {
        operation: "remove helper",
        source: io::Error::from_raw_os_error(5),
        pending_paths: pending_paths.clone(),
    };
    assert_eq!(
        error.to_string(),
        format!("remove helper: {}", error.source)
    );
    same_source(&error, &error.source);
    assert_eq!(error.pending_paths, pending_paths);
}
