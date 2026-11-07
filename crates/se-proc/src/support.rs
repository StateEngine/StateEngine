use crate::*;
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn now() -> ProcResult<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .map_err(|e| {
            native(
                ProcErrorCode::IdentityUnreadable,
                "read observation wall clock",
                io::Error::other(e),
            )
        })
}
pub(crate) fn input(field: &str, reason: &str) -> ProcError {
    error(
        ProcErrorCode::InvalidInput,
        ProcErrorDetail::Input {
            field: field.into(),
            reason: reason.into(),
        },
    )
}
pub(crate) fn error(code: ProcErrorCode, detail: ProcErrorDetail) -> ProcError {
    ProcError {
        code,
        detail: Box::new(detail),
        native: None,
    }
}
pub(crate) fn native(code: ProcErrorCode, api: &str, cause: io::Error) -> ProcError {
    ProcError {
        code,
        detail: Box::new(ProcErrorDetail::Input {
            field: "native operation".into(),
            reason: api.into(),
        }),
        native: Some(NativeFailure {
            api: api.into(),
            code: cause.raw_os_error().map(i64::from),
            reason: cause.to_string(),
        }),
    }
}
pub(crate) fn capacity(resource: &str, limit: u64) -> ProcError {
    error(
        ProcErrorCode::ResourceLimit,
        ProcErrorDetail::Capacity {
            resource: resource.into(),
            limit,
        },
    )
}
pub(crate) fn state(lifecycle: &LifecycleId, from: LifecycleState, operation: &str) -> ProcError {
    error(
        ProcErrorCode::IllegalTransition,
        ProcErrorDetail::State {
            lifecycle: lifecycle.clone(),
            from,
            operation: operation.into(),
        },
    )
}
pub(crate) fn unsupported(reason: &str) -> ProcError {
    error(
        ProcErrorCode::UnsupportedPlatform,
        ProcErrorDetail::Input {
            field: "capability".into(),
            reason: reason.into(),
        },
    )
}
pub(crate) fn changed(expected: &ProcessIdentity, found: Option<&ProcessIdentity>) -> ProcError {
    error(
        ProcErrorCode::IdentityChanged,
        ProcErrorDetail::Identity {
            pid: expected.pid,
            expected_start: Some(expected.start.clone()),
            found_start: found.map(|p| p.start.clone()),
            expected: Some(Box::new(expected.clone())),
            found: found.map(|p| Box::new(p.clone())),
        },
    )
}

pub(crate) fn check_stop_deadline(deadline: std::time::Instant) -> ProcResult<()> {
    if std::time::Instant::now() >= deadline {
        return Err(error(
            ProcErrorCode::StopTokenExpired,
            ProcErrorDetail::Input {
                field: "stop deadline".into(),
                reason: "original authorization expired before native signal dispatch".into(),
            },
        ));
    }
    Ok(())
}
