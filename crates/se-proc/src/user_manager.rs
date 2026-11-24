//! Typed `se-proc` adapter over `se-user-manager`.
use crate::support::input;
use crate::{ProcResult, ProcessId, RuntimeLaunchSpec, RuntimeLifetime, RuntimeUserScope};
use std::{fs::File, time::Instant};

pub(crate) fn admit(pin: &File, pid: ProcessId, spec: &RuntimeLaunchSpec) -> RuntimeLifetime {
    match se_user_manager::admit(pin, pid.0, spec.deadline) {
        Ok(scope) => RuntimeLifetime {
            user_scope: Some(RuntimeUserScope {
                unit: scope.unit,
                invocation: scope.invocation,
                cgroup: scope.cgroup,
            }),
            session_reason: None,
        },
        Err(reason) => RuntimeLifetime {
            user_scope: None,
            session_reason: Some(reason),
        },
    }
}

pub(crate) fn verify(
    scope: &RuntimeUserScope,
    pid: ProcessId,
    deadline: Instant,
) -> Result<(), String> {
    se_user_manager::verify(
        &scope.unit,
        &scope.invocation,
        &scope.cgroup,
        pid.0,
        deadline,
    )
}

/// Re-observe the admitted scope before a status reader reports its lifetime.
pub fn verify_runtime_user_scope(
    scope: &RuntimeUserScope,
    pid: ProcessId,
    deadline: Instant,
) -> ProcResult<()> {
    verify(scope, pid, deadline).map_err(|reason| input("runtime user scope", &reason))
}

pub(crate) fn pin_launcher(pid: i32) -> ProcResult<File> {
    se_user_manager::pin_launcher(pid).map_err(|reason| input("user scope bootstrap", &reason))
}

/// Observe only the recorded unit's kernel cgroup after exact host shutdown.
/// This never signals a unit or obtains authority over any process in it.
pub fn runtime_user_scope_empty(scope: &RuntimeUserScope) -> ProcResult<bool> {
    se_user_manager::scope_empty(&scope.unit, &scope.cgroup)
        .map_err(|reason| input("runtime user scope", &reason))
}
