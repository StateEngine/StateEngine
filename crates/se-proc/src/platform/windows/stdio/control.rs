use super::*;

impl NativeStdio {
    pub fn close(&self, scope: StdioCloseScope) -> ProcResult<u64> {
        let mut state = self.lock();
        if state.released || state.abandoned {
            return Err(transition("port has been released"));
        }
        let id = if let Some(id) = state.close {
            let operation = state
                .operations
                .get_mut(&id)
                .ok_or_else(|| transition("close control is missing"))?;
            if !operation.pending() {
                return Err(transition(
                    "take and release the terminal close before another close",
                ));
            }
            if scope == StdioCloseScope::All {
                operation.kind = Kind::Close(StdioCloseScope::All);
            }
            id
        } else {
            let id = state.next_id()?;
            state
                .operations
                .insert(id, Operation::new(Kind::Close(scope), Vec::new(), None));
            state.close = Some(id);
            id
        };
        let all = matches!(
            state.operations.get(&id).map(|op| op.kind),
            Some(Kind::Close(StdioCloseScope::All))
        );
        state.write_gated = true;
        state.all_gated |= all;
        drop(state);
        if all {
            self.cancel_all();
        }
        self.advance_close();
        self.nudge();
        Ok(id)
    }
    pub(super) fn abandon_partial(&self) {
        let _ = self.close(StdioCloseScope::All);
    }
    pub(super) fn advance_close(&self) {
        let mut state = self.lock();
        let close = state.close.and_then(|id| {
            state
                .operations
                .get(&id)
                .filter(|op| op.pending())
                .map(|op| (id, op.kind))
        });
        let scope = if state.abandoned {
            Some(StdioCloseScope::All)
        } else {
            close.and_then(|(_, kind)| {
                if let Kind::Close(scope) = kind {
                    Some(scope)
                } else {
                    None
                }
            })
        };
        let Some(scope) = scope else {
            return;
        };
        let pending = state.operations.values().any(|op| {
            op.pending()
                && match op.kind {
                    Kind::Write => true,
                    Kind::Read(_) | Kind::Connect(_) => scope == StdioCloseScope::All,
                    Kind::Close(_) => false,
                }
        });
        if pending {
            return;
        }
        let mut cause = None;
        let count = if scope == StdioCloseScope::All { 3 } else { 1 };
        for handle in state.handles.iter_mut().take(count) {
            if let Some(open) = handle {
                match open.close() {
                    Ok(()) => *handle = None,
                    Err(error) => {
                        cause = Some(error.native.unwrap_or_else(|| NativeFailure {
                            api: "close provider endpoint".into(),
                            code: None,
                            reason: "endpoint closure failed".into(),
                        }))
                    }
                }
            }
        }
        if let Some((id, _)) = close {
            if let Some(operation) = state.operations.get_mut(&id) {
                operation.status = Status::Done {
                    bytes: 0,
                    code: ERROR_SUCCESS,
                };
                operation.close_error = cause;
            }
            state.notices.insert(id);
        }
    }
    pub fn take(self: &Arc<Self>, id: u64, binding: u64) -> ProcResult<StdioCompletion> {
        let mut state = self.lock();
        let identity = state.identity.clone();
        let operation = state
            .operations
            .get_mut(&id)
            .ok_or_else(|| transition("unknown stream operation"))?;
        let Status::Done { bytes: count, code } = operation.status else {
            return if operation.pending() {
                Ok(StdioCompletion::Pending)
            } else {
                Err(transition("terminal result already taken"))
            };
        };
        operation.status = Status::Taken;
        let mut bytes = std::mem::take(&mut operation.bytes);
        operation.charge = None; // The allocation now belongs to the caller.
        let valid_count = count as usize <= bytes.len();
        let bounded = count.min(bytes.len() as u32);
        let outcome = if count as usize > bytes.len() {
            StdioOutcome::Failed(failure(
                "invalid provider completion byte count",
                ERROR_INVALID_DATA,
            ))
        } else if code == ERROR_OPERATION_ABORTED {
            StdioOutcome::Cancelled
        } else if code == ERROR_SUCCESS {
            StdioOutcome::Complete
        } else {
            StdioOutcome::Failed(failure(
                if matches!(operation.kind, Kind::Write) {
                    "WriteFile"
                } else {
                    "ReadFile"
                },
                code,
            ))
        };
        match operation.kind {
            Kind::Read(stream) => {
                bytes.truncate(bounded as usize);
                let eof = valid_count
                    && matches!(
                        code,
                        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_HANDLE_EOF
                    );
                Ok(StdioCompletion::Read {
                    stream,
                    bytes,
                    eof,
                    outcome: if eof { StdioOutcome::Complete } else { outcome },
                })
            }
            Kind::Write => Ok(StdioCompletion::Write {
                bytes,
                written: bounded,
                outcome,
            }),
            Kind::Close(scope) => Ok(StdioCompletion::Close {
                scope,
                result: if let Some(cause) = operation.close_error.take() {
                    Err(cause)
                } else {
                    Ok(StdioClosed {
                        native: Arc::downgrade(self),
                        identity,
                        binding,
                        scope,
                    })
                },
            }),
            Kind::Connect(_) => Err(transition(
                "internal pipe connection is not a public operation",
            )),
        }
    }
    pub fn release_operation(&self, id: u64) -> ProcResult<()> {
        let mut state = self.lock();
        if !state
            .operations
            .get(&id)
            .is_some_and(|op| matches!(op.status, Status::Taken))
        {
            return Err(transition(
                "take the actual terminal completion before release",
            ));
        }
        state.operations.remove(&id);
        state.notices.remove(&id);
        if state.close == Some(id) {
            state.close = None;
        }
        Ok(())
    }
    pub fn release(self: &Arc<Self>, witness: &StdioClosed, binding: u64) -> ProcResult<()> {
        let mut state = self.lock();
        if witness.scope != StdioCloseScope::All
            || witness.binding != binding
            || witness.identity != state.identity
            || !witness
                .native
                .upgrade()
                .is_some_and(|native| Arc::ptr_eq(&native, self))
        {
            return Err(transition("exact All-close witness required"));
        }
        if !state.operations.is_empty()
            || state.handles.iter().any(Option::is_some)
            || !state.all_gated
        {
            return Err(transition(
                "all endpoints must close and every operation must release before the port",
            ));
        }
        state.released = true;
        state.binding.disable();
        drop(state);
        self.queue()?.unregister();
        Ok(())
    }
}
