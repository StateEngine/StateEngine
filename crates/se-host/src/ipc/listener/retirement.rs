//! Close the reactor object before observing native instance retirement. The
//! protected reservation stays held until the supplied reactor releases I/O.
use super::*;
use crate::runtime::BlockingPool;

/// Dropping a reactor object may only request cancellation on Windows.
#[derive(Debug)]
pub enum IpcClose {
    Closed,
    /// The error retains the protected reservation until it is released.
    PendingRelease {
        error: SeError,
    },
}
impl IpcListener {
    /// Request closure without driving the supplied reactor. PendingRelease
    /// retains the reservation when Windows still owns application instances;
    /// hosted shutdown instead joins closure on the supplied executor.
    pub fn close(self) -> Result<IpcClose> {
        let Self {
            native, listener, ..
        } = self;
        drop(listener);
        #[cfg(unix)]
        {
            native.close().map_err(native_error)?;
            Ok(IpcClose::Closed)
        }
        #[cfg(windows)]
        {
            let bound = se_proc::native_ipc::IpcIoBound {
                deadline: std::time::Instant::now() + HELLO_TIMEOUT,
                cancelled: Arc::new(AtomicBool::new(false)),
            };
            match native.current_instances(&bound) {
                Ok(1) => {
                    drop(native);
                    Ok(IpcClose::Closed)
                }
                Ok(_) => Ok(IpcClose::PendingRelease {
                    error: pending(
                        native,
                        SeError::invalid(
                            "IPC retirement",
                            "only the reserved native instance before release",
                        ),
                    ),
                }),
                Err(error) => Err(pending(native, native_error(error))),
            }
        }
    }
    /// Connection tasks, including the final stop reply, must already be joined.
    /// Awaiting finite native work keeps the supplied event reactor driven.
    pub(crate) async fn close_joined(
        self,
        blocking: &BlockingPool,
        deadline: &Deadline,
    ) -> Result<()> {
        #[cfg(unix)]
        {
            blocking
                .run_owned(deadline, move || self.close().map(|_| ()))
                .await
        }
        #[cfg(windows)]
        {
            let Self {
                native, listener, ..
            } = self;
            drop(listener);
            let permit = match blocking.admit_owned(deadline).await {
                Ok(permit) => permit,
                Err(error) => return Err(pending(native, error)),
            };
            let bound = deadline.native_bound();
            blocking
                .run_admitted_owned(permit, move || match native.wait_until_exclusive(&bound) {
                    Ok(()) => {
                        drop(native);
                        Ok(())
                    }
                    Err(error) => Err(pending(native, native_error(error))),
                })
                .await
        }
    }
}
#[cfg(windows)]
struct PendingRelease {
    _reservation: NativeEndpoint,
    error: SeError,
}
#[cfg(windows)]
impl std::fmt::Debug for PendingRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRelease")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
#[cfg(windows)]
impl std::fmt::Display for PendingRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IPC transport pending release: {}", self.error)
    }
}
#[cfg(windows)]
impl std::error::Error for PendingRelease {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
#[cfg(windows)]
fn pending(reservation: NativeEndpoint, error: SeError) -> SeError {
    se_core::scope::unreadable("IPC transport pending release", &error.to_string()).with_cause(
        PendingRelease {
            _reservation: reservation,
            error,
        },
    )
}
