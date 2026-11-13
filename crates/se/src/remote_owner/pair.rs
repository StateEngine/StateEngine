//! Native image staging has its own clock between two short Owner admissions.
use super::*;
use se_host::remote::{OwnerInput, ssh::ImageProgress};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(super) fn execute(
    context: &crate::bootstrap::Bootstrap,
    input: Input,
    progress: &mut dyn FnMut(ImageProgress) -> Result<()>,
) -> Result<se_host::OperationOutput> {
    let Input::Ready(input) = input;
    input.validate()?;
    let OwnerInput::Add {
        destination,
        alias,
        distribution,
    } = input
    else {
        return crate::route::remote_owner::execute(context, Input::Ready(input));
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| SeError::invalid("remote setup", "an available native I/O runtime"))?;
    runtime.block_on(async {
        let cancelled = Arc::new(AtomicBool::new(false));
        let interrupted = interruption()?;
        let pairing = async {
            request(
                context,
                OwnerInput::PrepareAdd {
                    destination: destination.clone(),
                    alias: alias.clone(),
                },
                cancelled.clone(),
            )
            .await?;
            se_host::remote::ssh::prepare_image(
                &destination,
                &distribution.to_local()?,
                &cancelled,
                progress,
            )
            .await?;
            // Resolve current native presence, endpoint and generation again:
            // image staging did not renew any IPC request or Owner admission.
            request(
                context,
                OwnerInput::Add {
                    destination,
                    alias,
                    distribution,
                },
                cancelled.clone(),
            )
            .await
        };
        tokio::pin!(pairing);
        tokio::pin!(interrupted);
        tokio::select! {
            biased;
            result = &mut pairing => result,
            signal = &mut interrupted => {
                cancelled.store(true, Ordering::Release);
                // The operation owns its native children; cancellation requests
                // their bounded cleanup rather than dropping their futures.
                let result = pairing.await;
                match (signal, result) {
                    (_, Ok(output)) => Ok(output),
                    (Ok(()), Err(error)) => Err(error),
                    (Err(signal), Err(error)) => Err(error.with_cause(signal)),
                }
            }
        }
    })
}

async fn request(
    context: &crate::bootstrap::Bootstrap,
    input: OwnerInput,
    cancelled: Arc<AtomicBool>,
) -> Result<se_host::OperationOutput> {
    let (home, no_color, json) = (context.home.clone(), context.no_color, context.json);
    tokio::task::spawn_blocking(move || {
        let context =
            crate::bootstrap::Bootstrap::resolve_remote_owner(Some(home), no_color, json)?;
        crate::route::remote_owner::execute_with_cancel(&context, Input::Ready(input), cancelled)
    })
    .await
    .map_err(|_| SeError::invalid("remote setup admission", "a joined native Owner request"))?
}

fn interruption() -> Result<impl std::future::Future<Output = Result<()>>> {
    #[cfg(unix)]
    let mut signals = {
        use tokio::signal::unix::{SignalKind, signal};
        [
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ]
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| {
            SeError::invalid(
                "remote setup cancellation",
                "available native termination signals",
            )
        })?
    };
    #[cfg(windows)]
    let (mut terminate, mut close) = (
        tokio::signal::windows::ctrl_break().map_err(|_| {
            SeError::invalid(
                "remote setup cancellation",
                "an available native break signal",
            )
        })?,
        tokio::signal::windows::ctrl_close().map_err(|_| {
            SeError::invalid(
                "remote setup cancellation",
                "an available native close signal",
            )
        })?,
    );
    Ok(async move {
        #[cfg(unix)]
        {
            let (first, second) = signals.split_at_mut(1);
            tokio::select! {
                result = tokio::signal::ctrl_c() => result.map_err(|_| SeError::invalid("remote setup cancellation", "an available interrupt signal")),
                _ = first[0].recv() => Ok(()),
                _ = second[0].recv() => Ok(()),
            }
        }
        #[cfg(windows)]
        {
            tokio::select! {
                result = tokio::signal::ctrl_c() => result.map_err(|_| SeError::invalid("remote setup cancellation", "an available interrupt signal")),
                _ = terminate.recv() => Ok(()),
                _ = close.recv() => Ok(()),
            }
        }
    })
}
