//! Real prepared Windows scopes and IOCP pipes; no provider process or H05 is
//! claimed. The child endpoints stay owned by the prepared launch until stop.
use super::*;
use se_proc::*;
use std::{future::Future, task::Poll, time::Instant as NativeInstant};
#[path = "../../../tests/support/prepared_windows_scope.rs"]
mod fixture;
use fixture::{Fixture, proc_error};
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn context() -> Check<CallContext> {
    Ok(CallContext {
        generation: se_types::Generation::new(1)?,
        timeout: Duration::from_secs(5),
        cancellation: Arc::new(crate::CancellationState { _private: () }),
    })
}
/// Poll once without replacing the real operation or its native completion.
async fn poll_once<F: Future + ?Sized>(future: std::pin::Pin<&mut F>) -> Option<F::Output> {
    let mut future = future;
    std::future::poll_fn(|cx| {
        Poll::Ready(match future.as_mut().poll(cx) {
            Poll::Pending => None,
            Poll::Ready(value) => Some(value),
        })
    })
    .await
}
/// Cleanup follows the native inventory only after recording the wrapper's
/// result. It cannot turn an unsuccessful consumer close into passing evidence.
async fn repair_for_cleanup(
    f: &Fixture,
    platform: &WindowsProviderIo<NativeProcessRuntime>,
    transport: &ProviderTransport,
) -> Check {
    let Some(state) = f.runtime.stdio_state(&f.owner).map_err(proc_error)? else {
        return Ok(());
    };
    let _ = f.runtime.begin_close(&state.port, StdioCloseScope::All);
    let state = f
        .runtime
        .stdio_state(&f.owner)
        .map_err(proc_error)?
        .ok_or("cleanup stream inventory disappeared")?;
    let mut witness = None;
    for ticket in state.operations {
        let _ = f.runtime.cancel(&ticket);
        let until = NativeInstant::now() + Duration::from_secs(5);
        loop {
            match f.runtime.take_completion(&ticket) {
                Ok(StdioCompletion::Pending) if NativeInstant::now() < until => {
                    tokio::time::sleep(Duration::from_millis(2)).await
                }
                Ok(StdioCompletion::Pending) => {
                    return Err("cleanup native completion stayed pending".into());
                }
                Ok(StdioCompletion::Close {
                    scope: StdioCloseScope::All,
                    result: Ok(closed),
                }) => {
                    witness = Some(closed);
                    break;
                }
                Ok(_) | Err(_) => break,
            }
        }
        f.runtime.release_operation(&ticket).map_err(proc_error)?;
    }
    if let Some(witness) = witness {
        f.runtime
            .release_stdio(&state.port, &witness)
            .map_err(proc_error)?;
    } else {
        platform.close(transport, context()?).await?;
    }
    Ok(())
}
async fn trial(cancel_close: bool) -> Check {
    let mut f = Fixture::new()?;
    let platform = f.platform();
    let transport = match f.bind(&platform) {
        Ok(transport) => transport,
        Err(error) => {
            f.release()?;
            return Err(error);
        }
    };
    let mut read = platform.read(
        &transport,
        ProviderStream::Output,
        NonZeroU32::new(16).ok_or("read bound")?,
        context()?,
    );
    if poll_once(read.as_mut()).await.is_some() {
        return Err("held child pipe did not produce an actual pending read".into());
    }
    let pending = f
        .runtime
        .stdio_state(&f.owner)
        .map_err(proc_error)?
        .ok_or("native read port absent")?;
    if pending.operations.is_empty() {
        return Err("wrapper read did not accept a native ticket".into());
    }
    if cancel_close {
        // The read still holds its wrapper stream lock, so close must await
        // either actual IOCP completion or that reader before it can finish.
        let mut close = platform.close(&transport, context()?);
        if let Some(result) = poll_once(close.as_mut()).await {
            return Err(format!("close did not suspend with a live reader: {result:?}").into());
        }
        drop(close);
        // Resume the real cancelled read, so only the close future was lost.
        let _ = read.await;
    } else {
        drop(read);
    }
    let outcome = platform.close(&transport, context()?).await;
    let inventory = f.runtime.stdio_state(&f.owner).map_err(proc_error)?;
    let correct = outcome.is_ok() && inventory.is_none();
    let diagnostic = format!(
        "outcome={outcome:?}; remaining native operations={}",
        inventory.as_ref().map_or(0, |state| state.operations.len())
    );
    let cleanup = if inventory.is_some() {
        repair_for_cleanup(&f, &platform, &transport).await
    } else {
        Ok(())
    };
    drop(transport);
    drop(platform);
    cleanup.map_err(|error| format!("original wrapper result: {diagnostic}; cleanup: {error}"))?;
    f.release()?;
    if !correct {
        return Err(format!(
            "cancelled {} future lost native ticket custody: {diagnostic}",
            if cancel_close { "close" } else { "read" }
        )
        .into());
    }
    f.finish()
}
/// Protects: close joins the operation accepted by a dropped reader future.
#[test]
fn independent_windows_wrapper_cancelled_read_releases_every_native_ticket() -> Check {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(trial(false))
}
/// Protects: accepted close custody survives cancellation and an ordinary retry.
#[test]
fn independent_windows_wrapper_cancelled_close_releases_every_native_ticket() -> Check {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        for _ in 0..8 {
            trial(true).await?;
        }
        Ok(())
    })
}
