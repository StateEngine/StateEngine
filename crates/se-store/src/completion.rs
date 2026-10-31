//! Awaitable replies independent of any executor; dropping a waiter never cancels work.
use crate::{error::*, *};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
struct State<T> {
    value: Option<StoreResult<T>>,
    waker: Option<Waker>,
    sender: bool,
}
pub struct Completion<T> {
    shared: Arc<Mutex<State<T>>>,
}
pub(crate) struct Reply<T> {
    shared: Arc<Mutex<State<T>>>,
}
pub(crate) fn channel<T>() -> (Reply<T>, Completion<T>) {
    let shared = Arc::new(Mutex::new(State {
        value: None,
        waker: None,
        sender: true,
    }));
    (
        Reply {
            shared: shared.clone(),
        },
        Completion { shared },
    )
}
impl<T> Reply<T> {
    pub(crate) fn send(self, value: StoreResult<T>) {
        let wake = match self.shared.lock() {
            Ok(mut s) => {
                s.value = Some(value);
                s.sender = false;
                s.waker.take()
            }
            Err(p) => {
                let mut s = p.into_inner();
                s.value = Some(Err(fail(
                    StoreErrorCode::WriterClosed,
                    "reply state poisoned",
                )));
                s.sender = false;
                s.waker.take()
            }
        };
        if let Some(w) = wake {
            w.wake()
        }
    }
}
impl<T> Drop for Reply<T> {
    fn drop(&mut self) {
        let wake = match self.shared.lock() {
            Ok(mut s) => {
                s.sender = false;
                s.waker.take()
            }
            Err(p) => {
                let mut s = p.into_inner();
                s.sender = false;
                s.waker.take()
            }
        };
        if let Some(w) = wake {
            w.wake()
        }
    }
}
impl<T> Future for Completion<T> {
    type Output = StoreResult<T>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.shared.lock() {
            Ok(mut s) => {
                if let Some(value) = s.value.take() {
                    return Poll::Ready(value);
                }
                if !s.sender {
                    return Poll::Ready(Err(fail(
                        StoreErrorCode::CommitOutcomeUnknown,
                        "writer reply ended; resolve the original operation key",
                    )));
                }
                s.waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(fail(
                StoreErrorCode::WriterClosed,
                "reply state poisoned",
            ))),
        }
    }
}
impl CommitWait for Completion<CommitReceipt> {}
