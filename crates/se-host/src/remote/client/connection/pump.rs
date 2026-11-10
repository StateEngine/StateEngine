//! Independent reader/writer tasks and bounded quiet keepalive.
use super::*;
use futures_util::{SinkExt, StreamExt};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

pub(super) fn open(socket: super::super::super::channel::Socket) -> Arc<Connection> {
    let (outgoing, mut rx) = mpsc::channel::<Outgoing>(REMOTE_CLIENT_QUEUE_FRAMES);
    let shared = Arc::new(Shared {
        pending: StdMutex::new(BTreeMap::new()),
        outgoing,
        requests: Arc::new(Semaphore::new(REMOTE_MAX_REQUESTS)),
        mutations: Arc::new(Semaphore::new(REMOTE_MAX_MUTATIONS)),
        outbound_bytes: Arc::new(Semaphore::new(REMOTE_CLIENT_QUEUE_BYTES)),
        inbound_bytes: Arc::new(Semaphore::new(REMOTE_CLIENT_QUEUE_BYTES)),
        stop: Arc::new(tokio::sync::Notify::new()),
        serial: AtomicU64::new(1),
        closed: AtomicBool::new(false),
        terminal: StdMutex::new(None),
    });
    let (mut write, mut read) = socket.split();
    let (urgent, mut urgent_rx) = mpsc::channel::<Message>(8);
    let writer_weak = Arc::downgrade(&shared);
    let writer_stop = shared.stop.clone();
    let writer = tokio::spawn(async move {
        let outcome: Result<()> = async {
                loop {
                    if writer_weak.upgrade().is_none_or(|s| s.closed.load(Ordering::Acquire)) { return Ok(()); }
                    tokio::select! { biased;
                        _ = writer_stop.notified() => return Err(unavailable("connection invalidated")),
                        control = urgent_rx.recv() => {
                            let Some(control) = control else { return Ok(()); };
                            timeout(super::super::super::channel::WRITE_TIMEOUT,write.send(control)).await
                                .map_err(|_| unavailable("control write deadline"))?.map_err(|_| unavailable("control write failed"))?;
                        }
                        output = rx.recv() => {
                            let Some(output) = output else { return Ok(()); };
                            if let Some(call) = &output.call && let Err(error) = call.check_current() {
                                if let (Some(shared),Some(id)) = (writer_weak.upgrade(),output.id) { shared.fail(id,error); }
                                continue;
                            }
                            timeout(super::super::super::channel::WRITE_TIMEOUT,write.send(Message::text(output.text))).await
                                .map_err(|_| unavailable("network write deadline; acceptance may be unknown"))?.map_err(|_| unavailable("network write failed; acceptance may be unknown"))?;
                        }
                    }
                }
            }.await;
        if let Some(shared) = writer_weak.upgrade() {
            match outcome {
                Err(error) => shared.close_error(error),
                Ok(()) => shared.close("writer closed"),
            }
        }
    });
    let reader_weak = Arc::downgrade(&shared);
    let reader_stop = shared.stop.clone();
    let reader = tokio::spawn(async move {
        let outcome: Result<()> = async {
                let mut ping_at = Instant::now()+Duration::from_secs(15);
                let mut pong_due = None;
                loop {
                    if reader_weak.upgrade().is_none_or(|s| s.closed.load(Ordering::Acquire)) { return Ok(()); }
                    let deadline = pong_due.unwrap_or(ping_at);
                    tokio::select! {
                        _ = reader_stop.notified() => return Err(unavailable("connection invalidated")),
                        _ = tokio::time::sleep_until(deadline) => {
                            if pong_due.is_some() { return Err(unavailable("keepalive response deadline (10seconds)")); }
                            urgent.try_send(Message::Ping(Vec::new().into())).map_err(|_| unavailable("keepalive queue unavailable"))?;
                            pong_due = Some(Instant::now()+Duration::from_secs(10));
                        }
                        input = read.next() => {
                            match input {
                                Some(Ok(Message::Pong(_))) => { pong_due=None; ping_at=Instant::now()+Duration::from_secs(15); }
                                Some(Ok(Message::Ping(data))) => { urgent.try_send(Message::Pong(data)).map_err(|_| unavailable("control queue unavailable"))?; }
                                Some(Ok(Message::Text(text))) => {
                                    let frame: ServerFrame = wire::decode(text.as_bytes(),Phase::Authenticated)?;
                                    let shared=reader_weak.upgrade().ok_or_else(|| unavailable("client closed"))?;
                                    shared.deliver(frame,text.len())?;
                                }
                                Some(Ok(Message::Close(_))) | None => return Err(unavailable("remote connection closed")),
                                _ => return Err(unavailable("remote connection failed or sent a non-JSON message")),
                            }
                        }
                    }
                }
            }.await;
        if let Some(shared) = reader_weak.upgrade() {
            match outcome {
                Err(error) => shared.close_error(error),
                Ok(()) => shared.close("reader closed"),
            }
        }
    });
    Arc::new(Connection {
        shared,
        tasks: tokio::sync::Mutex::new(vec![writer, reader]),
    })
}
