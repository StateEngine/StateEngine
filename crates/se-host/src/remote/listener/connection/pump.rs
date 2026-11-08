use super::*;
use futures_util::stream::{SplitSink, SplitStream};
use std::collections::BTreeMap;
use tokio::{
    sync::mpsc,
    task::AbortHandle,
    time::{Instant, sleep_until},
};
pub(super) type Device = Arc<auth::AuthenticatedDevice>;
type Sink = SplitSink<Socket, Message>;
type Stream = SplitStream<Socket>;

pub(super) async fn run(
    socket: Socket,
    endpoint: Arc<ClientEndpoint>,
    output: Arc<Output>,
    device: Device,
    slot: limits::DeviceSlot,
) -> Result<()> {
    let (sink, stream) = socket.split();
    let (urgent_tx, urgent_rx) = mpsc::channel(8);
    let used = tokio::sync::Notify::new();
    // These are futures in this one connection task. Losing either half drops
    // both socket halves, all private output and all read/watch continuations.
    let result = tokio::select! {biased;
        _=output.stop.notified()=>Err(unavailable("client output invalidated")),
        result=writer(sink,&endpoint,&output,&device,urgent_rx,&used)=>result,
        result=lease(&endpoint,&device,&used)=>result,
        result=reader(stream,&endpoint,&output,&device,urgent_tx,slot)=>result,
    };
    output.invalidate();
    result
}
async fn writer(
    mut sink: Sink,
    endpoint: &ClientEndpoint,
    output: &Output,
    device: &Device,
    mut urgent: mpsc::Receiver<Message>,
    used: &tokio::sync::Notify,
) -> Result<()> {
    loop {
        if output.invalid.load(Ordering::Acquire) {
            return Err(unavailable("client writer fenced"));
        }
        if let Ok(message) = urgent.try_recv() {
            write(&mut sink, message, output).await?;
            continue;
        }
        {
            let notified = output.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(frame) = output.pop()? {
                let len = frame.text.len();
                let security = endpoint.security.clone();
                let device = device.clone();
                bounded(endpoint, move || {
                    drop(security.output_fence(&device, &device.grant().scope)?);
                    Ok(())
                })
                .await?;
                write(&mut sink, Message::text(frame.text), output).await?;
                output.sent(len)?;
                if frame.use_watch {
                    used.notify_one();
                }
                continue;
            }
            tokio::select! {biased;
                _=output.stop.notified()=>return Err(unavailable("client writer invalidated")),
                message=urgent.recv()=>write(&mut sink,message.ok_or_else(||unavailable("client reader closed"))?,output).await?,
                _=notified=>(),
            }
        }
    }
}
async fn write(sink: &mut Sink, message: Message, output: &Output) -> Result<()> {
    if output.invalid.load(Ordering::Acquire) {
        return Err(unavailable("client writer fenced"));
    }
    tokio::select! {biased;
        _=output.stop.notified()=>Err(unavailable("client writer invalidated")),
        result=timeout(Duration::from_secs(5),sink.send(message))=>result.map_err(|_|unavailable("client write deadline exceeded"))?.map_err(|_|unavailable("client write failed")),
    }
}
fn urgent(tx: &mpsc::Sender<Message>, message: Message) -> Result<()> {
    tx.try_send(message)
        .map_err(|_| unavailable("bounded client control queue full or closed"))
}
async fn reader(
    mut stream: Stream,
    endpoint: &ClientEndpoint,
    output: &Arc<Output>,
    device: &Device,
    control: mpsc::Sender<Message>,
    slot: limits::DeviceSlot,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let mut pending = BTreeMap::<wire::RequestId, (AbortHandle, bool)>::new();
    let mut ping_at = Instant::now() + Duration::from_secs(15);
    let mut pong_until = None;
    let mut serial = 0u64;
    let mut expected_pong = None;
    let mut last_request = None;
    loop {
        if output.invalid.load(Ordering::Acquire) {
            return Err(unavailable("client reader fenced"));
        }
        let until = [Some(ping_at), pong_until]
            .into_iter()
            .flatten()
            .min()
            .ok_or_else(|| unavailable("client clock absent"))?;
        tokio::select! {biased;
            _=output.stop.notified()=>return Err(unavailable("client reader invalidated")),
            joined=tasks.join_next(),if !tasks.is_empty()=>{
                match joined {Some(Ok(Ok(id)))=>{pending.remove(&id);},Some(Ok(Err(error)))=>return Err(error),Some(Err(error)) if error.is_cancelled()=>(),Some(Err(_))=>return Err(unavailable("client operation task failed")),None=>()}
            }
            _=sleep_until(until)=>{
                let now=Instant::now();
                if pong_until.is_some_and(|at|now>=at) {return Err(unavailable("client pong deadline exceeded (10 seconds)"));}
                if now>=ping_at {
                    serial=serial.checked_add(1).ok_or_else(||unavailable("client ping sequence exhausted"))?;
                    let bytes=serial.to_be_bytes();expected_pong=Some(bytes);urgent(&control,Message::Ping(bytes.to_vec().into()))?;
                    pong_until=Some(now+Duration::from_secs(10));ping_at=now+Duration::from_secs(15);
                }
            }
            frame=stream.next()=>{
                match frame {
                    Some(Ok(Message::Text(text)))=>match wire::decode(text.as_bytes(),Phase::Authenticated)? {
                        ClientFrame::Request {id,invocation}=>{
                            if last_request.is_some_and(|last|id<=last) {return Err(unavailable("request IDs must increase on this connection; reconnect before reuse"));}
                            last_request=Some(id);
                            let mutation=matches!(invocation.request,RemoteRequest::Send(_));
                            let admission=slot.limits.request(mutation)?;
                            let endpoint=Arc::new(ClientEndpoint {security:endpoint.security.clone(),key:endpoint.key.clone(),cipher:endpoint.cipher.clone(),service:endpoint.service.clone(),blocking:endpoint.blocking.clone()});
                            let output=output.clone();let device=device.clone();
                            let handle=tasks.spawn(async move {let _admission=admission;requests::run(endpoint,output,device,id,*invocation).await.map(|()|id)});
                            pending.insert(id,(handle,mutation));
                        }
                        ClientFrame::Cancel {id}=>{if pending.get(&id).is_some_and(|(_,mutation)|!*mutation) && let Some((task,_))=pending.remove(&id) {task.abort();}}
                    },
                    Some(Ok(Message::Ping(bytes)))=>urgent(&control,Message::Pong(bytes))?,
                    Some(Ok(Message::Pong(bytes)))=>{if expected_pong.as_ref().is_some_and(|expected|bytes.as_ref()==expected) {expected_pong=None;pong_until=None;}},
                    Some(Ok(Message::Close(_)))|None=>return Ok(()),
                    _=>return Err(unavailable("client sent a non-JSON message or closed abnormally")),
                }
            }
        }
    }
}

async fn lease(
    endpoint: &ClientEndpoint,
    device: &Device,
    used: &tokio::sync::Notify,
) -> Result<()> {
    loop {
        used.notified().await;
        endpoint.security.record_use(device).await?;
    }
}
