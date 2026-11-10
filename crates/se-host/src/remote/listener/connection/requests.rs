use super::pump::Device;
use super::*;
pub(super) async fn run(
    endpoint: Arc<ClientEndpoint>,
    output: Arc<Output>,
    device: Device,
    id: wire::RequestId,
    invocation: RemoteInvocation,
) -> Result<()> {
    let security = endpoint.security.clone();
    let checked = device.clone();
    let authorized = bounded(&endpoint, move || {
        security.authorize_invocation(&checked, invocation)
    })
    .await;
    let result = match authorized {
        Ok(request) if matches!(request.request(), RemoteRequest::Watch(_)) => {
            watch(&endpoint, &output, &device, id, request).await
        }
        Ok(request) => match endpoint.service.execute(request).await {
            Ok(result) => {
                enqueue(
                    &endpoint,
                    &output,
                    &device,
                    ServerFrame::Response { id, result },
                )
                .await
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    match result {
        // Lease renewal is signalled by the socket writer after delivery.
        // A completed request never holds capacity behind maintenance writes.
        Ok(()) => Ok(()),
        Err(error) => {
            enqueue(
                &endpoint,
                &output,
                &device,
                ServerFrame::Error {
                    id: Some(id),
                    error: error.into_body(),
                },
            )
            .await
        }
    }
}
async fn watch(
    endpoint: &ClientEndpoint,
    output: &Arc<Output>,
    device: &Device,
    id: wire::RequestId,
    request: auth::AuthorizedRemoteRequest,
) -> Result<()> {
    let mut stream = endpoint.service.watch(request).await?;
    let mut first = true;
    loop {
        if output.invalid.load(Ordering::Acquire) {
            return Err(unavailable("watch output invalidated"));
        }
        let batch = stream
            .next(if first {
                Duration::ZERO
            } else {
                Duration::from_secs(30)
            })
            .await?;
        let used = !batch.records.is_empty();
        if first {
            enqueue(
                endpoint,
                output,
                device,
                ServerFrame::Response {
                    id,
                    result: wire::Reply::Watch(Box::new(batch)),
                },
            )
            .await?;
            first = false;
        } else if used || batch.reset_required {
            enqueue(
                endpoint,
                output,
                device,
                ServerFrame::WatchEvent {
                    id,
                    batch: Box::new(batch),
                },
            )
            .await?;
        }
    }
}
pub(super) async fn enqueue(
    endpoint: &ClientEndpoint,
    output: &Arc<Output>,
    device: &Device,
    frame: ServerFrame,
) -> Result<()> {
    // Encode before entering the finite grant lock. Only bounded queue insertion
    // happens under it; no SQL pin, serialization, network await or filesystem I/O.
    let record_use = matches!(&frame, ServerFrame::Response { .. })
        || matches!(&frame, ServerFrame::WatchEvent { batch, .. } if !batch.records.is_empty());
    let text = wire::encode(&frame, Phase::Authenticated)?;
    let security = endpoint.security.clone();
    let queued = output.clone();
    let device = device.clone();
    let result = bounded(endpoint, move || {
        let _fence = security.output_fence(&device, &device.grant().scope)?;
        queued.enqueue(text, record_use)
    })
    .await;
    if result.is_err() {
        output.invalidate();
    }
    result
}
