//! Native loopback controls for bounded staged connection disposal.
use super::{CLOSE_TIMEOUT, MAX_BODY_BYTES, MAX_HEADER_BYTES, finish_close};
use crate::client::{ClientOptions, lease::Deadline};
use std::{
    future::{Future, poll_fn},
    sync::{Arc, atomic::AtomicBool},
    task::Poll,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
};
type Check = Result<(), Box<dyn std::error::Error>>;
const RESPONSE: &[u8] = b"complete-response-before-read-side-disposal";

async fn pair() -> std::io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let (client, (server, _)) = tokio::try_join!(
        TcpStream::connect(listener.local_addr()?),
        listener.accept()
    )?;
    Ok((server, client))
}

#[tokio::test]
async fn staged_close_keeps_exact_byte_bound() -> Check {
    let (mut server, peer) = pair().await?;
    let cap = MAX_BODY_BYTES + MAX_HEADER_BYTES;
    let extra = 8192;
    let sender = tokio::spawn(async move {
        let (mut read, mut write) = peer.into_split();
        let send = async {
            write.write_all(&vec![b'x'; cap + extra]).await?;
            write.shutdown().await
        };
        let receive = async {
            let mut response = Vec::new();
            read.read_to_end(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        };
        let ((), response) = tokio::try_join!(send, receive)?;
        Ok::<_, std::io::Error>(response)
    });
    let (_fence, mut shutdown) = watch::channel(None);
    server.write_all(RESPONSE).await?;
    finish_close(&mut server, &mut shutdown).await;
    let mut remainder = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), server.read_to_end(&mut remainder)).await??;
    let response = tokio::time::timeout(Duration::from_secs(3), sender).await???;
    assert_eq!(response, RESPONSE, "write-half close lost response bytes");
    assert_eq!(
        remainder.len(),
        extra,
        "discard read beyond its exact cap or stopped before it"
    );
    println!(
        "CLOSE byte-cap={cap} retained-tail={} response-complete=true",
        remainder.len()
    );
    Ok(())
}

#[tokio::test]
async fn staged_close_times_out_a_continuing_sender() -> Check {
    let (mut server, peer) = pair().await?;
    let (stop, mut stopped) = oneshot::channel::<()>();
    let sender = tokio::spawn(async move {
        let (mut read, mut write) = peer.into_split();
        let send = async {
            let mut sent = 0usize;
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {
                        write.write_all(&[b'x'; 64]).await?;
                        sent += 64;
                    }
                }
            }
            Ok::<_, std::io::Error>(sent)
        };
        let receive = async {
            let mut response = Vec::new();
            read.read_to_end(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        };
        tokio::try_join!(send, receive)
    });
    let (_fence, mut shutdown) = watch::channel(None);
    server.write_all(RESPONSE).await?;
    let begin = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(2),
        finish_close(&mut server, &mut shutdown),
    )
    .await?;
    let elapsed = begin.elapsed();
    stop.send(())
        .map_err(|()| "continuing sender stopped before close completed")?;
    let (sent, response) = tokio::time::timeout(Duration::from_secs(3), sender).await???;
    assert!(
        sent > 0 && sent < MAX_BODY_BYTES,
        "sender did not exercise the time bound"
    );
    assert!(
        elapsed >= CLOSE_TIMEOUT,
        "close ended before the unfinished sender's deadline"
    );
    assert_eq!(response, RESPONSE, "write-half close lost response bytes");
    println!(
        "CLOSE continuing-sender-bytes={sent} elapsed-ms={} response-complete=true",
        elapsed.as_millis()
    );
    Ok(())
}

#[tokio::test]
async fn staged_close_shutdown_preempts_pending_discard() -> Check {
    let (mut server, mut peer) = pair().await?;
    let (fence, mut shutdown) = watch::channel(None);
    server.write_all(RESPONSE).await?;
    let mut closing = Box::pin(finish_close(&mut server, &mut shutdown));
    let ready = poll_fn(|cx| Poll::Ready(closing.as_mut().poll(cx).is_ready())).await;
    assert!(!ready, "idle peer should leave discard pending");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut response)).await??;
    assert_eq!(
        response, RESPONSE,
        "response/half-close was not observed before shutdown"
    );
    fence.send(Some(Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    })?))?;
    let ready = poll_fn(|cx| Poll::Ready(closing.as_mut().poll(cx).is_ready())).await;
    assert!(ready, "shutdown did not preempt on the next poll");
    println!("CLOSE shutdown-pending-discard=preempted next-poll=true");
    Ok(())
}
