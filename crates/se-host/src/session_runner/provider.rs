//! Own the child and bounded stdio queues independently of any IPC connection.
use super::protocol::{Bootstrap, CHUNK_BYTES, Chunk};
use crate::client::wire;
use se_types::{Result, SeError};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    sync::mpsc,
    task::JoinSet,
};

pub(super) struct Provider {
    child: Child,
    input: Option<ChildStdin>,
    output: mpsc::Receiver<Result<Chunk>>,
    readers: JoinSet<()>,
}

impl Provider {
    pub fn spawn(plan: &Bootstrap) -> Result<Self> {
        let mut child = Command::new(plan.executable.to_local()?)
            .args(&plan.arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| wire::io_failure("start runner provider", error))?;
        let (sender, output) = mpsc::channel(8);
        let mut readers = JoinSet::new();
        let stdout = child.stdout.take().ok_or_else(missing_pipe)?;
        let stderr = child.stderr.take().ok_or_else(missing_pipe)?;
        readers.spawn(read_stream(stdout, "stdout", sender.clone()));
        readers.spawn(read_stream(stderr, "stderr", sender));
        let input = child.stdin.take();
        Ok(Self {
            child,
            input,
            output,
            readers,
        })
    }

    pub fn pid(&self) -> Result<u32> {
        self.child
            .id()
            .ok_or_else(|| SeError::invalid("runner provider", "a retained child PID"))
    }

    pub async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > CHUNK_BYTES {
            return Err(SeError::invalid("runner write", "at most 16 KiB per frame"));
        }
        let input = self.input.as_mut().ok_or_else(missing_pipe)?;
        input
            .write_all(bytes)
            .await
            .map_err(|error| wire::io_failure("write provider stdin", error))?;
        input
            .flush()
            .await
            .map_err(|error| wire::io_failure("flush provider stdin", error))
    }

    pub async fn read(&mut self) -> Result<Chunk> {
        self.output.recv().await.ok_or_else(|| {
            SeError::invalid(
                "runner output",
                "both EOF frames were delivered; no further output is available",
            )
        })?
    }

    pub async fn finish(&mut self) -> Result<serde_json::Value> {
        drop(self.input.take());
        let status = self
            .child
            .wait()
            .await
            .map_err(|error| wire::io_failure("join provider", error))?;
        Ok(serde_json::json!({"code": status.code(), "success": status.success()}))
    }

    pub async fn close(mut self) -> Result<()> {
        drop(self.input.take());
        // This prototype owns only its newly spawned child. Native provider
        // scope custody remains in the host until the transport cost is known.
        self.child
            .kill()
            .await
            .or_else(|error| {
                self.child
                    .try_wait()
                    .and_then(|status| if status.is_some() { Ok(()) } else { Err(error) })
            })
            .map_err(|error| wire::io_failure("close runner provider", error))?;
        self.readers.abort_all();
        while let Some(joined) = self.readers.join_next().await {
            if let Err(error) = joined
                && !error.is_cancelled()
            {
                return Err(SeError::invalid("runner stream join", &error.to_string()));
            }
        }
        Ok(())
    }
}

fn missing_pipe() -> SeError {
    SeError::invalid("runner provider stdio", "the original retained pipe")
}

async fn read_stream(
    mut stream: impl AsyncRead + Unpin,
    name: &'static str,
    sender: mpsc::Sender<Result<Chunk>>,
) {
    loop {
        let mut bytes = vec![0; CHUNK_BYTES];
        let read = stream.read(&mut bytes).await;
        let result = match read {
            Ok(count) => {
                bytes.truncate(count);
                Ok(Chunk {
                    stream: name,
                    bytes,
                    eof: count == 0,
                })
            }
            Err(error) => Err(wire::io_failure("read provider output", error)),
        };
        let done = match &result {
            Ok(chunk) => chunk.eof,
            Err(_) => true,
        };
        if sender.send(result).await.is_err() || done {
            break;
        }
    }
}

pub(super) async fn bounded<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .map_err(|_| SeError::invalid("runner provider I/O", "completion within five seconds"))?
}
