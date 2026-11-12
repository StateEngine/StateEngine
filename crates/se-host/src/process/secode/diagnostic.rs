//! Auxiliary streams are drained independently of readiness and retain bounded
//! private diagnostics. A caller leaving never leaves an open, undrained pipe.
use super::*;
use crate::{ProviderStream, StreamRead};
use serde::Serialize;
use std::{io::Write, num::NonZeroU32, sync::Mutex};

#[derive(Default, Serialize)]
struct Stream {
    bytes: Vec<u8>,
    omitted_bytes: u64,
    eof: bool,
    failure: Option<String>,
}
impl Stream {
    fn retain(&mut self, bytes: &[u8]) {
        let keep = bytes.len().min(65536usize.saturating_sub(self.bytes.len()));
        self.bytes.extend_from_slice(&bytes[..keep]);
        self.omitted_bytes = self
            .omitted_bytes
            .saturating_add((bytes.len() - keep) as u64);
    }
}
#[derive(Default, Serialize)]
struct Diagnostics {
    stdout: Stream,
    stderr: Stream,
}
pub(super) struct Output {
    io: Arc<dyn ProviderIoPlatform>,
    transport: crate::ProviderTransport,
    diagnostics: Mutex<Diagnostics>,
    tasks: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    generation: se_types::Generation,
    path: PathBuf,
}
impl Output {
    pub fn new(
        io: Arc<dyn ProviderIoPlatform>,
        transport: crate::ProviderTransport,
        generation: se_types::Generation,
        path: PathBuf,
    ) -> Arc<Self> {
        Arc::new(Self {
            io,
            transport,
            generation,
            path,
            diagnostics: Mutex::default(),
            tasks: tokio::sync::Mutex::default(),
        })
    }
    pub async fn start(self: &Arc<Self>) {
        let mut tasks = self.tasks.lock().await;
        for kind in [ProviderStream::Output, ProviderStream::Error] {
            let output = self.clone();
            tasks.push(tokio::spawn(async move {
                output.drain(kind).await;
            }));
        }
    }
    fn context(&self, timeout: std::time::Duration) -> crate::CallContext {
        crate::CallContext {
            generation: self.generation,
            timeout,
            cancellation: Arc::new(crate::CancellationState { _private: () }),
        }
    }
    pub async fn finish_input(&self, deadline: &Deadline) -> Result<()> {
        self.io
            .finish_input(&self.transport, self.context(deadline.remaining()?))
            .await
    }
    pub async fn write_input(&self, input: &se_types::Secret, deadline: &Deadline) -> Result<()> {
        let written = self
            .io
            .write(
                &self.transport,
                input.expose().to_vec(),
                self.context(deadline.remaining()?),
            )
            .await?;
        if written.completed_bytes as usize != input.expose().len() || written.failure.is_some() {
            return Err(error(
                "SE Code auxiliary stdin",
                "private credential write was incomplete; retain the original cleanup operation",
            ));
        }
        Ok(())
    }
    pub fn response(&self) -> Result<serde_json::Value> {
        let value = self
            .diagnostics
            .lock()
            .map_err(|_| error("SE Code retirement response", "poisoned diagnostics"))?;
        if !value.stdout.eof || value.stdout.omitted_bytes != 0 || value.stdout.failure.is_some() {
            return Err(error(
                "SE Code retirement response",
                "complete bounded stdout is unavailable",
            ));
        }
        serde_json::from_slice(&value.stdout.bytes)
            .map_err(|e| error("SE Code retirement response", e))
    }
    async fn drain(self: Arc<Self>, kind: ProviderStream) {
        loop {
            let read = self
                .io
                .read(
                    &self.transport,
                    kind,
                    NonZeroU32::new(65536).unwrap_or(NonZeroU32::MIN),
                    self.context(std::time::Duration::from_secs(60)),
                )
                .await;
            if matches!(&read,Err(error) if matches!(error.body.detail(),se_types::Detail::DeadlineExceeded(_)))
            {
                continue;
            }
            let Ok(mut diagnostics) = self.diagnostics.lock() else {
                return;
            };
            let stream = if kind == ProviderStream::Error {
                &mut diagnostics.stderr
            } else {
                &mut diagnostics.stdout
            };
            match read {
                Ok(StreamRead::Bytes(bytes)) => stream.retain(&bytes),
                Ok(StreamRead::Eof) => {
                    stream.eof = true;
                    return;
                }
                Ok(StreamRead::Failed { bytes, error }) => {
                    stream.retain(&bytes);
                    stream.failure = Some(se_types::SeError::from(error).to_string());
                    return;
                }
                Err(error) => {
                    stream.failure = Some(error.to_string());
                    return;
                }
            }
        }
    }
    pub async fn close(&self, deadline: &Deadline) -> Result<()> {
        let mut tasks = self.tasks.lock().await;
        while let Some(mut task) = tasks.pop() {
            match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.at()), &mut task)
                .await
            {
                Ok(result) => result.map_err(|e| error("SE Code auxiliary drain join", e))?,
                Err(_) => {
                    tasks.push(task);
                    return Err(error(
                        "SE Code auxiliary drain join",
                        "original stream remains retained after deadline",
                    ));
                }
            }
        }
        self.io
            .close(&self.transport, self.context(deadline.remaining()?))
            .await
    }
    pub fn save(&self, deadline: &Deadline) -> Result<()> {
        deadline.remaining()?;
        let diagnostics = self
            .diagnostics
            .lock()
            .map_err(|_| error("SE Code auxiliary diagnostics", "poisoned diagnostics"))?;
        let bytes = serde_json::to_vec(&*diagnostics)
            .map_err(|e| error("SE Code auxiliary diagnostics", e))?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| error("SE Code auxiliary diagnostics", "parent absent"))?;
        let files = se_proc::NativeStateFiles::create(parent)
            .map_err(|e| error("SE Code auxiliary diagnostics", e))?;
        if let Some(mut existing) = self.open_file(deadline)? {
            let hash = existing
                .sha256()
                .map_err(|e| error("SE Code auxiliary diagnostics", e))?;
            existing
                .replace(hash, &bytes)
                .map_err(|e| error("SE Code auxiliary diagnostics", e))?;
        } else {
            let mut staged = files
                .create_staging(parent)
                .map_err(|e| error("SE Code auxiliary diagnostics", e))?;
            staged
                .file
                .write_all(&bytes)
                .and_then(|()| staged.file.sync_all())
                .map_err(|e| error("SE Code auxiliary diagnostics", e))?;
            drop(staged.file);
            files
                .publish_no_replace(&staged.path, &self.path)
                .map_err(|e| error("SE Code auxiliary diagnostics", e))?;
        }
        let mut observed = self.open_file(deadline)?.ok_or_else(|| {
            error(
                "SE Code auxiliary diagnostics",
                "published diagnostics absent",
            )
        })?;
        if observed
            .read(1024 * 1024)
            .map_err(|e| error("SE Code auxiliary diagnostics", e))?
            != bytes
        {
            return Err(error("SE Code auxiliary diagnostics", "readback differs"));
        }
        deadline.remaining()?;
        Ok(())
    }
    fn open_file(&self, deadline: &Deadline) -> Result<Option<se_proc::OwnedFile>> {
        use crate::state_files::{Acquisition, AcquisitionRetry};
        let mut retry = AcquisitionRetry::new(deadline.at());
        loop {
            deadline.remaining()?;
            match retry
                .acquire(|| se_proc::OwnedFile::open(&self.path))
                .map_err(|failure| {
                    failure.into_public(|native| error("SE Code auxiliary diagnostics", native))
                })? {
                Acquisition::Ready(file) => {
                    deadline.remaining()?;
                    return Ok(file);
                }
                Acquisition::Wait(delay) => std::thread::sleep(delay),
            }
        }
    }
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}
