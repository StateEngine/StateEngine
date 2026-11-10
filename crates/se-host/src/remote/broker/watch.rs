use super::*;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
mod measure;
#[derive(Default)]
pub(crate) struct Watches {
    entries: Mutex<BTreeMap<String, Arc<Entry>>>,
}
struct Entry {
    target_count: usize,
    touched: Mutex<Instant>,
    source: Option<RemoteSourceSession>,
    fence: Option<Arc<AtomicBool>>,
    state: AsyncMutex<State>,
}
struct State {
    opened_at: Instant,
    clock: Option<measure::Bracket>,
    request: RemoteWatch,
    stream: Option<Box<dyn RemoteWatchStream>>,
    cursors: Vec<RemoteCursorSet>,
    returned_cursors: Vec<RemoteCursorSet>,
}
impl Entry {
    fn context(&self) -> RemoteCallContext {
        match (&self.source, &self.fence) {
            (Some(source), Some(fence)) => {
                RemoteCallContext::from_verified_source(source.clone(), Arc::clone(fence))
            }
            _ => RemoteCallContext::human_device(),
        }
    }
}
impl Watches {
    pub(crate) fn close(&self) -> Result<()> {
        self.entries.lock().map_err(|_| poisoned())?.clear();
        Ok(())
    }

    pub(super) fn remove_fenced(&self) -> Result<()> {
        let mut entries = self.entries.lock().map_err(|_| poisoned())?;
        let mut remove = Vec::new();
        for (key, entry) in entries.iter() {
            let idle =
                entry.touched.lock().map_err(|_| poisoned())?.elapsed() > Duration::from_secs(120);
            if entry.context().check_current().is_err() || (idle && Arc::strong_count(entry) == 1) {
                remove.push(key.clone());
            }
        }
        for key in remove {
            entries.remove(&key);
        }
        Ok(())
    }
    pub(super) async fn read(
        &self,
        device: &MachineSession,
        source: Option<&VerifiedSourceSession>,
        client: Arc<dyn RemoteClient>,
        selection: (RemoteWatch, Option<[u8; 16]>),
        wait_ms: u32,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<RemoteWatchBatch> {
        let (request, reader_id) = selection;
        let key = serde_json::to_string(&(
            device.host,
            &device.grant,
            source.map(|s| (&s.source, s.credential)),
            &request.targets,
            &request.visible,
            request.measure,
            reader_id,
        ))
        .map_err(|_| poisoned())?;
        self.read_with(
            key,
            source,
            request,
            wait_ms,
            deadline,
            move |context, request| Box::pin(async move { client.watch(context, request).await }),
        )
        .await
    }

    #[cfg(feature = "remote")]
    pub(crate) async fn read_local(
        &self,
        admission: &se_store::Admission,
        service: service::Service,
        selection: (RemoteWatch, Option<[u8; 16]>),
        wait_ms: u32,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<RemoteWatchBatch> {
        let (request, reader_id) = selection;
        let key = serde_json::to_string(&serde_json::json!({
            "native_owner":admission.actor,"generation":admission.generation,
            "targets":request.targets,"visible":request.visible,"measure":request.measure,"reader":reader_id,
        }))
        .map_err(|_| poisoned())?;
        let admission = admission.clone();
        self.read_with(key, None, request, wait_ms, deadline, move |_, request| {
            Box::pin(async move { service.watch_local(admission, request) })
        })
        .await
    }

    async fn read_with<F>(
        &self,
        key: String,
        source: Option<&VerifiedSourceSession>,
        request: RemoteWatch,
        wait_ms: u32,
        deadline: &crate::client::lease::Deadline,
        open: F,
    ) -> Result<RemoteWatchBatch>
    where
        F: FnOnce(
                RemoteCallContext,
                RemoteWatch,
            ) -> RemoteFuture<'static, Box<dyn RemoteWatchStream>>
            + Send,
    {
        self.remove_fenced()?;
        let entry = {
            let mut entries = self.entries.lock().map_err(|_| poisoned())?;
            if !entries.contains_key(&key) {
                while entries.values().map(|e| e.target_count).sum::<usize>()
                    + request.targets.len()
                    > 64
                    || entries.len() >= REMOTE_MAX_REQUESTS / 2
                {
                    // Leave request slots for active list/send calls as well as
                    // readers: inactive subscriptions also occupy far-side slots.
                    // A stopped terminal must not reserve capacity for the full
                    // idle TTL. Evict only entries no read currently owns; their
                    // sealed cursors reconstruct the view if a reader returns.
                    let mut oldest = None;
                    for (key, entry) in entries
                        .iter()
                        .filter(|(_, entry)| Arc::strong_count(entry) == 1)
                    {
                        let touched = *entry.touched.lock().map_err(|_| poisoned())?;
                        if oldest.as_ref().is_none_or(|(_, prior)| touched < *prior) {
                            oldest = Some((key.clone(), touched));
                        }
                    }
                    let Some((key, _)) = oldest else {
                        if entries.values().map(|e| e.target_count).sum::<usize>()
                            + request.targets.len()
                            > 64
                        {
                            return Err(refused(
                                "64 source watch targets are in flight; retry after a reader finishes",
                            ));
                        }
                        // The smaller threshold trims idle cache entries only;
                        // it never interrupts or limits an active reader.
                        break;
                    };
                    entries.remove(&key);
                }
                entries.insert(
                    key.clone(),
                    Arc::new(Entry {
                        target_count: request.targets.len(),
                        touched: Mutex::new(Instant::now()),
                        source: source.map(|s| s.source.clone()),
                        fence: source.map(|s| Arc::clone(&s.fence)),
                        state: AsyncMutex::new(State {
                            opened_at: Instant::now(),
                            clock: None,
                            request: request.clone(),
                            stream: None,
                            cursors: request.cursors.clone(),
                            returned_cursors: request.cursors.clone(),
                        }),
                    }),
                );
            }
            Arc::clone(entries.get(&key).ok_or_else(poisoned)?)
        };
        // Allow a disconnected predecessor's task to release its page. The
        // caller retains its existing bounded activity slot, and neither a
        // concurrent reader nor a reconnect allocates a second subscription.
        let lock_wait = Duration::from_millis(50).min(deadline.remaining()?);
        let mut state = tokio::time::timeout(lock_wait, entry.state.lock())
            .await
            .map_err(|_| {
                let mut error = SeError::new(se_types::Detail::DeadlineExceeded(
                    se_types::details::DeadlineExceeded {
                        op: "remote watch; another page is still in flight, close it or retry this read".into(),
                        deadline_ms: lock_wait.as_millis() as u64,
                    },
                ));
                error.body = error
                    .body
                    .with_retry(se_types::Retry::After(Duration::from_millis(50)))
                    .with_remedy(se_types::Remedy {
                        text: "Await the current watch page or close its reader, then retry this same scoped read.".into(),
                        command: None,
                    });
                error
            })?;
        *entry.touched.lock().map_err(|_| poisoned())? = Instant::now();
        entry.context().check_current()?;
        let incoming = serde_json::to_vec(&request.cursors).map_err(|_| poisoned())?;
        let same_cursors = incoming
            == serde_json::to_vec(&state.returned_cursors).map_err(|_| poisoned())?
            || incoming == serde_json::to_vec(&state.cursors).map_err(|_| poisoned())?;
        if request.cursors.is_empty() || !same_cursors {
            // An explicitly different continuation requests a new starting view.
            state.cursors = request.cursors.clone();
            state.stream = None;
        }
        if state.request.budget != request.budget {
            state.stream = None;
        }
        if state.stream.is_none() {
            state.opened_at = Instant::now();
            state.clock = None;
            let mut resumed = request.clone();
            resumed.cursors = state.cursors.clone();
            state.stream = Some(open(entry.context(), resumed).await?);
            state.request = request.clone();
        }
        entry.context().check_current()?;
        // A wait is an upper bound, not a fresh request deadline. Keep the
        // existing native response-write allowance after subscription setup.
        let wait = Duration::from_millis(u64::from(wait_ms)).min(
            deadline
                .remaining()?
                .saturating_sub(crate::client::lease::WRITE_TIMEOUT),
        );
        // Take ownership across the await. Cancellation/error drops this read
        // subscription, leaving the last verified cursors for a safe replay.
        let mut stream = state.stream.take().ok_or_else(poisoned)?;
        let mut result = stream.next(wait).await?;
        if request.measure {
            let opened_at = state.opened_at;
            measure::release(&mut state.clock, opened_at, &mut result)?;
        }
        let validated = (|| {
            entry.context().check_current()?;
            check_size(&result, request.budget)?;
            if result.schema != RemoteWatchBatch::SCHEMA
                || result.cursors.len() > 64
                || result
                    .cursors
                    .iter()
                    .any(|c| !request.targets.contains(&c.target))
            {
                return Err(refused(
                    "remote watch schema or cursors do not match this selection",
                ));
            }
            for record in &result.records {
                match record {
                    RemoteWatchRecord::Snapshot { view } => {
                        if view.schema != RemoteListResult::SCHEMA
                            || view
                                .agents
                                .items()
                                .iter()
                                .any(|r| !request.targets.contains(&r.target))
                        {
                            return Err(refused("watch snapshot exceeded its selected scope"));
                        }
                    }
                    RemoteWatchRecord::Durable { target, .. }
                    | RemoteWatchRecord::Provisional { target, .. }
                    | RemoteWatchRecord::Gap { target, .. } => {
                        if !request.targets.contains(target) {
                            return Err(refused("watch record exceeded its selected scope"));
                        }
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = validated {
            state.stream = None;
            return Err(error);
        }
        if result.reset_required {
            state.cursors.clear();
        }
        for cursor in &result.cursors {
            if let Some(saved) = state
                .cursors
                .iter_mut()
                .find(|saved| saved.target == cursor.target)
            {
                *saved = cursor.clone();
            } else {
                state.cursors.push(cursor.clone());
            }
        }
        // A bounded page may carry only cursor updates for targets it advanced.
        // The next CLI/MCP call can return that exact page without losing the
        // other targets' retained positions or restarting their replay at zero.
        state.returned_cursors = result.cursors.clone();
        // A reset/gap is a real discontinuity. Drop this stream; the next call
        // opens a bounded fresh watch from the returned scoped cursors.
        if !result.reset_required {
            state.stream = Some(stream);
        }
        Ok(result)
    }
}
