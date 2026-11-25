//! A bounded native Windows source watcher. Completion ownership stays here.
use super::*;
use std::{
    collections::{HashMap, VecDeque},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
};
use windows_sys::Win32::{
    Foundation::{ERROR_IO_PENDING, ERROR_NOT_FOUND, INVALID_HANDLE_VALUE},
    Storage::FileSystem::*,
    System::IO::{
        CancelIoEx, CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
        PostQueuedCompletionStatus,
    },
};

mod decode;
mod events;
pub use events::NativeWatchEvents;

const BUFFER: usize = 64 * 1024;
const MAX_WATCHES: usize = 128;
const MAX_QUEUE: usize = 16384;
const COMMAND: usize = usize::MAX;
type Signal = Arc<dyn Fn() + Send + Sync>;

struct Queue {
    events: VecDeque<Vec<u8>>,
    invalidated: VecDeque<u32>,
    bytes: usize,
    lost: bool,
    signal: Option<Signal>,
}
impl Queue {
    fn lost(&mut self) {
        self.events.clear();
        self.bytes = 0;
        self.lost = true;
        if let Some(signal) = &self.signal {
            signal();
        }
    }
    fn push(&mut self, event: Vec<u8>) {
        if self.lost {
            return;
        }
        if self.bytes.saturating_add(event.len()) > MAX_QUEUE {
            self.lost();
            return;
        }
        self.bytes += event.len();
        self.events.push_back(event);
        if let Some(signal) = &self.signal {
            signal();
        }
    }
}

enum Command {
    Subscribe {
        directory: File,
        identity: [u8; 32],
        ancestors: Vec<(File, String)>,
        recursive: bool,
        response: mpsc::Sender<io::Result<NativeWatchRegistration>>,
    },
    Remove {
        id: u32,
        response: mpsc::Sender<io::Result<bool>>,
    },
    Barrier {
        response: mpsc::Sender<()>,
    },
    Stop,
}

pub struct NativeSourceWatch {
    port: Arc<OwnedHandle>,
    commands: mpsc::Sender<Command>,
    queue: Arc<Mutex<Queue>>,
    worker: Option<JoinHandle<()>>,
    finished: mpsc::Receiver<()>,
    stopping: bool,
}
impl NativeSourceWatch {
    pub fn new() -> io::Result<Self> {
        // SAFETY: INVALID_HANDLE_VALUE creates a new completion port without associating a file.
        let raw = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 1) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful creation transfers a unique handle to this owner.
        let port = Arc::new(unsafe { OwnedHandle::from_raw_handle(raw) });
        let queue = Arc::new(Mutex::new(Queue {
            events: VecDeque::new(),
            invalidated: VecDeque::new(),
            bytes: 0,
            lost: false,
            signal: None,
        }));
        let (commands, receiver) = mpsc::channel();
        let (finished_sender, finished) = mpsc::channel();
        let worker_port = port.clone();
        let worker_queue = queue.clone();
        let worker = thread::Builder::new()
            .name("source-watch".into())
            .spawn(move || {
                let mut worker = Worker::new(worker_port, worker_queue, receiver);
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker.run())).is_err()
                {
                    worker.fail_all();
                    // A panic does not prove the OS has stopped using these buffers.
                    std::mem::forget(std::mem::take(&mut worker.subscriptions));
                }
                let _ = finished_sender.send(());
            })?;
        Ok(Self {
            port,
            commands,
            queue,
            worker: Some(worker),
            finished,
            stopping: false,
        })
    }
    pub fn set_signal(&self, signal: Signal) -> io::Result<()> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| io::Error::other("watch queue poisoned"))?;
        queue.signal = Some(signal);
        if (queue.lost || !queue.events.is_empty() || !queue.invalidated.is_empty())
            && let Some(signal) = &queue.signal
        {
            signal();
        }
        Ok(())
    }
    fn post(&self, command: Command) -> io::Result<()> {
        self.commands
            .send(command)
            .map_err(|_| io::Error::other("watch worker stopped"))?;
        // SAFETY: the port remains owned; this reserved key carries no overlapped pointer.
        if unsafe { PostQueuedCompletionStatus(self.port.as_raw_handle(), 0, COMMAND, ptr::null()) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn subscribe(
        &self,
        root: &NativeSourceRoot,
        path: &str,
    ) -> io::Result<Option<NativeWatchRegistration>> {
        self.subscribe_impl(root, path, false)
    }
    /// Watch a whole retained source tree with one native recursive request.
    pub fn subscribe_tree(
        &self,
        root: &NativeSourceRoot,
    ) -> io::Result<Option<NativeWatchRegistration>> {
        self.subscribe_impl(root, "", true)
    }
    fn subscribe_impl(
        &self,
        root: &NativeSourceRoot,
        path: &str,
        recursive: bool,
    ) -> io::Result<Option<NativeWatchRegistration>> {
        let Some(directory) = root.open_directory(path)? else {
            return Ok(None);
        };
        let identity = directory.identity.root_key();
        let file = open_async(&root.path.join(path))
            .map_err(|error| watch_error("open watched directory", error))?;
        if !identity.eq(&os::revision(&file, true)
            .map_err(|error| watch_error("inspect watched directory", error))?
            .root_key())
            || !directory.validate_name()?
        {
            return Err(changed("watched directory changed during subscription"));
        }
        let mut ancestors = Vec::new();
        if path.is_empty()
            && let (Some(parent), Some(name)) = (root.path.parent(), root.path.file_name())
        {
            let name = name
                .to_str()
                .ok_or_else(|| invalid("source ancestry encoding"))?;
            let parent_root = NativeSourceRoot::open(parent)
                .map_err(|error| watch_error("open watched ancestor", error))?;
            let parent_pin = parent_root
                .open_directory("")?
                .ok_or_else(|| changed("source ancestor disappeared"))?;
            let parent_file = open_async(parent)
                .map_err(|error| watch_error("open ancestor notification", error))?;
            if !parent_pin.validate_name()?
                || !parent_pin.identity.same_object(
                    &os::revision(&parent_file, true)
                        .map_err(|error| watch_error("inspect watched ancestor", error))?,
                )
            {
                return Err(changed("source ancestor changed during subscription"));
            }
            ancestors.push((parent_file, name.to_owned()));
        }
        let (response, result) = mpsc::channel();
        self.post(Command::Subscribe {
            directory: file,
            identity,
            ancestors,
            recursive,
            response,
        })?;
        let registration = result
            .recv()
            .map_err(|_| io::Error::other("watch worker stopped"))??;
        if !directory.validate_name()? {
            self.remove(registration.descriptor)?;
            return Err(changed("watched directory changed while arming"));
        }
        Ok(Some(registration))
    }
    pub fn remove(&self, id: u32) -> io::Result<bool> {
        let (response, result) = mpsc::channel();
        self.post(Command::Remove { id, response })?;
        result
            .recv()
            .map_err(|_| io::Error::other("watch worker stopped"))?
    }
    /// Process completions already queued before observing the bounded event queue.
    pub fn synchronize(&self, timeout: std::time::Duration) -> io::Result<()> {
        let (response, result) = mpsc::channel();
        self.post(Command::Barrier { response })?;
        result.recv_timeout(timeout).map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => io::Error::new(
                io::ErrorKind::TimedOut,
                "watch completion barrier timed out",
            ),
            mpsc::RecvTimeoutError::Disconnected => io::Error::other("watch worker stopped"),
        })
    }
    pub fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.read_limit(buffer, usize::MAX)
    }
    /// Retain later records in the native queue for a bounded consumer.
    pub fn read_one(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.read_limit(buffer, 1)
    }
    fn read_limit(&self, buffer: &mut [u8], maximum: usize) -> io::Result<usize> {
        if !(4096..=32768).contains(&buffer.len()) {
            return Err(invalid("native watch buffer must be 4096..32768 bytes"));
        }
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| io::Error::other("watch queue poisoned"))?;
        if let Some(id) = queue.invalidated.pop_front() {
            buffer[..12].fill(0);
            buffer[..4].copy_from_slice(&id.to_le_bytes());
            buffer[4] = 4;
            if (queue.lost || !queue.events.is_empty() || !queue.invalidated.is_empty())
                && let Some(signal) = &queue.signal
            {
                signal();
            }
            return Ok(12);
        }
        if queue.lost {
            queue.lost = false;
            buffer[..12].fill(0);
            buffer[4] = 5;
            return Ok(12);
        }
        let mut used = 0;
        let mut records = 0;
        while let Some(event) = queue.events.front() {
            if records == maximum || used + event.len() > buffer.len() {
                break;
            }
            let event = queue
                .events
                .pop_front()
                .ok_or_else(|| io::Error::other("watch queue changed"))?;
            buffer[used..used + event.len()].copy_from_slice(&event);
            used += event.len();
            queue.bytes -= event.len();
            records += 1;
        }
        if !queue.events.is_empty()
            && let Some(signal) = &queue.signal
        {
            signal();
        }
        Ok(used)
    }
    pub fn observed_limit() -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows does not expose an aggregate watch limit",
        ))
    }
    /// Retire the exact worker without holding an unbounded shutdown.
    pub fn shutdown(&mut self, timeout: std::time::Duration) -> io::Result<()> {
        if self.worker.is_none() {
            return Ok(());
        }
        if !self.stopping {
            self.post(Command::Stop)?;
            self.stopping = true;
        }
        self.finished
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "source watch cancellation is still pending",
                ),
                mpsc::RecvTimeoutError::Disconnected => {
                    io::Error::other("source watch worker stopped without a completion receipt")
                }
            })?;
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("source watch worker panicked"))?;
        }
        Ok(())
    }
}
fn watch_error(action: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{action}: {error}"))
}

fn open_async(path: &std::path::Path) -> io::Result<File> {
    let name = se_state_files::state_files::windows::wide(path)
        .map_err(|_| invalid("normalized absolute watched directory required"))?;
    // SAFETY: the terminated path is opened without following its final reparse point.
    // The caller verifies the resulting identity against the retained directory pin.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful native open transfers an owned handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}
impl Drop for NativeSourceWatch {
    fn drop(&mut self) {
        if !self.stopping
            && self.worker.is_some()
            && self.shutdown(std::time::Duration::from_secs(2)).is_err()
        {
            eprintln!("source watch worker could not be stopped");
        }
    }
}

struct Subscription {
    file: File,
    overlapped: OVERLAPPED,
    buffer: Box<[u32; BUFFER / 4]>,
    active: bool,
    sentinel: Option<(u32, String)>,
    recursive: bool,
}
struct Worker {
    port: Arc<OwnedHandle>,
    queue: Arc<Mutex<Queue>>,
    commands: mpsc::Receiver<Command>,
    subscriptions: HashMap<u32, Box<Subscription>>,
    companions: HashMap<u32, Vec<u32>>,
    next: u32,
    stopping: bool,
}
impl Worker {
    fn new(
        port: Arc<OwnedHandle>,
        queue: Arc<Mutex<Queue>>,
        commands: mpsc::Receiver<Command>,
    ) -> Self {
        Self {
            port,
            queue,
            commands,
            subscriptions: HashMap::new(),
            companions: HashMap::new(),
            next: 1,
            stopping: false,
        }
    }
    fn lose(&self) {
        if let Ok(mut q) = self.queue.lock() {
            q.lost();
        }
    }
    fn fail_all(&self) {
        self.lose();
        for (&id, item) in &self.subscriptions {
            if item.active && item.sentinel.is_none() {
                self.invalidate(id);
            }
        }
    }
    fn run(&mut self) {
        loop {
            if self.stopping && self.subscriptions.is_empty() {
                break;
            }
            let (mut count, mut key, mut overlap) = (0, 0, ptr::null_mut());
            // SAFETY: owned port and writable completion result fields remain valid during the wait.
            let ok = unsafe {
                GetQueuedCompletionStatus(
                    self.port.as_raw_handle(),
                    &mut count,
                    &mut key,
                    &mut overlap,
                    u32::MAX,
                )
            };
            if key == COMMAND && overlap.is_null() {
                self.commands();
                continue;
            }
            if overlap.is_null() {
                self.fail_all();
                // Outstanding overlapped buffers may still be owned by the OS.
                // A broken port cannot prove completion; retain them instead of
                // freeing memory that the kernel may still write.
                std::mem::forget(std::mem::take(&mut self.subscriptions));
                break;
            }
            let Ok(id) = u32::try_from(key) else {
                self.lose();
                continue;
            };
            let Some(mut item) = self.subscriptions.remove(&id) else {
                self.lose();
                continue;
            };
            if !item.active {
                continue;
            }
            if ok == 0 {
                self.lose();
                self.invalidate(item.sentinel.as_ref().map_or(id, |(owner, _)| *owner));
                continue;
            } else if count == 0
                || count as usize > BUFFER
                || self.decode_completion(id, &item, count).is_err()
            {
                self.lose();
            }
            if !self.stopping && Self::arm(&mut item).is_ok() {
                self.subscriptions.insert(id, item);
            } else if !self.stopping {
                self.lose();
                self.invalidate(item.sentinel.as_ref().map_or(id, |(owner, _)| *owner));
            }
        }
    }
    fn invalidate(&self, id: u32) {
        if let Ok(mut queue) = self.queue.lock() {
            if !queue.invalidated.contains(&id) {
                queue.invalidated.push_back(id);
            }
            if let Some(signal) = &queue.signal {
                signal();
            }
        }
    }
    fn commands(&mut self) {
        if let Ok(command) = self.commands.try_recv() {
            match command {
                Command::Subscribe {
                    directory,
                    identity,
                    ancestors,
                    recursive,
                    response,
                } => {
                    let result = self.subscribe(directory, identity, ancestors, recursive);
                    let _ = response.send(result);
                }
                Command::Remove { id, response } => {
                    let result = self.remove(id);
                    let _ = response.send(result);
                }
                Command::Barrier { response } => {
                    let _ = response.send(());
                }
                Command::Stop => {
                    self.stopping = true;
                    for item in self.subscriptions.values_mut() {
                        item.active = false;
                        let _ = Self::cancel(item);
                    }
                }
            }
        }
    }
    fn subscribe(
        &mut self,
        file: File,
        identity: [u8; 32],
        ancestors: Vec<(File, String)>,
        recursive: bool,
    ) -> io::Result<NativeWatchRegistration> {
        if self.stopping
            || self.subscriptions.len().saturating_add(ancestors.len() + 1) > MAX_WATCHES
        {
            return Err(io::Error::other("Windows source watch capacity exhausted"));
        }
        let id = self.add(file, None, recursive)?;
        self.companions.insert(id, Vec::new());
        for (file, name) in ancestors {
            match self.add(file, Some((id, name)), false) {
                Ok(child) => self
                    .companions
                    .get_mut(&id)
                    .ok_or_else(|| io::Error::other("missing watch ancestry"))?
                    .push(child),
                Err(error) => {
                    let _ = self.remove(id);
                    return Err(error);
                }
            }
        }
        Ok(NativeWatchRegistration {
            descriptor: id,
            physical_directory: identity,
        })
    }
    fn add(
        &mut self,
        file: File,
        sentinel: Option<(u32, String)>,
        recursive: bool,
    ) -> io::Result<u32> {
        let id = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("watch identifier exhausted"))?;
        // SAFETY: retained handle and owned completion port, with a bounded key identifying this subscription.
        if unsafe {
            CreateIoCompletionPort(
                file.as_raw_handle(),
                self.port.as_raw_handle(),
                id as usize,
                0,
            )
        }
        .is_null()
        {
            return Err(io::Error::last_os_error());
        }
        let mut item = Box::new(Subscription {
            file,
            overlapped: OVERLAPPED::default(),
            buffer: Box::new([0; BUFFER / 4]),
            active: true,
            sentinel,
            recursive,
        });
        Self::arm(&mut item)?;
        self.subscriptions.insert(id, item);
        Ok(id)
    }
    fn remove(&mut self, id: u32) -> io::Result<bool> {
        let mut all = self.companions.remove(&id).unwrap_or_default();
        all.push(id);
        let mut found = false;
        let mut error = None;
        for id in all {
            if let Some(item) = self.subscriptions.get_mut(&id)
                && item.active
            {
                item.active = false;
                found = true;
                if let Err(failure) = Self::cancel(item) {
                    error.get_or_insert(failure);
                }
            }
        }
        error.map_or(Ok(found), Err)
    }
    fn arm(item: &mut Subscription) -> io::Result<()> {
        // This operation's preceding completion was removed before re-arming.
        item.overlapped = OVERLAPPED::default();
        // SAFETY: the boxed OVERLAPPED and buffer stay allocated until the completion is removed from the port.
        let ok = unsafe {
            ReadDirectoryChangesW(
                item.file.as_raw_handle(),
                item.buffer.as_mut_ptr().cast(),
                BUFFER as u32,
                i32::from(item.recursive),
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_ATTRIBUTES
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE
                    | FILE_NOTIFY_CHANGE_SECURITY
                    | FILE_NOTIFY_CHANGE_CREATION,
                ptr::null_mut(),
                &mut item.overlapped,
                None,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error);
            }
        }
        Ok(())
    }
    fn cancel(item: &Subscription) -> io::Result<()> {
        // SAFETY: the operation's retained handle and OVERLAPPED stay alive until completion.
        if unsafe { CancelIoEx(item.file.as_raw_handle(), &item.overlapped) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
                return Err(error);
            }
        }
        Ok(())
    }
}
