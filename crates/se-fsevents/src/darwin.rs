//! Bounded macOS file notifications. The operating system owns event delivery;
//! this port owns every stream, callback context and queued record.
use std::{
    collections::VecDeque,
    ffi::{CStr, CString, c_char, c_void},
    io, ptr,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

const MAX_QUEUE: usize = 16_384;
const MAX_STREAMS: usize = 3;
const FILE_EVENTS: u32 = 0x10;
const WATCH_ROOT: u32 = 0x04;
const NO_DEFER: u32 = 0x02;
const LOST: u32 = 0x0f;
const ROOT_OR_MOUNT: u32 = 0xe0;
const REMOVED_OR_RENAMED: u32 = 0x0a00;
const IS_DIRECTORY: u32 = 0x0002_0000;
const UTF8: u32 = 0x0800_0100;
type Raw = *mut c_void;
type Signal = Arc<dyn Fn() + Send + Sync>;

#[repr(C)]
struct StreamContext {
    version: isize,
    info: Raw,
    retain: Option<unsafe extern "C" fn(Raw) -> Raw>,
    release: Option<unsafe extern "C" fn(Raw)>,
    describe: Option<unsafe extern "C" fn(Raw) -> Raw>,
}
type Callback = unsafe extern "C" fn(Raw, Raw, usize, Raw, *const u32, *const u64);

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeArrayCallBacks: u8;
    fn CFStringCreateWithCString(allocator: Raw, string: *const c_char, encoding: u32) -> Raw;
    fn CFArrayCreate(
        allocator: Raw,
        values: *const Raw,
        count: isize,
        callbacks: *const c_void,
    ) -> Raw;
    fn CFRelease(value: Raw);
}
#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: Raw,
        callback: Callback,
        context: *mut StreamContext,
        paths: Raw,
        since: u64,
        latency: f64,
        flags: u32,
    ) -> Raw;
    fn FSEventStreamSetDispatchQueue(stream: Raw, queue: Raw);
    fn FSEventStreamStart(stream: Raw) -> u8;
    fn FSEventStreamStop(stream: Raw);
    fn FSEventStreamInvalidate(stream: Raw);
    fn FSEventStreamRelease(stream: Raw);
}
unsafe extern "C" {
    fn dispatch_queue_create(label: *const c_char, attributes: Raw) -> Raw;
    fn dispatch_async_f(queue: Raw, context: Raw, work: unsafe extern "C" fn(Raw));
    fn dispatch_sync_f(queue: Raw, context: Raw, work: unsafe extern "C" fn(Raw));
    fn dispatch_release(object: Raw);
}

struct Queue {
    records: VecDeque<Vec<u8>>,
    bytes: usize,
    lost: bool,
    signal: Option<Signal>,
}
impl Queue {
    fn loss(&mut self) -> Option<Signal> {
        self.records.clear();
        self.bytes = 0;
        self.lost = true;
        self.signal.clone()
    }
    fn push(&mut self, id: u32, action: u8, directory: bool, name: &[u8]) -> Option<Signal> {
        if self.lost {
            return self.signal.clone();
        }
        if name.len() > 4084 || self.bytes.saturating_add(12 + name.len()) > MAX_QUEUE {
            return self.loss();
        }
        let mut record = vec![0; 12 + name.len()];
        record[..4].copy_from_slice(&id.to_le_bytes());
        record[4] = action;
        record[5] = u8::from(directory);
        record[8..12].copy_from_slice(&(name.len() as u32).to_le_bytes());
        record[12..].copy_from_slice(name);
        self.bytes += record.len();
        self.records.push_back(record);
        self.signal.clone()
    }
}
struct Context {
    id: u32,
    root: std::path::PathBuf,
    queue: Arc<Mutex<Queue>>,
}
struct Stream {
    stream: Raw,
    context: *mut Context,
}
// SAFETY: each stream is touched only while the owner's mutex is held; its
// callback executes on the single retained serial dispatch queue.
unsafe impl Send for Stream {}
struct State {
    next: u32,
    streams: Vec<Stream>,
}
struct Dispatch(Raw);
// SAFETY: libdispatch queues are thread-safe and remain retained by this owner.
unsafe impl Send for Dispatch {}
// SAFETY: libdispatch serializes callbacks and synchronization operations.
unsafe impl Sync for Dispatch {}

pub struct Watcher {
    queue: Arc<Mutex<Queue>>,
    dispatch: Dispatch,
    state: Mutex<State>,
}
impl Watcher {
    pub fn new() -> io::Result<Self> {
        // SAFETY: a static terminated label and NULL attributes create one serial queue.
        let dispatch =
            unsafe { dispatch_queue_create(c"stateengine.source-watch".as_ptr(), ptr::null_mut()) };
        if dispatch.is_null() {
            return Err(io::Error::other("cannot create source watch queue"));
        }
        Ok(Self {
            queue: Arc::new(Mutex::new(Queue {
                records: VecDeque::new(),
                bytes: 0,
                lost: false,
                signal: None,
            })),
            dispatch: Dispatch(dispatch),
            state: Mutex::new(State {
                next: 1,
                streams: Vec::new(),
            }),
        })
    }
    pub fn set_signal(&self, signal: Signal) -> io::Result<()> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| io::Error::other("watch queue poisoned"))?;
        let pending = queue.lost || !queue.records.is_empty();
        queue.signal = Some(signal.clone());
        drop(queue);
        if pending {
            signal();
        }
        Ok(())
    }
    pub fn subscribe_tree(&self, root: &std::path::Path) -> io::Result<u32> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("watch state poisoned"))?;
        if state.streams.len() >= MAX_STREAMS {
            return Err(io::Error::other("source watch capacity exhausted"));
        }
        let id = state.next;
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("source watch identifier overflow"))?;
        let root = std::fs::canonicalize(root)?; // match FSEvents' canonical paths
        let path = CString::new(root.as_os_str().as_encoded_bytes())
            .map_err(|_| invalid("source path encoding"))?;
        let context = Box::into_raw(Box::new(Context {
            id,
            root,
            queue: self.queue.clone(),
        }));
        // SAFETY: path is NUL-terminated; returned Core Foundation objects are retained.
        let string = unsafe { CFStringCreateWithCString(ptr::null_mut(), path.as_ptr(), UTF8) };
        if string.is_null() {
            // SAFETY: no stream was created and this is the unique context allocation.
            unsafe {
                drop(Box::from_raw(context));
            }
            return Err(invalid("source path is not valid UTF-8"));
        }
        // SAFETY: the array retains its one CFString using the standard callbacks.
        let paths = unsafe {
            CFArrayCreate(
                ptr::null_mut(),
                &string,
                1,
                ptr::addr_of!(kCFTypeArrayCallBacks).cast(),
            )
        };
        // SAFETY: the string's original retain is no longer needed.
        unsafe {
            CFRelease(string);
        }
        if paths.is_null() {
            // SAFETY: no stream was created and this is the unique context allocation.
            unsafe {
                drop(Box::from_raw(context));
            }
            return Err(io::Error::other("cannot allocate source watch paths"));
        }
        let mut native_context = StreamContext {
            version: 0,
            info: context.cast(),
            retain: None,
            release: None,
            describe: None,
        };
        // SAFETY: paths and context are valid for creation; the stream copies its context.
        let stream = unsafe {
            FSEventStreamCreate(
                ptr::null_mut(),
                callback,
                &mut native_context,
                paths,
                u64::MAX,
                0.05,
                FILE_EVENTS | WATCH_ROOT | NO_DEFER,
            )
        };
        // SAFETY: creation has consumed the path array; this releases our retain.
        unsafe {
            CFRelease(paths);
        }
        if stream.is_null() {
            // SAFETY: no stream owns this context.
            unsafe {
                drop(Box::from_raw(context));
            }
            return Err(io::Error::other("cannot create source watch stream"));
        }
        // SAFETY: both handles are live and the serial queue stays retained by the owner.
        unsafe {
            FSEventStreamSetDispatchQueue(stream, self.dispatch.0);
        }
        // SAFETY: the stream is scheduled on its retained queue before start.
        if unsafe { FSEventStreamStart(stream) } == 0 {
            // SAFETY: invalidation and release retire the failed scheduled stream.
            unsafe {
                FSEventStreamInvalidate(stream);
                FSEventStreamRelease(stream);
                drop(Box::from_raw(context));
            }
            return Err(io::Error::other("cannot start source watch stream"));
        }
        state.streams.push(Stream { stream, context });
        Ok(id)
    }
    pub fn synchronize(&self, timeout: Duration) -> io::Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let context = Box::into_raw(Box::new(sender));
        // SAFETY: the queue remains retained and the callback owns this allocation.
        unsafe {
            dispatch_async_f(self.dispatch.0, context.cast(), complete_barrier);
        }
        receiver.recv_timeout(timeout).map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => {
                io::Error::new(io::ErrorKind::TimedOut, "source watch barrier timed out")
            }
            mpsc::RecvTimeoutError::Disconnected => {
                io::Error::other("source watch barrier stopped")
            }
        })
    }
    pub fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        if !(4096..=32768).contains(&buffer.len()) {
            return Err(invalid("native watch buffer must be 4096..32768 bytes"));
        }
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| io::Error::other("watch queue poisoned"))?;
        if queue.lost {
            queue.lost = false;
            buffer[..12].fill(0);
            buffer[4] = 5;
            return Ok(12);
        }
        let mut used = 0;
        while let Some(record) = queue.records.front() {
            if used + record.len() > buffer.len() {
                break;
            }
            let record = queue
                .records
                .pop_front()
                .ok_or_else(|| io::Error::other("watch queue changed"))?;
            buffer[used..used + record.len()].copy_from_slice(&record);
            used += record.len();
            queue.bytes -= record.len();
        }
        let signal = queue.records.front().and_then(|_| queue.signal.clone());
        drop(queue);
        if let Some(signal) = signal {
            signal();
        }
        Ok(used)
    }
}
unsafe extern "C" fn barrier(_: Raw) {}

unsafe extern "C" fn complete_barrier(context: Raw) {
    // SAFETY: the dispatch callback uniquely owns the boxed sender, even after timeout.
    let sender = unsafe { Box::from_raw(context.cast::<mpsc::SyncSender<()>>()) };
    let _ = sender.send(());
}

unsafe extern "C" fn callback(
    _: Raw,
    info: Raw,
    count: usize,
    paths: Raw,
    flags: *const u32,
    _: *const u64,
) {
    let _ = run_no_unwind(|| {
        // SAFETY: the context is held until invalidation and the serial queue barrier.
        let context = unsafe { &*(info.cast::<Context>()) };
        let result = run_no_unwind(|| {
            let Ok(mut queue) = context.queue.lock() else {
                return None;
            };
            if count > 128 || paths.is_null() || flags.is_null() {
                queue.loss()
            } else {
                // SAFETY: FSEvents supplies count valid paths and flags for this callback.
                let names =
                    unsafe { std::slice::from_raw_parts(paths.cast::<*const c_char>(), count) };
                // SAFETY: FSEvents supplies count flags for this callback.
                let flags = unsafe { std::slice::from_raw_parts(flags, count) };
                let mut notify = None;
                for (&name, &flags) in names.iter().zip(flags) {
                    if flags & LOST != 0 {
                        notify = queue.loss();
                        break;
                    }
                    if flags & 0x10 != 0 {
                        continue;
                    }
                    if flags & ROOT_OR_MOUNT != 0 || name.is_null() {
                        notify = queue.push(context.id, 4, false, b"").or(notify);
                        continue;
                    }
                    // SAFETY: FSEvents supplies each path as a NUL-terminated string.
                    let path = unsafe { CStr::from_ptr(name) };
                    let Some(rel) = std::str::from_utf8(path.to_bytes())
                        .ok()
                        .and_then(|p| std::path::Path::new(p).strip_prefix(&context.root).ok())
                        .and_then(|r| r.to_str())
                    else {
                        notify = queue.loss();
                        break;
                    };
                    let a = u8::from(flags & REMOVED_OR_RENAMED != 0);
                    let d = flags & IS_DIRECTORY != 0;
                    notify = queue.push(context.id, a, d, rel.as_bytes()).or(notify);
                }
                notify
            }
        });
        match result {
            Some(Some(s)) if run_no_unwind(|| s()).is_none() => {
                let _ = run_no_unwind(|| context.queue.lock().ok().map(|mut q| q.loss()));
            }
            None => {
                let _ = run_no_unwind(|| {
                    if let Some(s) = context.queue.lock().ok().and_then(|mut q| q.loss()) {
                        s();
                    }
                });
            }
            _ => {}
        }
    });
}
fn run_no_unwind<T>(f: impl FnOnce() -> T) -> Option<T> {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    catch_unwind(AssertUnwindSafe(f))
        .map_err(|p| {
            let _ = catch_unwind(AssertUnwindSafe(move || drop(p))).map_err(std::mem::forget);
        })
        .ok()
}
impl Drop for Watcher {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        for stream in &state.streams {
            // SAFETY: streams are scheduled, owned, and retired before their contexts.
            unsafe {
                FSEventStreamStop(stream.stream);
                FSEventStreamInvalidate(stream.stream);
            }
        }
        // SAFETY: callbacks scheduled before invalidation finish before the barrier returns.
        unsafe { dispatch_sync_f(self.dispatch.0, ptr::null_mut(), barrier) };
        for stream in state.streams.drain(..) {
            // SAFETY: no callback can use these unique stream and context allocations now.
            unsafe {
                FSEventStreamRelease(stream.stream);
                drop(Box::from_raw(stream.context));
            }
        }
        // SAFETY: all streams are retired; this releases the queue's owned reference.
        unsafe { dispatch_release(self.dispatch.0) };
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
