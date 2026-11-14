//! Native recursive change notifications, reduced to one bounded reactor wake.
use std::{
    ffi::c_void,
    io,
    os::unix::{ffi::OsStrExt, net::UnixDatagram},
    path::Path,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
type Ref = *const c_void;
#[repr(C)]
struct Context {
    version: isize,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(Ref) -> Ref>,
    release: Option<unsafe extern "C" fn(Ref)>,
    description: Option<unsafe extern "C" fn(Ref) -> Ref>,
}
#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: Ref,
        callback: unsafe extern "C" fn(
            Ref,
            *mut c_void,
            usize,
            *mut c_void,
            *const u32,
            *const u64,
        ),
        context: *mut Context,
        paths: Ref,
        since: u64,
        latency: f64,
        flags: u32,
    ) -> Ref;
    fn FSEventStreamSetDispatchQueue(stream: Ref, queue: *mut c_void);
    fn FSEventStreamStart(stream: Ref) -> u8;
    fn FSEventStreamStop(stream: Ref);
    fn FSEventStreamInvalidate(stream: Ref);
    fn FSEventStreamRelease(stream: Ref);
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(
        allocator: Ref,
        bytes: *const u8,
        count: isize,
        encoding: u32,
        external: u8,
    ) -> Ref;
    fn CFArrayCreate(allocator: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
    fn CFRelease(object: Ref);
}
unsafe extern "C" {
    fn dispatch_queue_create(label: *const libc::c_char, attributes: Ref) -> *mut c_void;
    fn dispatch_sync_f(
        queue: *mut c_void,
        context: *mut c_void,
        work: unsafe extern "C" fn(*mut c_void),
    );
    fn dispatch_release(object: *mut c_void);
}
pub(crate) struct Signal {
    pub socket: UnixDatagram,
    pub pending: Arc<AtomicBool>,
    pub lost: Arc<AtomicBool>,
}
pub(crate) struct Stream {
    stream: Ref,
    queue: *mut c_void,
    path: Ref,
    paths: Ref,
    started: bool,
    _signal: Box<Signal>,
}
// SAFETY: the owner serializes stream operations. The callback touches only its
// owned socket/atomics, and drop joins the serial callback queue before release.
unsafe impl Send for Stream {}
unsafe extern "C" fn notified(
    _: Ref,
    info: *mut c_void,
    count: usize,
    _: *mut c_void,
    flags: *const u32,
    _: *const u64,
) {
    // SAFETY: Stream retains this box until its stopped callback queue is joined.
    let signal = unsafe { &*info.cast::<Signal>() };
    if count == 0 {
        return;
    }
    // Native event loss, root movement and wrapped IDs all require a fresh scan.
    let mut lost = count > 4096;
    for index in 0..count.min(4096) {
        // SAFETY: the native callback supplies count flags for this invocation.
        let value = unsafe { *flags.add(index) };
        lost |= value & (0x2 | 0x4 | 0x8 | 0x20 | 0x40 | 0x80) != 0;
    }
    if lost {
        signal.lost.store(true, Ordering::Release);
    }
    if !signal.pending.swap(true, Ordering::AcqRel) && signal.socket.send(&[1]).is_err() {
        signal.lost.store(true, Ordering::Release);
    }
}
unsafe extern "C" fn drained(_: *mut c_void) {}
impl Stream {
    pub(crate) fn new(path: &Path, signal: Signal) -> io::Result<Self> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() > 4096 || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bounded native watch path required",
            ));
        }
        let mut result = Self {
            stream: ptr::null(),
            queue: ptr::null_mut(),
            path: ptr::null(),
            paths: ptr::null(),
            started: false,
            _signal: Box::new(signal),
        };
        // SAFETY: bounded path bytes, UTF-8 encoding; the objects remain retained
        // until the stream and its callback queue have both stopped.
        unsafe {
            result.path = CFStringCreateWithBytes(
                ptr::null(),
                bytes.as_ptr(),
                bytes.len() as isize,
                0x0800_0100,
                0,
            );
            if result.path.is_null() {
                return Err(io::Error::other("native watch path is not UTF-8"));
            }
            result.paths = CFArrayCreate(ptr::null(), &result.path, 1, ptr::null());
            if result.paths.is_null() {
                return Err(io::Error::other(
                    "native watch path array allocation failed",
                ));
            }
            result.queue = dispatch_queue_create(c"source-change-events".as_ptr(), ptr::null());
            if result.queue.is_null() {
                return Err(io::Error::other("native watch queue allocation failed"));
            }
            let mut context = Context {
                version: 0,
                info: ptr::from_mut(result._signal.as_mut()).cast(),
                retain: None,
                release: None,
                description: None,
            };
            // SinceNow, NoDefer and WatchRoot. Directory-level events cover
            // recursive file-content changes; paths are advisory, never IO authority.
            result.stream = FSEventStreamCreate(
                ptr::null(),
                notified,
                &mut context,
                result.paths,
                u64::MAX,
                0.05,
                0x2 | 0x4,
            );
            if result.stream.is_null() {
                return Err(io::Error::other(
                    "native source event stream creation failed",
                ));
            }
            FSEventStreamSetDispatchQueue(result.stream, result.queue);
            result.started = FSEventStreamStart(result.stream) != 0;
        }
        if !result.started {
            return Err(io::Error::other(
                "native source event stream refused to start",
            ));
        }
        Ok(result)
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: owned objects, serialized lifecycle. Joining the callback queue
        // after invalidation prevents callbacks from outliving their boxed context.
        unsafe {
            if !self.stream.is_null() {
                if self.started {
                    FSEventStreamStop(self.stream);
                }
                FSEventStreamInvalidate(self.stream);
                dispatch_sync_f(self.queue, ptr::null_mut(), drained);
                FSEventStreamRelease(self.stream);
            }
            if !self.queue.is_null() {
                dispatch_release(self.queue);
            }
            if !self.paths.is_null() {
                CFRelease(self.paths);
            }
            if !self.path.is_null() {
                CFRelease(self.path);
            }
        }
    }
}
