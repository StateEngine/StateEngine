use super::*;
use windows_sys::Win32::System::IO::OVERLAPPED;

pub(crate) struct Budget {
    limit: u64,
    used: AtomicU64,
}
impl Budget {
    pub fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicU64::new(0),
        })
    }
    pub(super) fn charge(self: &Arc<Self>, bytes: usize) -> ProcResult<Charge> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes as u64)
                    .filter(|next| *next <= self.limit)
            })
            .map_err(|_| capacity("host provider stream buffers", self.limit))?;
        Ok(Charge {
            budget: self.clone(),
            bytes,
        })
    }
}
pub(super) struct Charge {
    budget: Arc<Budget>,
    bytes: usize,
}
impl Drop for Charge {
    fn drop(&mut self) {
        self.budget
            .used
            .fetch_sub(self.bytes as u64, Ordering::AcqRel);
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Read(StdioReadStream),
    Write,
    Connect(usize),
    Close(StdioCloseScope),
}
#[derive(Clone, Copy)]
pub(super) enum Status {
    Pending,
    Done { bytes: u32, code: u32 },
    Taken,
}
pub(super) struct Operation {
    pub overlapped: OVERLAPPED,
    pub kind: Kind,
    pub bytes: Vec<u8>,
    pub charge: Option<Charge>,
    pub status: Status,
    pub close_error: Option<NativeFailure>,
}
// SAFETY: each box has a stable address; its mutex serializes host/kernel
// submission/completion and the box stays retained until the due IOCP packet.
unsafe impl Send for Operation {}
impl Operation {
    pub fn new(kind: Kind, bytes: Vec<u8>, charge: Option<Charge>) -> Box<Self> {
        // SAFETY: zero OVERLAPPED uses the completion port, with no event handle.
        Box::new(Self {
            // SAFETY: zero initialization selects the IOCP and no event handle.
            overlapped: unsafe { std::mem::zeroed() },
            kind,
            bytes,
            charge,
            status: Status::Pending,
            close_error: None,
        })
    }
    pub fn address(&mut self) -> usize {
        (&raw mut self.overlapped) as usize
    }
    pub fn pending(&self) -> bool {
        matches!(self.status, Status::Pending)
    }
}
pub(super) struct State {
    pub identity: StdioIdentity,
    pub limits: StdioLimits,
    pub binding: Arc<binding::Binding>,
    pub old_binding: Option<Arc<binding::Binding>>,
    pub binding_serial: u64,
    pub bound: bool,
    pub handles: [Option<Handle>; 3],
    pub operations: BTreeMap<u64, Box<Operation>>,
    pub next: u64,
    pub notices: BTreeSet<u64>,
    pub binding_notice: bool,
    pub close: Option<u64>,
    pub write_gated: bool,
    pub all_gated: bool,
    pub released: bool,
    pub abandoned: bool,
    pub failure: Option<ProcError>,
}
impl State {
    pub fn new(config: &StdioConfig) -> Self {
        Self {
            identity: config.identity.clone(),
            limits: config.limits,
            binding: binding::Binding::new(config),
            old_binding: None,
            binding_serial: 1,
            bound: true,
            handles: [None, None, None],
            operations: BTreeMap::new(),
            next: 1,
            notices: BTreeSet::new(),
            binding_notice: false,
            close: None,
            write_gated: false,
            all_gated: false,
            released: false,
            abandoned: false,
            failure: None,
        }
    }
    pub fn binding_state(&self) -> StdioBinding {
        if self
            .old_binding
            .as_ref()
            .is_some_and(|binding| binding.draining())
        {
            StdioBinding::Draining
        } else if self.bound {
            StdioBinding::Ready
        } else {
            StdioBinding::Unbound
        }
    }
    pub fn ready(&self) -> ProcResult<()> {
        if self.released || self.abandoned {
            return Err(transition("port has been released"));
        }
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        if self.binding_state() != StdioBinding::Ready {
            return Err(transition("prior binding is draining"));
        }
        Ok(())
    }
    pub fn next_id(&mut self) -> ProcResult<u64> {
        let id = self.next;
        self.next = id
            .checked_add(1)
            .ok_or_else(|| capacity("stream operation identifiers", u64::MAX))?;
        Ok(id)
    }
    pub fn retained_bytes(&self) -> usize {
        self.operations.values().map(|op| op.bytes.capacity()).sum()
    }
    pub fn native_pending(&self) -> bool {
        self.operations
            .values()
            .any(|op| op.pending() && !matches!(op.kind, Kind::Close(_)))
    }
    pub fn check_limits(&self, limits: StdioLimits) -> ProcResult<()> {
        if limits.max_read_bytes == 0 || limits.max_write_bytes == 0 || limits.max_buffer_bytes == 0
        {
            return Err(input("stdio limits", "positive byte limits required"));
        }
        if self.retained_bytes() > limits.max_buffer_bytes as usize
            || self.operations.values().any(|op| match op.kind {
                Kind::Read(_) => op.bytes.capacity() > limits.max_read_bytes as usize,
                Kind::Write => op.bytes.capacity() > limits.max_write_bytes as usize,
                _ => false,
            })
        {
            return Err(capacity(
                "retained provider stream buffers",
                limits.max_buffer_bytes as u64,
            ));
        }
        Ok(())
    }
}
pub(super) fn transition(reason: &str) -> ProcError {
    error(
        ProcErrorCode::IllegalTransition,
        ProcErrorDetail::Input {
            field: "provider stdio".into(),
            reason: reason.into(),
        },
    )
}
pub(super) fn failure(api: &str, code: u32) -> NativeFailure {
    NativeFailure {
        api: api.into(),
        code: Some(code as i64),
        reason: std::io::Error::from_raw_os_error(code as i32).to_string(),
    }
}
