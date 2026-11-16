//! The marker grants no authority: only inherited objects and the live native
//! creator can participate, and deletion still needs its private authorization.
use super::*;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    parent: u64,
    claim: u64,
    authorize: u64,
    ready: u64,
    report: u64,
    nonce: String,
    deadline: u64,
    cleanup_pipe: String,
    entries: Vec<Object>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Object {
    handle: u64,
    pub(super) path: PathBuf,
    pub(super) kind: String,
    identity: String,
    sha256: Option<String>,
}
pub(super) struct Held {
    pub(super) object: Object,
    pub(super) file: File,
}
fn duplicate(raw: u64) -> Result<OwnedHandle> {
    let raw = usize::try_from(raw)
        .map_err(|_| refuse("admit carrier handle", "handle exceeds native width"))?;
    native::duplicate_same(raw as HANDLE, false)
}
fn read_json<T: serde::de::DeserializeOwned>(file: &mut File) -> Result<T> {
    // Envelopes are anonymous file objects, never a blocking caller pipe.
    // SAFETY: retained native handle; immutable type query.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(refuse(
            "read carrier envelope",
            "private disk file required",
        ));
    }
    file.rewind()
        .map_err(|e| error("rewind carrier envelope", e))?;
    let mut bytes = Vec::new();
    file.take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| error("read carrier envelope", e))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(refuse("read carrier envelope", "two MiB bound exceeded"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| error("decode carrier envelope", io::Error::other(e)))
}
fn live_parent(parent: &OwnedHandle) -> Result<()> {
    let current = native::current_process()?;
    // SAFETY: retained process handles from native duplication.
    let (pid, parent_pid) = unsafe {
        (
            GetProcessId(current.as_raw_handle()),
            GetProcessId(parent.as_raw_handle()),
        )
    };
    let creator = crate::windows_native::parent(current.as_raw_handle(), pid)
        .map_err(|e| error(e.operation, e.source))?;
    let creator = match creator {
        Some(pid) => Some(pid),
        None => crate::windows_native::parents()
            .map_err(|e| error(e.operation, e.source))?
            .get(&pid)
            .copied(),
    };
    if parent_pid == 0 || creator != Some(parent_pid) || native::exited(parent)? {
        return Err(refuse(
            "admit carrier creator",
            "exact live native creator required",
        ));
    }
    Ok(())
}
fn nonce(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refuse(
            "admit carrier nonce",
            "canonical private nonce required",
        ));
    }
    let mut nonce = [0; 32];
    for (index, byte) in nonce.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| refuse("admit carrier nonce", "invalid hex"))?;
    }
    Ok(nonce)
}
fn remaining(deadline: u64) -> Result<u32> {
    let remaining = deadline.saturating_sub(clock());
    if remaining == 0 || remaining > 90000 {
        return Err(refuse(
            "admit carrier deadline",
            "deadline expired or invalid",
        ));
    }
    Ok(remaining as u32)
}
impl Held {
    pub(super) fn verify(&mut self) -> Result<()> {
        let directory = matches!(self.object.kind.as_str(), "directory" | "flush");
        let identity = super::entry_effects::identity(&self.file, directory)?;
        if identity != self.object.identity {
            return Err(refuse(
                "admit carrier object",
                "original native identity differs",
            ));
        }
        if !directory
            && self.object.sha256.as_deref()
                != Some(&se_types::hex_lower(&native::digest(&mut self.file)?))
        {
            return Err(refuse(
                "admit carrier object",
                "original object bytes differ",
            ));
        }
        Ok(())
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    nonce: String,
    report: serde_json::Value,
}
fn admit_objects(entries: Vec<Object>, parent: &OwnedHandle) -> Result<Vec<Held>> {
    if !(5..=133).contains(&entries.len()) {
        return Err(refuse(
            "admit carrier objects",
            "finite inventory bound required",
        ));
    }
    let mut objects = Vec::new();
    for object in entries {
        if !matches!(
            object.kind.as_str(),
            "image" | "record" | "carrier" | "directory" | "flush"
        ) {
            return Err(refuse("admit carrier object", "unknown object kind"));
        }
        let file = File::from(duplicate(object.handle)?);
        let mut held = Held { object, file };
        held.verify()?;
        objects.push(held);
    }
    for kind in ["image", "record", "carrier"] {
        if objects.iter().filter(|o| o.object.kind == kind).count() != 1 {
            return Err(refuse(
                "admit carrier objects",
                "one original image and record required",
            ));
        }
    }
    // Creator and private copy have separate native identities, with identical
    // admitted bytes. Neither the entry marker nor a path grants authority.
    let current = native::current_process()?;
    for (process, kind) in [(&current, "carrier"), (parent, "image")] {
        let image = native::open_image(&native::process_image(process)?, false)?;
        let identity = super::entry_effects::identity(&image, false)?;
        if !objects
            .iter()
            .any(|o| o.object.kind == kind && o.object.identity == identity)
        {
            return Err(refuse(
                "admit carrier image",
                "running image differs from admitted object",
            ));
        }
    }
    let original = objects.iter().find(|o| o.object.kind == "image");
    let copy = objects.iter().find(|o| o.object.kind == "carrier");
    if original.and_then(|o| o.object.sha256.as_ref())
        != copy.and_then(|o| o.object.sha256.as_ref())
        || original.map(|o| &o.object.identity) == copy.map(|o| &o.object.identity)
    {
        return Err(refuse(
            "admit carrier copy",
            "separate identical private image required",
        ));
    }
    Ok(objects)
}
fn execute() -> Result<()> {
    // SAFETY: querying this process's standard input does not transfer ownership.
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut input = File::from(native::duplicate_same(input, false)?);
    let mut frame: Frame = read_json(&mut input)?;
    let parent = duplicate(frame.parent)?;
    live_parent(&parent)?;
    remaining(frame.deadline)?;
    let nonce = nonce(&frame.nonce)?;
    // Retain the original account-wide claim through the final native effects.
    let _claim = duplicate(frame.claim)?;
    let mut objects = admit_objects(std::mem::take(&mut frame.entries), &parent)?;
    let mut ready = File::from(duplicate(frame.ready)?);
    let mut ack = [0; 33];
    ack[0] = b'R';
    ack[1..].copy_from_slice(&nonce);
    ready
        .write_all(&ack)
        .map_err(|e| error("publish carrier readiness", e))?;
    drop(ready);
    let mut authorize = File::from(duplicate(frame.authorize)?);
    loop {
        remaining(frame.deadline)?;
        if let Some(auth) = native::poll_frame(&mut authorize)? {
            if auth[0] != b'G' || auth[1..] != nonce {
                return Err(refuse(
                    "admit carrier authorization",
                    "private nonce differs",
                ));
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut report = File::from(duplicate(frame.report)?);
    let mut authorization: Authorization = read_json(&mut report)?;
    if authorization.nonce != frame.nonce {
        return Err(refuse("admit completion report", "private nonce differs"));
    }
    // SAFETY: retained exact creator and bounded machine-monotonic wait.
    let wait = unsafe { WaitForSingleObject(parent.as_raw_handle(), remaining(frame.deadline)?) };
    let outcome = match wait {
        WAIT_OBJECT_0 => super::entry_effects::remove(&mut objects),
        WAIT_TIMEOUT => Err(refuse(
            "await authorized parent exit",
            "exact creator did not exit before deadline",
        )),
        _ => Err(native::last("observe authorized parent exit")),
    };
    // The system guardian forwards completion only after this image exits and
    // its private executable and cleanup journal are independently absent.
    authorization.report["completion"] = serde_json::json!({
        "pipe": frame.cleanup_pipe, "token": frame.nonce
    });
    let delivery =
        super::entry_effects::complete(&objects, &authorization.report, outcome.as_ref().err());
    outcome.and(delivery)
}
/// Called only by the binary's private native entry, before ordinary routing.
pub fn uninstall_carrier_entry() -> u8 {
    match execute() {
        Ok(()) => 0,
        Err(cause) => {
            eprintln!("{cause}");
            78
        }
    }
}
