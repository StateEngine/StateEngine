//! Provider-written discovery joins a claimed conversation to its native birth.
//! Missing or changing discovery is unconfirmed, never a guessed association.
use super::*;
use se_proc::native_ipc::NativeIpcPeer;
use serde_json::Value;

fn verify(registration: &Registration, provider: &NativeIpcPeer, input: &Input) -> Result<()> {
    if current(registration, provider, input)? {
        Ok(())
    } else {
        Err(invalid(
            "the same provider process birth, conversation and registered working directory in native discovery",
        ))
    }
}
/// Whether discovery still names this exact native session. Absence or a
/// different conversation ends an old waiter; unreadable discovery refuses.
pub fn current(
    registration: &Registration,
    provider: &NativeIpcPeer,
    input: &Input,
) -> Result<bool> {
    let path = registration
        .config_home
        .to_local()?
        .join("sessions")
        .join(format!("{}.json", provider.pid()));
    let pin = se_proc::NativeSourcePin::open(&path).map_err(native)?;
    let Some(mut pin) = pin else {
        return Ok(false);
    };
    let chunk = pin.read_at(0, 65536).map_err(native)?;
    if !chunk.end_of_file {
        return Err(invalid("provider discovery within 64 KiB"));
    }
    let row: Value = crate::client::wire::decode_json(&chunk.bytes, 65536)?;
    let start = row
        .get("procStart")
        .and_then(Value::as_str)
        .and_then(|v| v.parse::<u64>().ok());
    let matches_birth = match provider.started() {
        se_types::StartIdentity::Linux { start_ticks } => start == Some(*start_ticks),
        se_types::StartIdentity::Windows { creation_filetime } => {
            let ticks = creation_filetime.get();
            start == Some(ticks)
                || start
                    == ticks
                        .checked_div(10_000)
                        .and_then(|ms| ms.checked_sub(11_644_473_600_000))
        }
        _ => false,
    };
    let cwd = row
        .get("cwd")
        .and_then(Value::as_str)
        .map(std::path::Path::new)
        .map(se_proc::canonicalize_path)
        .transpose()
        .map_err(io)?;
    if row.get("pid").and_then(Value::as_u64) != Some(u64::from(provider.pid()))
        || row.get("sessionId").and_then(Value::as_str) != Some(input.conversation.as_str())
        || cwd.as_ref() != Some(&input.cwd.to_local()?)
        || !matches_birth
    {
        return Ok(false);
    }
    pin.validate_path(&path).map_err(native)?;
    Ok(true)
}

fn witness(
    home: &std::path::Path,
    generation: se_types::Generation,
    provider: &NativeIpcPeer,
    input: &Input,
) -> Result<(std::path::PathBuf, [u8; 32])> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"observed-provider-birth/v1");
    hash.update(provider.binding());
    hash.update(generation.get().to_le_bytes());
    hash.update(input.project.as_str());
    hash.update(input.conversation.as_str());
    hash.update(
        serde_json::to_vec(&input.cwd).map_err(|_| invalid("native working directory encoding"))?,
    );
    let bytes: [u8; 32] = hash.finalize().into();
    Ok((
        home.join(format!(
            "observed-provider-{}.pin",
            se_types::hex_lower(&bytes)
        )),
        bytes,
    ))
}
/// SessionEnd runs after the provider removes its discovery file. Only an
/// earlier natively verified association may authorize that final retirement.
pub(crate) fn authorize(
    home: &std::path::Path,
    generation: se_types::Generation,
    registration: &Registration,
    provider: &NativeIpcPeer,
    input: &Input,
) -> Result<()> {
    let (path, expected) = witness(home, generation, provider, input)?;
    let files = se_proc::NativeStateFiles::open(home).map_err(native)?;
    let remembered = || -> Result<bool> {
        let Some(file) = files.readback(&path).map_err(native)? else {
            return Ok(false);
        };
        let mut bytes = Vec::new();
        file.take(33).read_to_end(&mut bytes).map_err(io)?;
        Ok(bytes == expected)
    };
    if let Err(error) = verify(registration, provider, input) {
        return if input.action == Action::End && remembered()? {
            Ok(())
        } else {
            Err(error)
        };
    }
    if remembered()? {
        return Ok(());
    }
    let mut staged = files.create_staging(home).map_err(native)?;
    staged.file.write_all(&expected).map_err(io)?;
    staged.file.sync_all().map_err(io)?;
    drop(staged.file);
    match files.publish_no_replace(&staged.path, &path) {
        Ok(()) => Ok(()),
        Err(error) if error.code == se_proc::StateFileErrorCode::AlreadyExists && remembered()? => {
            if let Some(pin) = se_proc::OwnedFile::open(&staged.path).map_err(native)? {
                pin.remove(digest(&expected)).map_err(native)?;
            }
            Ok(())
        }
        Err(error) => Err(native(error)),
    }
}
pub(crate) fn forget(
    home: &std::path::Path,
    generation: se_types::Generation,
    provider: &NativeIpcPeer,
    input: &Input,
) -> Result<()> {
    let (path, expected) = witness(home, generation, provider, input)?;
    if let Some(mut file) = se_proc::OwnedFile::open(&path).map_err(native)? {
        let actual = file.read(33).map_err(native)?;
        if actual != expected {
            return Err(invalid("the original observed provider retirement witness"));
        }
        let digest = file.sha256().map_err(native)?;
        file.remove(digest).map_err(native)?;
    }
    Ok(())
}
