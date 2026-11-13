//! Latest suppressed native hook per action, outside pending adoption status.
//! Six fixed slots bound storage across projects; these are observations, not
//! evidence that another user session should be classified as managed.
use super::*;
use crate::state_files::{Acquisition, AcquisitionRetry};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DIRECTORY: &str = "adoption-diagnostics";
const MAX_BYTES: usize = 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    schema: u16,
    pub project: ProjectId,
    pub action: Action,
    pub observed_at: String,
}

pub fn record(home: &Path, project: &ProjectId, action: Action) -> Result<()> {
    let files = se_proc::NativeStateFiles::open(home).map_err(native)?;
    let directory = home.join(DIRECTORY);
    files.prepare_directory(&directory).map_err(native)?;
    let target = directory.join(format!("{}.json", action.name()));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(diagnostic_error)?;
    let observation = Observation {
        schema: 1,
        project: project.clone(),
        action,
        observed_at: se_core::ops::receipt::timestamp(
            i64::try_from(now.as_micros()).map_err(diagnostic_error)?,
        )?,
    };
    let bytes = serde_json::to_vec(&observation).map_err(diagnostic_error)?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid("suppression diagnostic within one KiB"));
    }
    let mut retry = AcquisitionRetry::new(Instant::now() + Duration::from_secs(1));
    loop {
        match retry
            .acquire(|| se_proc::OwnedFile::open(&target))
            .map_err(|e| e.into_public(native))?
        {
            Acquisition::Wait(wait) => std::thread::sleep(wait),
            Acquisition::Ready(Some(mut file)) => {
                let previous = file.read(MAX_BYTES).map_err(native)?;
                return file.replace(digest(&previous), &bytes).map_err(native);
            }
            Acquisition::Ready(None) => {
                let mut staged = files.create_staging(&directory).map_err(native)?;
                staged.file.write_all(&bytes).map_err(io)?;
                staged.file.sync_all().map_err(io)?;
                drop(staged.file);
                let published = files.publish_no_replace(&staged.path, &target);
                if published.is_err()
                    && let Some(file) = se_proc::OwnedFile::open(&staged.path).map_err(native)?
                {
                    file.remove(digest(&bytes)).map_err(native)?;
                }
                match published {
                    Ok(()) => return Ok(()),
                    Err(error) if error.code == se_proc::StateFileErrorCode::AlreadyExists => (),
                    Err(error) => return Err(native(error)),
                }
            }
        }
    }
}

pub fn observations(home: &Path) -> Result<Vec<Observation>> {
    let files = se_proc::NativeStateFiles::open(home).map_err(native)?;
    let mut rows = Vec::new();
    for action in Action::ALL {
        let path = home.join(DIRECTORY).join(format!("{}.json", action.name()));
        let Some(file) = files.readback(&path).map_err(native)? else {
            continue;
        };
        let mut bytes = Vec::new();
        file.take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        let row: Observation = crate::client::wire::decode_json(&bytes, MAX_BYTES)?;
        if row.schema != 1 || row.action != action || row.observed_at.len() > 64 {
            return Err(invalid("the exact bounded hook suppression observation"));
        }
        rows.push(row);
    }
    Ok(rows)
}

fn diagnostic_error(error: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable("adoption suppression diagnostic", &error.to_string())
}
