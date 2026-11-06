//! Human-readable failure diagnostics, never runtime authority or a launch frame.
use se_types::{Remedy, SeError};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

const RETAINED_LOGS: usize = 8;

pub(crate) struct StartupLog {
    home: PathBuf,
    entries: String,
    phase: String,
    started: Instant,
}
impl StartupLog {
    pub(crate) fn new(home: &Path) -> Self {
        Self {
            home: home.to_owned(),
            entries: String::new(),
            phase: String::new(),
            started: Instant::now(),
        }
    }
    pub(crate) fn note(&mut self, stage: &str) {
        self.phase = stage.to_owned();
        self.entries.push_str(&format!(
            "{} ms: {stage}\n",
            self.started.elapsed().as_millis()
        ));
    }
    pub(crate) fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
    fn save(&self) -> std::result::Result<(PathBuf, Option<String>), String> {
        let files = se_proc::NativeStateFiles::open(&self.home).map_err(|e| e.to_string())?;
        let mut staged = files
            .create_staging(&self.home)
            .map_err(|e| e.to_string())?;
        let name = staged
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("startup log staging name unavailable")?;
        let name = name.strip_prefix(".se-stage-").unwrap_or(name);
        let path = self.home.join(format!("runtime-startup-{name}.log"));
        staged
            .file
            .write_all(self.entries.as_bytes())
            .map_err(|e| e.to_string())?;
        drop(staged.file);
        files
            .publish_no_replace(&staged.path, &path)
            .map_err(|e| e.to_string())?;
        let cleanup_failure = prune(&files, &path).err();
        Ok((path, cleanup_failure))
    }
    pub(crate) fn refusal(&mut self, mut error: SeError) -> SeError {
        let phase = self.phase.clone();
        let outcome = if error.code() == se_types::Code::RuntimeStartPending {
            "Startup incomplete"
        } else {
            "Startup refused"
        };
        self.note(&format!("{outcome}: {}", error.body.message()));
        // Successful startup pays no diagnostic file creation or durability
        // barriers. Only a refusal publishes the finite observed phase trace.
        let diagnostic = match self.save() {
            Ok((path, cleanup_failure)) => {
                let mut diagnostic = format!(
                    "Last startup phase: {phase}. Read the startup log: {}",
                    path.display()
                );
                if let Some(reason) = cleanup_failure {
                    diagnostic.push_str(&format!(
                        ". Older startup logs could not be removed: {reason}"
                    ));
                }
                diagnostic
            }
            Err(reason) => {
                format!("Last startup phase: {phase}. Startup log could not be written: {reason}")
            }
        };
        let remedy = match error.body.remedy(&se_types::RenderCx::default()) {
            Ok(mut remedy) => {
                remedy.text.push_str(". ");
                remedy.text.push_str(&diagnostic);
                remedy
            }
            Err(reason) => Remedy {
                text: format!(
                    "{diagnostic}. Original recovery advice could not be rendered: {reason}"
                ),
                command: None,
            },
        };
        error.body = error.body.with_remedy(remedy);
        error
    }
}

fn prune(files: &se_proc::NativeStateFiles, current: &Path) -> std::result::Result<(), String> {
    let mut older = Vec::new();
    for entry in std::fs::read_dir(files.root()).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path == current || !log_name(&entry.file_name()) {
            continue;
        }
        if entry.file_type().map_err(|e| e.to_string())?.is_file() {
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .map_err(|e| e.to_string())?;
            older.push((modified, path));
        }
    }
    older.sort_unstable_by(|a, b| b.cmp(a));
    let mut failure = None;
    // Always retain the log advertised by this refusal, even if its clock is
    // behind another writer's. Unrelated names and non-files are never removed.
    for (_, path) in older.into_iter().skip(RETAINED_LOGS - 1) {
        let removed = (|| {
            let Some(mut owned) = se_proc::OwnedFile::open(&path)? else {
                return Ok(());
            };
            // Revalidate the held state root as well as the deletion pin.
            if files.readback(&path)?.is_none() {
                return Ok(());
            }
            let digest = owned.sha256()?;
            owned.remove(digest)
        })();
        if let Err(error) = removed {
            failure.get_or_insert_with(|| format!("{}: {error}", path.display()));
        }
    }
    failure.map_or(Ok(()), Err)
}

fn log_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_prefix("runtime-startup-"))
        .and_then(|name| name.strip_suffix(".log"))
        .is_some_and(|suffix| {
            // NativeStateFiles staging names contain exactly 16 random bytes
            // encoded as lowercase hexadecimal on every supported platform.
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

pub(crate) fn pending(home: &Path, mut error: SeError, waiting_for: &str) -> SeError {
    let mut log = StartupLog::new(home);
    log.note(waiting_for);
    error.body = error.body.with_remedy(Remedy {
        text: format!("Waiting for {waiting_for}. No launch request was submitted; inspect this same home's status before retrying, and do not remove runtime.lock or bypass its holder."),
        command: None,
    });
    log.refusal(error)
}
