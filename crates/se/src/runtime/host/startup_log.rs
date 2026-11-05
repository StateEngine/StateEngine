//! Human-readable failure diagnostics, never runtime authority or a launch frame.
use se_types::{Remedy, SeError};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

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
    fn save(&self) -> std::result::Result<PathBuf, String> {
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
        Ok(path)
    }
    pub(crate) fn refusal(&mut self, mut error: SeError) -> SeError {
        let phase = self.phase.clone();
        self.note(&format!("Startup refused: {}", error.body.message()));
        // Successful startup pays no diagnostic file creation or durability
        // barriers. Only a refusal publishes the finite observed phase trace.
        let diagnostic = match self.save() {
            Ok(path) => format!(
                "Last startup phase: {phase}. Read the startup log: {}",
                path.display()
            ),
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

pub(crate) fn pending(home: &Path, mut error: SeError, waiting_for: &str) -> SeError {
    let mut log = StartupLog::new(home);
    log.note(waiting_for);
    error.body = error.body.with_remedy(Remedy {
        text: format!("Waiting for {waiting_for}. No launch request was submitted; inspect this same home's status before retrying, and do not remove runtime.lock or bypass its holder."),
        command: None,
    });
    log.refusal(error)
}
