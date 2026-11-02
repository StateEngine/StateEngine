//! The authenticated private transport retains the core plan and the observed
//! record digest. Neither is accepted from public argv or an environment flag.
use super::*;
use se_proc::OwnedFile;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub installation: UninstallPlan,
    pub record_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<super::uninstall_completion::Request>,
}
pub(crate) struct Completion {
    _claim: se_proc::NativeInstallationClaim,
    record: OwnedFile,
    record_digest: [u8; 32],
    installation: ValidatedUninstallPlan,
}
impl Plan {
    /// Run before Ready: a changed installation record refuses authorization
    /// while the original installed process is still alive.
    pub(crate) fn prepare(self, image: &Path) -> Result<Completion> {
        let installation = self.installation.validate()?;
        let expected = *Sha256::parse_hex(&self.record_sha256)?.as_bytes();
        let record_path = installation.state_home().join("standalone-install.json");
        let native = |error: se_proc::StateFileError| {
            se_core::scope::unreadable("private uninstall record", &error.to_string())
                .with_cause(error)
        };
        let claim = se_proc::NativeInstallationClaim::acquire().map_err(native)?;
        let mut record = OwnedFile::open(&record_path)
            .map_err(native)?
            .ok_or_else(|| invalid("the authenticated uninstall record is absent"))?;
        record.claim_installation_record().map_err(native)?;
        let bytes = record.read(1024 * 1024).map_err(native)?;
        if record.sha256().map_err(native)? != expected
            || <[u8; 32]>::from(Hasher::digest(&bytes)) != expected
        {
            return Err(conflict(&record_path.to_string_lossy()));
        }
        let parsed: InstallRecord = serde_json::from_slice(&bytes).map_err(|error| {
            invalid("the authenticated uninstall record is invalid").with_cause(error)
        })?;
        if parsed.schema != "stateengine-install/v1" {
            return Err(invalid("the authenticated uninstall schema changed"));
        }
        let current = Installation {
            record_path,
            record: parsed,
        }
        .plan()?;
        if serde_json::to_value(&current)
            .map_err(|e| invalid("cannot encode record plan").with_cause(e))?
            != serde_json::to_value(&installation)
                .map_err(|e| invalid("cannot encode authenticated plan").with_cause(e))?
        {
            return Err(invalid(
                "the authenticated uninstall plan differs from the current owned record",
            ));
        }
        let canonical =
            se_proc::canonicalize_path(image).map_err(|error| unreadable(image, error))?;
        for file in installation.files() {
            match se_proc::canonicalize_path(&file.path) {
                Ok(path) if path == canonical => (),
                Ok(_) => return Err(conflict(&file.path)), // parent authorizes only after every other asset is absent.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(unreadable(Path::new(&file.path), error)),
            }
        }
        Ok(Completion {
            _claim: claim,
            record,
            record_digest: expected,
            installation,
        })
    }
}
impl Completion {
    pub(crate) fn installation(&self) -> &ValidatedUninstallPlan {
        &self.installation
    }

    pub(crate) fn record_helper_cleanup(
        &self,
        debt: &se_proc::UninstallHelperCleanup,
    ) -> Result<()> {
        super::helper_cleanup::publish(self.installation.state_home(), &self._claim, debt)
    }

    /// Called only after native proof of the exact parent's exit and image
    /// deletion. The running helper's own cleanup remains externally witnessed.
    pub(crate) fn finish(self) -> Result<()> {
        self.record.remove(self.record_digest).map_err(|error| {
            se_core::scope::unreadable("post-exit installation record removal", &error.to_string())
                .with_cause(error)
        })?;
        eprintln!("Removed owned installation record (native absence witnessed)");
        let mut directories: Vec<_> = self.installation.created_directories().iter().collect();
        directories.sort_by_key(|path| std::cmp::Reverse(Path::new(path).components().count()));
        for path in directories {
            match se_proc::remove_empty_directory(Path::new(path)) {
                Ok(result) => eprintln!("Post-exit directory {}: {:?}", path, result),
                Err(error) => {
                    return Err(se_core::scope::unreadable(
                        "post-exit empty-directory removal",
                        &error.to_string(),
                    )
                    .with_cause(error));
                }
            }
        }
        eprintln!("Helper cleanup remains pending until outside post-exit readback");
        Ok(())
    }
}
