//! Authenticated, exact-registration retirement after native scope closure.
//! The finite helper has the same persisted custody as other auxiliaries.
use super::*;
use se_proc::{CheckpointKind, CheckpointSource, ProcessRuntime, StopObservation};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub(crate) use se_harness::secode_process::{
    registration_fields as fields, service_registration as registration,
};
fn empty(profile: &std::path::Path) -> Result<bool> {
    let no_registration = se_proc::NativeSourcePin::open(&profile.join("registration"))
        .map_err(|e| error("SE Code registration retirement", e))?
        .is_none();
    let no_ready = se_proc::NativeSourcePin::open(&profile.join("serve-ready.json"))
        .map_err(|e| error("SE Code readiness retirement", e))?
        .is_none();
    Ok(no_registration && no_ready)
}
impl<H: HostPort> Coordinator<'_, H> {
    pub(crate) async fn remember_secode_registration(
        &self,
        service: &mut Service,
        authenticated: &readiness::Registration,
        deadline: &Deadline,
    ) -> Result<()> {
        let profile = service.journal.profile.to_local()?;
        let bytes = self
            .0
            .run_blocking(deadline, move || registration(&profile))
            .await?
            .ok_or_else(|| {
                error(
                    "SE Code registration custody",
                    "authenticated live service has no registration",
                )
            })?;
        authenticated.require_bytes(&bytes)?;
        if service
            .journal
            .registration
            .as_ref()
            .is_some_and(|original| original != &bytes)
        {
            return Err(error(
                "SE Code registration custody",
                "original complete registration changed; no replacement was adopted",
            ));
        }
        service.journal.registration = Some(bytes);
        service.persist(self.0, deadline).await
    }
    async fn open_retirement_images(
        &self,
        service: &Service,
        deadline: &Deadline,
    ) -> Result<(
        se_proc::NativeExecutableInvocation,
        se_harness::secode_process::Images,
    )> {
        let server = match service.journal.service.as_ref().map(|c| &c.checkpoint) {
            Some(CheckpointKind::Exit { source, .. }) => match &**source {
                CheckpointSource::Process(record) => record.root.image.clone(),
                _ => {
                    return Err(error(
                        "SE Code registration retirement",
                        "original service image is unproved",
                    ));
                }
            },
            _ => {
                return Err(error(
                    "SE Code registration retirement",
                    "original service has no native exit checkpoint",
                ));
            }
        };
        let expected_image = service.journal.server_sha256.ok_or_else(|| {
            error(
                "SE Code retirement image",
                "original server digest is unavailable",
            )
        })?;
        self.0
            .run_blocking(deadline, move || {
                let cli = server.with_file_name(if cfg!(windows) {
                    "secode.exe"
                } else {
                    "secode"
                });
                let mut images = se_harness::secode_process::Images::open(&cli)?;
                if images.server_sha256() != expected_image || images.server != server {
                    return Err(error(
                        "SE Code retirement image",
                        "selected server differs from the original service image",
                    ));
                }
                images.validate()?;
                Ok((images.server_invocation()?, images))
            })
            .await
    }
    async fn stage_retirement_inputs(
        &self,
        profile: &std::path::Path,
        original: &[u8],
        deadline: &Deadline,
    ) -> Result<(PathBuf, se_types::Secret)> {
        let directory = self.0.home().join("secode-retirements");
        let bytes = original.to_vec();
        let credential_profile = profile.to_path_buf();
        self.0
            .run_blocking(deadline, move || {
                let files = se_proc::NativeStateFiles::create(&directory)
                    .map_err(|e| error("SE Code retirement record", e))?;
                let hash: [u8; 32] = Sha256::digest(&bytes).into();
                let path = directory.join(format!("{}.registration", se_types::hex_lower(&hash)));
                if se_proc::OwnedFile::open(&path)
                    .map_err(|e| error("SE Code retirement record", e))?
                    .is_none()
                {
                    let mut staging = files
                        .create_staging(&directory)
                        .map_err(|e| error("SE Code retirement record", e))?;
                    // Publication flushes the staged data before moving its name.
                    staging
                        .file
                        .write_all(&bytes)
                        .map_err(|e| error("SE Code retirement record", e))?;
                    drop(staging.file);
                    files
                        .publish_no_replace(&staging.path, &path)
                        .map_err(|e| error("SE Code retirement record", e))?;
                }
                let mut observed = se_proc::OwnedFile::open(&path)
                    .map_err(|e| error("SE Code retirement record", e))?
                    .ok_or_else(|| error("SE Code retirement record", "retained bytes absent"))?;
                if observed
                    .sha256()
                    .map_err(|e| error("SE Code retirement record", e))?
                    != hash
                {
                    return Err(error("SE Code retirement record", "retained bytes changed"));
                }
                let files = se_proc::NativeProfileFiles::open(&credential_profile)
                    .map_err(|e| error("SE Code retirement credential", e))?;
                let mut source = files
                    .readback(&credential_profile.join("basic.credential"))
                    .map_err(|e| error("SE Code retirement credential", e))?
                    .ok_or_else(|| {
                        error(
                            "SE Code retirement credential",
                            "original credential absent",
                        )
                    })?;
                let mut raw = zeroize::Zeroizing::new(Vec::new());
                Read::by_ref(&mut source)
                    .take(257)
                    .read_to_end(&mut raw)
                    .map_err(|e| error("SE Code retirement credential", e))?;
                if raw.is_empty() || raw.len() > 256 {
                    return Err(error(
                        "SE Code retirement credential",
                        "credential exceeds the supported bound",
                    ));
                }
                Ok((path, se_types::Secret::new(std::mem::take(&mut *raw))?))
            })
            .await
    }
    async fn wait_retirement_helper(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        let owner = service
            .retirement
            .clone()
            .ok_or_else(|| error("SE Code retirement helper", "native reference absent"))?;
        loop {
            let native = self.0.native().clone();
            let process = owner.clone();
            let observed = self
                .0
                .run_blocking(deadline, move || {
                    native
                        .witness_exit(&process)
                        .map_err(|e| error("SE Code retirement helper", e))
                })
                .await?;
            if let StopObservation::Complete(witness) = observed {
                let succeeded = matches!(
                    witness.root,
                    se_proc::RootWitness::Identified {
                        status: se_proc::ExitStatus::Code(0),
                        ..
                    }
                );
                self.retire_secode_auxiliary(service, Auxiliary::Retirement, &witness, deadline)
                    .await?;
                if !succeeded {
                    return Err(error(
                        "SE Code registration retirement",
                        "authenticated helper refused or its exit status is unproved; preserve the original registration and diagnostic",
                    ));
                }
                return Ok(());
            }
            tokio::time::sleep(
                deadline
                    .remaining()?
                    .min(std::time::Duration::from_millis(25)),
            )
            .await;
        }
    }
    pub(crate) async fn retire_secode_registration(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        let profile = service.journal.profile.to_local()?;
        let check = profile.clone();
        if self.0.run_blocking(deadline, move || empty(&check)).await? {
            return Ok(());
        }
        let check = profile.clone();
        let original = self
            .0
            .run_blocking(deadline, move || registration(&check))
            .await?
            .ok_or_else(|| {
                error(
                    "SE Code registration retirement",
                    "current registration is absent while readiness remains",
                )
            })?;
        service.journal.require_registration(&original)?;
        let (server, images) = self.open_retirement_images(service, deadline).await?;
        if service.journal.retirement.is_some() {
            if service.owner(Auxiliary::Retirement).is_some()
                || !matches!(service.journal.retirement.as_ref().map(|c|&c.checkpoint),Some(CheckpointKind::Exit {witness,..}) if witness.scope_exit.exit_basis.is_some())
            {
                return Err(error(
                    "SE Code registration retirement",
                    "original helper scope remains unproved",
                ));
            }
            // The public operation permits an exact-byte retry after a lost
            // response. An earlier native helper must first be proved closed.
            service.journal.retirement = None;
            service.retirement_output = None;
            service.persist(self.0, deadline).await?;
        }
        let (expected, credential) = self
            .stage_retirement_inputs(&profile, &original, deadline)
            .await?;
        let policy = se_proc::LaunchPolicy {
            containment: se_proc::ContainmentRequirement::BestAvailable,
            writes: se_proc::WritePolicy::Workspace {
                roots: vec![profile.clone()],
                scratch: profile.with_extension("scratch"),
            },
            network: se_proc::NetworkPolicy::Offline,
            hardening: se_proc::OptionalHardening::Off,
        };
        self.start_secode_auxiliary(
            service,
            AuxiliaryLaunch {
                auxiliary: Auxiliary::Retirement,
                executable: server,
                arguments: vec![
                    "retire-service".into(),
                    "--service".into(),
                    profile.as_os_str().to_owned(),
                    "--expected-registration".into(),
                    expected.into_os_string(),
                ],
                cwd: profile.clone(),
                policy,
                input: Some(credential),
            },
            deadline,
        )
        .await?;
        self.wait_retirement_helper(service, deadline).await?;
        verify_retirement_report(service, &original)?;
        if !self
            .0
            .run_blocking(deadline, move || empty(&profile))
            .await?
        {
            return Err(error(
                "SE Code registration retirement",
                "registration or ready custody remains after helper exit",
            ));
        }
        self.0
            .run_blocking(deadline, move || {
                let mut images = images;
                images.validate()
            })
            .await?;
        Ok(())
    }
}
fn verify_retirement_report(service: &Service, original: &[u8]) -> Result<()> {
    let report = service
        .retirement_output
        .as_ref()
        .ok_or_else(|| error("SE Code retirement response", "original diagnostic absent"))?
        .response()?;
    let fields = fields(original)?;
    for (field, expected) in [
        ("service_instance", fields["instance"]),
        ("service_slot", fields["slot"]),
        ("environment", fields["environment"]),
        ("endpoint", fields["endpoint"]),
    ] {
        if report[field].as_str() != Some(expected) {
            return Err(error(
                "SE Code retirement response",
                "original registration coordinates differ",
            ));
        }
    }
    if report["schema"] != "secode.product.service-retirement.v1"
        || !matches!(
            (
                report["outcome"].as_str(),
                report["registration_released"].as_bool()
            ),
            (Some("released"), Some(true)) | (Some("slot_already_empty"), Some(false))
        )
        || report["generation"]
            .as_u64()
            .map(|n| n.to_string())
            .as_deref()
            != Some(fields["generation"])
        || report["pid"].as_u64().map(|n| n.to_string()).as_deref() != Some(fields["pid"])
    {
        return Err(error(
            "SE Code retirement response",
            "complete original retirement outcome is unavailable",
        ));
    }
    Ok(())
}
