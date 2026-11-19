//! Native restart admission and replacement of both transport credentials.
use super::*;
use crate::client::rebind::RebindReply;
use hmac::{Hmac, Mac};
use se_store::{Actor, Admission, Scope, mail::MailSnapshot};
use se_types::Secret;
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;
use zeroize::{Zeroize, Zeroizing};

fn refusal(reason: &str) -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::CapabilityInvalid(
        se_types::details::CapabilityInvalid {
            subject: "service restart".into(),
            reason: reason.into(),
            next_step:
                "Restore the selected seat's registered service and retry from that service.".into(),
        },
    ))
}

fn secret(
    key: &Secret,
    label: &str,
    session: &se_types::SessionId,
    identity: &[u8],
) -> Result<Secret> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.expose())
        .map_err(|_| refusal("protected key unavailable"))?;
    for field in [
        b"stateengine.rebind/v1".as_slice(),
        label.as_bytes(),
        session.as_str().as_bytes(),
        identity,
    ] {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field);
    }
    let mut raw = mac.finalize().into_bytes();
    let mut digest = Zeroizing::new([0u8; 32]);
    digest.copy_from_slice(&raw);
    raw.as_mut_slice().zeroize();
    let prefix = if label == "session" {
        format!("sec1.{session}.")
    } else {
        "sels-".into()
    };
    let mut bytes = Zeroizing::new(prefix.into_bytes());
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut accumulator = 0u32;
    let mut bits = 0;
    for byte in digest.iter() {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            bytes.push(ALPHABET[((accumulator >> bits) & 63) as usize]);
        }
    }
    if bits > 0 {
        bytes.push(ALPHABET[((accumulator << (6 - bits)) & 63) as usize]);
    }
    Secret::new(std::mem::take(&mut *bytes))
}

fn original_process(journal: &custody::Journal) -> Result<&se_proc::ProcessIdentity> {
    let checkpoint = journal
        .service
        .as_ref()
        .ok_or_else(|| refusal("original service process is unavailable"))?;
    match &checkpoint.checkpoint {
        se_proc::CheckpointKind::Process(record) => Ok(&record.root),
        se_proc::CheckpointKind::Exit { source, .. } => match source.as_ref() {
            se_proc::CheckpointSource::Process(record) => Ok(&record.root),
            _ => Err(refusal("the original service process was not established")),
        },
        _ => Err(refusal("the original service process was not established")),
    }
}

fn newer_than_original(
    peer: &crate::PeerProof,
    original: &se_proc::ProcessIdentity,
    current_boot: &se_proc::BootIdentity,
) -> Result<()> {
    if &original.boot != current_boot {
        return Ok(());
    }
    let later = match (&original.start, peer.native().started()) {
        (
            se_proc::StartIdentity::Linux { start_ticks: a },
            se_types::StartIdentity::Linux { start_ticks: b },
        ) => b > a,
        (
            se_proc::StartIdentity::Windows {
                creation_filetime: a,
            },
            se_types::StartIdentity::Windows {
                creation_filetime: b,
            },
        ) => b.get() > *a,
        (
            se_proc::StartIdentity::MacOs {
                seconds: a,
                microseconds: a_us,
            },
            se_types::StartIdentity::Macos {
                start_seconds: b,
                start_micros: b_us,
            },
        ) => (b, b_us) > (a, a_us),
        _ => false,
    };
    if !later {
        return Err(refusal(
            "the observed process is not newer than the originally registered service",
        ));
    }
    Ok(())
}

fn restart_identity(
    project: &se_types::ProjectId,
    agent: &se_types::AgentId,
    session: &se_types::SessionId,
    restart: &se_store::CredentialRestart,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        project,
        agent,
        session,
        &restart.boot,
        restart.pid,
        &restart.started,
        restart.image_sha256,
    ))
    .map_err(|_| refusal("restart identity cannot be encoded"))
}

fn validate_rebind_service(
    service: &Service,
    peer: &crate::PeerProof,
    boot: &se_proc::BootIdentity,
) -> Result<()> {
    if service.journal.retired
        || service.journal.server_sha256 != Some(peer.native().image_sha256())
    {
        return Err(refusal(
            "the observed executable is not registered for the selected active seat",
        ));
    }
    let journal = &service.journal;
    if journal.client_closed.is_some() {
        return Err(refusal(
            "the original client was closed; a restart cannot revive it",
        ));
    }
    newer_than_original(peer, original_process(journal)?, boot)?;
    Ok(())
}

fn native_restart(
    peer: &crate::PeerProof,
    boot: &se_types::BootId,
    endpoint: &str,
) -> Result<se_store::CredentialRestart> {
    Ok(se_store::CredentialRestart {
        boot: boot.clone(),
        pid: NonZeroU32::new(peer.native().pid())
            .ok_or_else(|| refusal("native peer has no process identity"))?,
        started: peer.native().started().clone(),
        image_sha256: peer.native().image_sha256(),
        control_endpoint: endpoint.to_owned(),
    })
}

fn start_order(start: &se_types::StartIdentity) -> (u8, u64, u32) {
    match start {
        se_types::StartIdentity::Linux { start_ticks } => (1, *start_ticks, 0),
        se_types::StartIdentity::Windows { creation_filetime } => (2, creation_filetime.get(), 0),
        se_types::StartIdentity::Macos {
            start_seconds,
            start_micros,
        } => (3, *start_seconds, *start_micros),
    }
}

impl LaunchCoordinator {
    pub(in crate::process) async fn rebind_service(
        &self,
        peer: &crate::PeerProof,
        selected_project: &se_types::ProjectId,
        selected_agent: &se_types::AgentId,
        control_endpoint: &str,
        deadline: &Deadline,
    ) -> Result<RebindReply> {
        let slot = self
            .rebind_slot(selected_project, selected_agent, deadline)
            .await?;
        let mut service = lock_service(&slot, deadline).await?;
        validate_rebind_service(&service, peer, &self.owner.boot)?;
        let journal = &service.journal;
        let project = journal.project.clone();
        let agent = journal.agent.clone();
        let session = journal.session.clone();
        let restart = native_restart(
            peer,
            &self.options.epoch.owner.fields().boot,
            control_endpoint,
        )?;
        let identity = restart_identity(&project, &agent, &session, &restart)?;
        let restart_bytes: [u8; 32] = Sha256::digest(&identity).into();
        let restart_key = se_types::hex_lower(&restart_bytes);
        let machine_key = self.capability_admission.machine_key()?;
        let capability = secret(&machine_key, "session", &session, &identity)?;
        let http_bearer = secret(&machine_key, "http", &session, &identity)?;
        let session_hash = Sha256::digest(capability.expose()).into();
        let http_hash = Sha256::digest(http_bearer.expose()).into();
        let key = se_types::IdempotencyKey::new(format!("secode.rebind.{restart_key}"))?;
        let same_restart = service
            .restart
            .as_ref()
            .is_some_and(|old| old.restart_key == restart_key);
        let control = if let Some(existing) = service.restart.as_ref().filter(|_| same_restart) {
            existing.control.clone()
        } else {
            self.restart_control(
                &service,
                control_endpoint,
                &capability,
                restart_bytes,
                deadline,
            )
            .await?
        };
        let selected = crate::SessionIdentity {
            project: project.clone(),
            agent: agent.clone(),
            session: session.clone(),
        };
        let request = se_core::ops::process_commit::RebindGrant {
            session: session.clone(),
            agent: agent.clone(),
            restart: restart.clone(),
            key,
            session_hash,
            http_hash,
        };
        self.rotate_if_new(&selected, request, deadline).await?;
        if !same_restart {
            service.live.invalidate()?;
        }
        if service.journal.restart_key.as_deref() != Some(&restart_key) {
            service.journal.restart_key = Some(restart_key.clone());
            service.journal.restart_effect = None;
            service.journal.restart_settled = false;
            service.journal.restart_reply_sent = false;
            service.journal.superseded_by_restart = true;
            service.persist(self, deadline).await?;
        }
        if !same_restart {
            service.restart = Some(RestartControl {
                control,
                reply_sent: false,
                mail_notified: false,
                identity: restart,
                adopted: false,
                session_hash,
                restart_key: restart_key.clone(),
            });
            service.capability_check_at = None;
        }
        let cursor = self
            .rebind_readback(&selected, &capability, &http_bearer, deadline)
            .await?;
        drop(service);
        Ok(RebindReply {
            project,
            agent,
            session,
            capability,
            http_bearer,
            restart_key,
            cursor,
        })
    }
    async fn rotate_if_new(
        &self,
        selected: &crate::SessionIdentity,
        request: se_core::ops::process_commit::RebindGrant,
        deadline: &Deadline,
    ) -> Result<()> {
        let admission = Admission {
            scope: Scope::Project(selected.project.clone()),
            actor: Actor::Human(self.human.clone()),
            session: None,
            generation: self.store.generation.get(),
        };
        let selected_session = selected.session.clone();
        let expected_restart = request.restart.clone();
        let already = self
            .store
            .read(admission.clone(), deadline, move |cx| {
                use se_store::Snapshot;
                let mut heads = Vec::new();
                for purpose in ["session", "http"] {
                    let id = se_core::ops::process_commit::session_credential_id(
                        &selected_session,
                        purpose,
                    )?;
                    let head = se_core::scope::require_present(
                        cx.read
                            .credential_head(id)
                            .map_err(|error| se_core::store_error::store_error(&error))?,
                        "restart grants",
                        "Restore the active session grants.",
                    )?;
                    if head.record.state != se_store::CredentialState::Active {
                        return Err(refusal("the selected session grant is not active"));
                    }
                    heads.push(head);
                }
                if heads[0].restart != heads[1].restart {
                    return Err(refusal(
                        "the two current grants have different restart identities",
                    ));
                }
                if let Some(old) = &heads[0].restart {
                    if old == &expected_restart {
                        return Ok(true);
                    }
                    if old.boot == expected_restart.boot
                        && (start_order(&expected_restart.started).0 != start_order(&old.started).0
                            || start_order(&expected_restart.started) <= start_order(&old.started))
                    {
                        return Err(refusal(
                            "an older or ambiguous process cannot replace the current grant",
                        ));
                    }
                }
                Ok(false)
            })
            .await?;
        if !already {
            self.store
                .commit(admission, deadline, None, move |kernel, cx| {
                    se_core::ops::process_commit::rebind(kernel, request, cx)
                })
                .await?;
        }
        Ok(())
    }
    async fn restart_control(
        &self,
        service: &Service,
        control_endpoint: &str,
        capability: &Secret,
        restart_bytes: [u8; 32],
        deadline: &Deadline,
    ) -> Result<Arc<crate::harness::secode_process::Control>> {
        let profile = service.journal.profile.to_local()?;
        let endpoint = control_endpoint.to_owned();
        let proof = Secret::new(capability.expose().to_vec())?;
        self.store
            .pool
            .run_owned(deadline, move || {
                crate::harness::secode_process::Control::for_restart(
                    &profile,
                    &endpoint,
                    proof,
                    restart_bytes,
                )
                .map(Arc::new)
            })
            .await
    }
    async fn rebind_slot(
        &self,
        selected_project: &se_types::ProjectId,
        selected_agent: &se_types::AgentId,
        deadline: &Deadline,
    ) -> Result<ServiceSlot> {
        if self
            .secode_services
            .1
            .lock()
            .map_err(|_| refusal("service inventory is unavailable"))?
            .is_some()
        {
            return Err(refusal("service inventory is incomplete"));
        }
        self.secode_services
            .get(selected_project, selected_agent, deadline)
            .await?
            .ok_or_else(|| refusal("the selected seat has no registered service"))
    }
    async fn rebind_readback(
        &self,
        selected: &crate::SessionIdentity,
        capability: &Secret,
        http_bearer: &Secret,
        deadline: &Deadline,
    ) -> Result<se_types::Read<se_types::Cursor>> {
        let admission_check = self.capability_admission.clone();
        let checked_session = selected.clone();
        let checked_capability = Secret::new(capability.expose().to_vec())?;
        let checked_bearer = Secret::new(http_bearer.expose().to_vec())?;
        self.store
            .pool
            .run_owned(deadline, move || {
                admission_check.verify_session_capability(&checked_capability, &checked_session)?;
                admission_check.check_session(&checked_bearer)
            })
            .await?;
        let read_admission = Admission {
            scope: Scope::Project(selected.project.clone()),
            actor: Actor::Agent(selected.agent.clone()),
            session: Some(selected.session.clone()),
            generation: self.store.generation.get(),
        };
        let recipient = selected.agent.clone();
        let cursor = self
            .store
            .read(read_admission, deadline, move |cx| {
                cx.read
                    .mail_settled_cursor(recipient)
                    .map_err(|error| se_core::store_error::store_error(&error))
            })
            .await?;
        Ok(cursor)
    }
    pub(in crate::process) async fn rebind_reply_sent(
        &self,
        reply: &RebindReply,
        deadline: &Deadline,
    ) -> Result<()> {
        let slot = self
            .secode_services
            .get(&reply.project, &reply.agent, deadline)
            .await?
            .ok_or_else(|| refusal("service custody disappeared after reply"))?;
        let mut service = lock_service(&slot, deadline).await?;
        if service.journal.session != reply.session {
            return Err(refusal("service session changed after reply"));
        }
        let mut saved = Ok(());
        if service
            .restart
            .as_ref()
            .is_some_and(|restart| restart.restart_key == reply.restart_key)
        {
            if !service.journal.restart_reply_sent {
                service.journal.restart_reply_sent = true;
                saved = service.persist(self, deadline).await;
            }
            if let Some(restart) = service.restart.as_mut() {
                restart.reply_sent = true;
            }
            service.capability_check_at = None;
        }
        drop(service);
        use std::sync::atomic::Ordering;
        let jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| refusal("service wake registry is unavailable"))?;
        for job in jobs.values() {
            if job.session == reply.session
                && job.target == (reply.project.clone(), reply.agent.clone())
            {
                job.mail_pending.store(true, Ordering::Release);
                job.wake.event.notify_one();
            }
        }
        saved
    }
    pub(super) async fn adopt_restart(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        let Some(restart) = &service.restart else {
            return Ok(());
        };
        if restart.adopted {
            return Ok(());
        }
        if !restart.reply_sent {
            return Err(refusal("the restart reply has not been delivered"));
        }
        let control = restart.control.clone();
        control.verify_restart(deadline).await?;
        let binding = control
            .binding(&service.journal.vendor_session, deadline)
            .await?;
        service.live.publish_restart(control, binding)?;
        if let Some(restart) = service.restart.as_mut() {
            restart.adopted = true;
        }
        Ok(())
    }

    pub(in crate::process) async fn restart_waiting(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> bool {
        let Ok(Some(slot)) = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await
        else {
            return false;
        };
        let Ok(service) = lock_service(&slot, deadline).await else {
            return false;
        };
        service.restart.is_some()
    }

    pub(in crate::process) async fn restart_session_hash(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<Option<[u8; 32]>> {
        let Some(slot) = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
        else {
            return Ok(None);
        };
        let service = lock_service(&slot, deadline).await?;
        if service.journal.session != work.meta.session {
            return Err(refusal("retained restart session differs"));
        }
        Ok(service.restart.as_ref().map(|restart| restart.session_hash))
    }

    /// Reconstruct pending challenge state from the committed credential heads.
    pub(super) async fn restore_restart_state(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        if service.journal.retired {
            return Ok(());
        }
        let session = service.journal.session.clone();
        let project = service.journal.project.clone();
        let agent = service.journal.agent.clone();
        let admission = Admission {
            scope: Scope::Project(project.clone()),
            actor: Actor::Human(self.human.clone()),
            session: None,
            generation: self.store.generation.get(),
        };
        let selected = session.clone();
        let restart = self
            .store
            .read(admission, deadline, move |cx| {
                use se_store::Snapshot;
                let mut values = Vec::new();
                for purpose in ["session", "http"] {
                    let id =
                        se_core::ops::process_commit::session_credential_id(&selected, purpose)?;
                    match cx
                        .read
                        .credential_head(id)
                        .map_err(|error| se_core::store_error::store_error(&error))?
                    {
                        se_types::Read::Present { value } => values.push(value),
                        se_types::Read::Absent { .. } => return Ok(None),
                        se_types::Read::Unreadable { source, reason, .. } => {
                            return Err(se_core::scope::unreadable(&source, &reason));
                        }
                        se_types::Read::Unknown { what } => {
                            return Err(se_core::scope::unreadable("restart grant", &what));
                        }
                    }
                }
                if values[0].restart != values[1].restart {
                    return Err(refusal("stored credential restart heads differ"));
                }
                if values
                    .iter()
                    .any(|value| value.record.state != se_store::CredentialState::Active)
                {
                    return Ok(None);
                }
                Ok(values[0].restart.clone())
            })
            .await?;
        let Some(restart) = restart else {
            return Ok(());
        };
        let identity = restart_identity(&project, &agent, &session, &restart)?;
        let restart_bytes: [u8; 32] = Sha256::digest(&identity).into();
        let restart_key = se_types::hex_lower(&restart_bytes);
        let machine_key = self.capability_admission.machine_key()?;
        let capability = secret(&machine_key, "session", &session, &identity)?;
        let session_hash = Sha256::digest(capability.expose()).into();
        let profile = service.journal.profile.to_local()?;
        let endpoint = restart.control_endpoint.clone();
        let control = self
            .store
            .pool
            .run_owned(deadline, move || {
                crate::harness::secode_process::Control::for_restart(
                    &profile,
                    &endpoint,
                    capability,
                    restart_bytes,
                )
                .map(Arc::new)
            })
            .await?;
        if service.journal.restart_key.as_deref() != Some(restart_key.as_str()) {
            service.journal.restart_key = Some(restart_key.clone());
            service.journal.restart_effect = None;
            service.journal.restart_settled = false;
            service.journal.restart_reply_sent = false;
            service.journal.superseded_by_restart = true;
            service.persist(self, deadline).await?;
        }
        service.live.invalidate()?;
        service.restart = Some(RestartControl {
            control,
            reply_sent: service.journal.restart_reply_sent,
            mail_notified: false,
            identity: restart,
            adopted: false,
            session_hash,
            restart_key,
        });
        service.capability_check_at = None;
        Ok(())
    }
}
