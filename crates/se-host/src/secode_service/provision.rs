//! Session and capability provisioning are authenticated, original-identity
//! operations. A disconnected write is reconciled by reading that same object.
use super::*;
use reqwest::Method;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;

impl LaunchCoordinator {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) async fn configure_secode(
        &self,
        service: &mut Service,
        request: &crate::HarnessRequest,
        deadline: &Deadline,
    ) -> Result<()> {
        let secret = |secret: &se_types::Secret| -> Result<String> {
            std::str::from_utf8(secret.expose())
                .map(str::to_owned)
                .map_err(|_| error("SE Code MCP configuration", "credential encoding differs"))
        };
        let roots = match &request.policy.writes {
            se_proc::WritePolicy::Workspace { roots, .. } => roots
                .iter()
                .map(|path| {
                    path.to_str().map(str::to_owned).ok_or_else(|| {
                        error("SE Code workspace policy", "this API requires UTF-8 paths")
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            _ => Vec::new(),
        };
        let mut permission = json!({});
        if matches!(request.policy.writes, se_proc::WritePolicy::ReadOnly { .. }) {
            permission = json!({"edit":"deny", "shell":"deny", "execute":"deny", "external_directory":"deny"});
        }
        if request.policy.network == se_proc::NetworkPolicy::Offline {
            permission["webfetch"] = json!("deny");
            permission["websearch"] = json!("deny");
        }
        let protect_git = matches!(
            request.policy.writes,
            se_proc::WritePolicy::Workspace { .. }
        ) && !self
            .options
            .configuration
            .profiles
            .get(&request.profile.named_profile)
            .is_some_and(|profile| profile.git_write);
        let mut value = json!({
            "sandbox": {"enabled":!matches!(request.policy.writes, se_proc::WritePolicy::NamedUnrestricted { .. }), "network":request.policy.network == se_proc::NetworkPolicy::Allow, "writable_roots":roots},
            "permission":permission,
            "mcp":{"stateengine":{
                "type":"remote", "url":format!("http://127.0.0.1:{}/mcp", self.options.http_port),
                "headers":{"Authorization":format!("Bearer {}",secret(&request.mcp_bearer)?),"X-StateEngine-Session-Proof":secret(&request.launch_credential)?},
                // The bound document reader requires identity coordinates for
                // both transports; remote MCP does not inherit this map.
                "environment":{"STATEENGINE_PROJECT_ID":request.identity.project,"STATEENGINE_AGENT_ID":request.identity.agent,"SECODE_SESSION_ID":service.journal.vendor_session},
            }},
        });
        if protect_git {
            value["sandbox"]["git_metadata_read_only"] = json!(true);
        }
        let bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(&value).map_err(|e| error("SE Code policy encoding", e))?,
        );
        let hash = Sha256::digest(bytes.as_slice()).into();
        if service
            .journal
            .policy_sha256
            .is_some_and(|found| *found.as_bytes() != hash)
        {
            return Err(error(
                "SE Code policy retry",
                "the original policy differs; settle its original session before replacement",
            ));
        }
        service.journal.policy_sha256 = Some(se_types::Sha256::from_bytes(hash));
        service.persist(self, deadline).await?;
        let previous = service
            .journal
            .previous_policy_sha256
            .map(|hash| *hash.as_bytes());
        let profile = service.journal.profile.to_local()?;
        self.store
            .pool
            .run_owned(deadline, move || {
                let files = se_proc::NativeProfileFiles::open(&profile)
                    .map_err(|e| error("SE Code policy custody", e))?;
                let path = profile.join("host-policy.json");
                if let Some(observed) = files
                    .sha256(&path)
                    .map_err(|e| error("SE Code policy acquisition", e))?
                {
                    if observed != hash {
                        if previous != Some(observed) {
                            return Err(error(
                                "SE Code policy readback",
                                "protected policy changed; no overwrite",
                            ));
                        }
                        files
                            .replace(&path, observed, &bytes)
                            .map_err(|e| error("SE Code settled policy replacement", e))?;
                    }
                } else {
                    let mut staged = files
                        .create_staging(&profile)
                        .map_err(|e| error("SE Code policy staging", e))?;
                    staged
                        .file
                        .write_all(&bytes)
                        .and_then(|()| staged.file.sync_all())
                        .map_err(|e| error("SE Code policy sync", e))?;
                    drop(staged.file);
                    files
                        .publish_no_replace(&staged.path, &path)
                        .map_err(|e| error("SE Code policy publication", e))?;
                }
                let observed = files
                    .sha256(&path)
                    .map_err(|e| error("SE Code policy readback", e))?
                    .ok_or_else(|| {
                        error("SE Code policy readback", "policy absent after publication")
                    })?;
                if observed != hash {
                    return Err(error("SE Code policy readback", "published policy differs"));
                }
                Ok(())
            })
            .await?;
        service.journal.previous_policy_sha256 = None;
        service.persist(self, deadline).await?;
        if protect_git {
            let selected = self.secode.images(&request.executable.to_local()?)?;
            let server = self
                .store
                .pool
                .run_owned(deadline, move || {
                    selected
                        .lock()
                        .map_err(|_| error("SE Code sandbox policy", "poisoned custody"))?
                        .server_invocation()
                })
                .await?;
            let profile = service.journal.profile.to_local()?;
            let directory = request.cwd.to_local()?;
            let observed = crate::harness::secode_process::sandbox::inspect(
                server, &profile, &directory, deadline,
            )
            .await?;
            let mut expected = vec![directory, profile.with_extension("scratch")];
            if let se_proc::WritePolicy::Workspace { roots, .. } = &request.policy.writes {
                expected.extend(roots.iter().cloned());
            }
            let expected = self
                .store
                .pool
                .run_owned(deadline, move || {
                    let mut roots = expected
                        .into_iter()
                        .map(|path| {
                            se_proc::canonicalize_path(&path)
                                .map_err(|cause| error("SE Code saved writable root", cause))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    roots.sort();
                    roots.dedup();
                    Ok(roots)
                })
                .await?;
            crate::harness::secode_process::sandbox::verify(
                &observed,
                &expected,
                request.policy.network == se_proc::NetworkPolicy::Allow,
            )?;
        }
        Ok(())
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) async fn provision_secode(
        &self,
        service: &mut Service,
        request: &crate::HarnessRequest,
        registration: &readiness::Registration,
        deadline: &Deadline,
    ) -> Result<String> {
        let control = service
            .control
            .clone()
            .ok_or_else(|| error("SE Code provisioning", "authenticated control absent"))?;
        let session = service.journal.vendor_session.clone();
        if !service.journal.session_create_attempted
            && matches!(request.resume, se_types::Read::Absent { .. })
        {
            service.journal.session_create_attempted = true;
            service.persist(self, deadline).await?;
            let directory = request.cwd.to_local()?;
            let directory = directory.to_str().ok_or_else(|| {
                error("SE Code workspace", "the native API requires a UTF-8 path")
            })?;
            let mut body = json!({"id":session,"location":{"directory":directory}});
            if let Some(model) = &request.profile.model {
                body["model"] = model_reference(model)?;
            }
            let write = control
                .request(Method::POST, &["api", "session"], Some(&body), deadline)
                .await;
            if let Err(original) = write {
                // An explicit session ID is already reserved. Read only that
                // identity; never substitute a new ID or another create call.
                control
                    .read(&["api", "session", &session], deadline)
                    .await
                    .map_err(|read| read.with_cause(original))?;
            }
        }
        let saved = control
            .read(&["api", "session", &session], deadline)
            .await?;
        let saved = saved
            .get("data")
            .ok_or_else(|| error("SE Code saved session", "response data absent"))?;
        let directory = request.cwd.to_local()?;
        let observed_directory = saved
            .pointer("/location/directory")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| error("SE Code saved workspace", "directory absent"))?;
        let same_directory = self
            .store
            .pool
            .run_owned(deadline, move || {
                let expected = directory
                    .canonicalize()
                    .map_err(|e| error("SE Code expected workspace", e))?;
                let observed = observed_directory
                    .canonicalize()
                    .map_err(|e| error("SE Code saved workspace", e))?;
                Ok(expected == observed)
            })
            .await?;
        if saved["id"] != session || !same_directory {
            return Err(error(
                "SE Code saved session",
                "original session or workspace differs; no initial input was offered",
            ));
        }
        // Retain authenticated service custody before later provisioning can
        // fail. An unbound session does not publish client readiness or
        // authorize any initial input.
        let binding = control.binding(&session, deadline).await?;
        registration.require_same(&binding.service)?;
        if let Some(original) = &service.journal.identity {
            original.require_same(&binding.service)?;
        }
        service.journal.identity = Some(binding.service);
        service.persist(self, deadline).await?;
        if let Some(model) = &request.profile.model {
            let expected = model_reference(model)?;
            if saved.get("model") != Some(&expected) {
                return Err(error(
                    "SE Code saved model",
                    "the saved model differs from the requested provider/model; no initial input was offered",
                ));
            }
        } else if saved
            .pointer("/model/providerID")
            .and_then(Value::as_str)
            .is_none()
            || saved.pointer("/model/id").and_then(Value::as_str).is_none()
        {
            return Err(error(
                "SE Code saved model",
                "no configured provider/model is saved; connect an SE Code provider and select its private seed profile before launching",
            ));
        }
        let actual_model = format!(
            "{}/{}",
            saved["model"]["providerID"]
                .as_str()
                .ok_or_else(|| error("SE Code actual model", "provider ID absent"))?,
            saved["model"]["id"]
                .as_str()
                .ok_or_else(|| error("SE Code actual model", "model ID absent"))?
        );
        let preset = match request.policy.writes {
            se_proc::WritePolicy::ReadOnly { .. } => "inspect",
            se_proc::WritePolicy::NamedUnrestricted { .. } => "bypass",
            se_proc::WritePolicy::Workspace { .. } => "maintainer",
        };
        let preset_body = json!({"preset":preset});
        control
            .request(
                Method::POST,
                &["api", "session", &session, "preset"],
                Some(&preset_body),
                deadline,
            )
            .await?;
        let observed = control
            .read(&["api", "session", &session, "preset"], deadline)
            .await?;
        if observed.pointer("/data/effective").and_then(Value::as_str) != Some(preset) {
            return Err(error(
                "SE Code effective permission preset",
                "saved effective preset differs",
            ));
        }
        let identity = json!({"scope":"project","project_id":request.identity.project,"agent_id":request.identity.agent});
        control
            .request(
                Method::PUT,
                &[
                    "api",
                    "session",
                    &session,
                    "instructions",
                    "entries",
                    "stateengine-identity",
                ],
                Some(&json!({"value":identity})),
                deadline,
            )
            .await?;
        let entries = control
            .read(
                &["api", "session", &session, "instructions", "entries"],
                deadline,
            )
            .await?;
        if !entries["data"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|row| row["key"] == "stateengine-identity" && row["value"] == identity)
        }) {
            return Err(error(
                "SE Code context binding",
                "saved project/agent instruction differs",
            ));
        }
        let config = service.journal.profile.to_local()?.join("host-policy.json");
        control
            .put_session_capability(&session, &request.launch_credential, &config, deadline)
            .await?;
        let binding = control.binding(&session, deadline).await?;
        binding.require_ready()?;
        if let Some(original) = &service.journal.identity {
            original.require_same(&binding.service)?;
        }
        service.journal.identity = Some(binding.service);
        service.journal.capability_repair = None;
        service.live = Default::default();
        service.capability_failure = None;
        service.capability_check_at = None;
        service.persist(self, deadline).await?;
        Ok(actual_model)
    }
}
fn model_reference(model: &str) -> Result<Value> {
    let (provider, model) = model
        .split_once('/')
        .filter(|(provider, model)| !provider.is_empty() && !model.is_empty())
        .ok_or_else(|| {
            error(
                "SE Code model selection",
                "set a provider/model reference or use the provider profile's saved default",
            )
        })?;
    Ok(json!({"providerID":provider,"id":model}))
}
