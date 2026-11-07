//! Attended Claude owns its terminal streams. Readiness comes from the
//! provider's transcript at our trusted resolver, never from prepared argv.
use super::*;

impl ClaudeHarness {
    pub(super) async fn attach_attended(&self, request: HarnessAttach) -> Result<LaunchOutcome> {
        let provider = self
            .probed
            .lock()
            .map_err(|_| poisoned())?
            .clone()
            .ok_or_else(|| {
                SeError::invalid("Claude window", "an actual provider probe before attach")
            })?;
        let conversation = claude::conversation(&request.request)?;
        let transcript = claude::transcript_location(
            &claude::config_home(&claude::provider_environment())?,
            &request.request,
            &conversation,
        )?;
        let mut source = None;
        let mut offset = 0;
        let mut pending = Vec::new();
        loop {
            // The coordinator watches the exact native instance and explicit
            // stop requests. Reading welcome/trust screens is not a timeout.
            let path = transcript.clone();
            let wanted = conversation.clone();
            let (returned, position, tail, ready) =
                tokio::task::spawn_blocking(move || -> Result<_> {
                    if source.is_none() {
                        source = se_proc::NativeSourcePin::open(&path).map_err(|e| {
                            se_core::scope::unreadable("attended Claude transcript", &e.to_string())
                        })?;
                    }
                    let Some(pin) = &mut source else {
                        return Ok((source, offset, pending, false));
                    };
                    let chunk = pin.read_at(offset, 256 * 1024).map_err(|e| {
                        se_core::scope::unreadable("attended Claude transcript", &e.to_string())
                    })?;
                    pending.extend_from_slice(&chunk.bytes);
                    let mut start = 0;
                    let mut ready = false;
                    for (index, byte) in pending.iter().enumerate() {
                        if *byte != b'\n' {
                            continue;
                        }
                        let row: serde_json::Value = serde_json::from_slice(&pending[start..index])
                            .map_err(|e| {
                                se_core::scope::unreadable(
                                    "Claude readiness record",
                                    &e.to_string(),
                                )
                            })?;
                        if let Some(id) = row.get("sessionId").and_then(serde_json::Value::as_str) {
                            if id != wanted.as_str() {
                                return Err(SeError::invalid(
                                    "Claude window conversation",
                                    "the selected conversation in the provider-written transcript",
                                ));
                            }
                            ready = true;
                        }
                        start = index + 1;
                    }
                    pending.drain(..start);
                    if pending.len() > completion::MAX_LINE
                        || chunk.next_offset > 4 * 1024 * 1024 && !ready
                    {
                        return Err(SeError::too_large(
                            "Claude window readiness scan",
                            4 * 1024 * 1024,
                            chunk.next_offset as usize,
                        ));
                    }
                    Ok((source, chunk.next_offset, pending, ready))
                })
                .await
                .map_err(|e| {
                    se_core::scope::unreadable("Claude readiness worker", &e.to_string())
                })??;
            source = returned;
            offset = position;
            pending = tail;
            if ready {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let binding = Arc::new(Binding {
            bell_session: request.request.identity.session.clone(),
            io: self.io.clone(),
            transport: request.transport,
            conversation: conversation.clone(),
            transcript,
            attended: true,
            completion: completion::Completion::default(),
            drains: Mutex::default(),
        });
        Ok(LaunchOutcome {
            witness: BindingWitness {
                identity: request.request.identity,
                conversation,
                lifecycle: request.record.lifecycle,
                provider,
            },
            binding: HarnessBinding {
                claude: Some(binding),
                codex: None,
                _private: (),
            },
        })
    }
}
