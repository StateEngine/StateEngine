//! The supervisor drains bounded batches from the durable cursor until EOF or
//! its existing deadline. Its private result contains the last batch only;
//! earlier receipts remain durable, never an unbounded response allocation.
use super::*;

impl Capturing<'_> {
    pub(super) async fn capture(
        &self,
        admission: se_store::Admission,
        terminal: se_core::admission::HumanTerminal,
        selections: Option<se_core::ops::CliSelections>,
        hook: crate::ClaudeHookInput,
        deadline: &Deadline,
    ) -> Result<ExecutedCall> {
        let batch = self
            .batch(admission, terminal, selections, hook, deadline)
            .await?;
        if batch.complete {
            return Ok(batch.result);
        }
        Err(incomplete(batch.result, "At most 128 commits per hook signal; the coordinator continues final capture from the durable cursor, or repeat the same hook.".into()))
    }

    pub(super) async fn drain(
        &self,
        admission: se_store::Admission,
        terminal: se_core::admission::HumanTerminal,
        hook: crate::ClaudeHookInput,
        deadline: &Deadline,
    ) -> Result<ExecutedCall> {
        let mut previous = None;
        let mut completed_batches = 0_u64;
        loop {
            let signal = crate::ClaudeHookInput {
                kind: hook.kind,
                conversation: hook.conversation.clone(),
                claimed_transcript: hook.claimed_transcript.clone(),
                payload: serde_json::Value::Null,
            };
            let result = self
                .batch(admission.clone(), terminal.clone(), None, signal, deadline)
                .await;
            let batch = match result {
                Ok(batch) => batch,
                Err(error) => {
                    return Err(match previous {
                        Some(result) => incomplete(result, format!("{completed_batches} complete capture batches are durable; the diagnostic lists the last complete batch only. A later batch failed: {error}")).with_cause(error),
                        None => error,
                    });
                }
            };
            if batch.complete {
                return Ok(batch.result);
            }
            completed_batches = completed_batches.saturating_add(1);
            previous = Some(batch.result);
        }
    }
}

fn incomplete(result: ExecutedCall, reason: String) -> SeError {
    SeError::new(se_types::Detail::CaptureIncomplete(
        se_types::details::CaptureIncomplete {
            committed_events: result
                .capture_commits
                .into_iter()
                .map(|commit| commit.event_id)
                .collect(),
            natural_keys: result.capture_keys,
            reason,
        },
    ))
}
