//! Providers that allocate a conversation after C1 publish its actual reference
//! through the committed source binding. A preparation is never a vendor ID.
use crate::{scope, store_error::store_error};
use se_store::{EventBody, ProjectionRecord, Snapshot};
use se_types::{ProviderSessionId, Read, Result};
pub const CODEX_PENDING: &str = "se-codex-pending:";
pub const SECODE_PENDING: &str = "se-secode-pending:";

pub fn read<R: Snapshot>(
    read: &mut R,
    record: &ProjectionRecord,
) -> Result<Read<ProviderSessionId>> {
    let first = record.original.as_deref().unwrap_or(&record.current);
    let EventBody::SessionPrepared {
        session,
        provider,
        native_ref,
        consent,
        surface,
        ..
    } = &first.body
    else {
        return Err(scope::unreadable(
            "provider conversation",
            "the original session preparation is unavailable",
        ));
    };
    let pending = match provider {
        se_store::Provider::Codex if native_ref.starts_with(CODEX_PENDING) => Some("Codex"),
        se_store::Provider::SeCode
            if *surface == Some(se_store::SessionSurface::Headless)
                && native_ref.starts_with(SECODE_PENDING) =>
        {
            Some("SE Code")
        }
        _ => None,
    };
    let Some(provider) = pending else {
        return if native_ref.is_empty() {
            Ok(Read::Absent {
                checked: "no provider reference was recorded in this historical session".into(),
            })
        } else {
            Ok(Read::Present {
                value: ProviderSessionId::new(native_ref.clone())?,
            })
        };
    };
    let subject = format!("actual {provider} thread binding");
    let id = super::process_commit::session_credential_id(session, "capture-source")?;
    let source = match read.capture_source(id).map_err(|e| store_error(&e))? {
        Read::Absent { .. }
            if matches!(
                record.current.body,
                EventBody::SessionPrepared { .. } | EventBody::SessionRevoked { .. }
            ) =>
        {
            return Ok(Read::Absent {
                checked: format!(
                    "this {provider} preparation never acquired an activated provider thread"
                ),
            });
        }
        other => scope::require_present(
            other,
            &subject,
            "Restore the original committed source binding; a C1 placeholder cannot resume a conversation.",
        )?,
    };
    match &source.original.as_deref().unwrap_or(&source.current).body {
        EventBody::CaptureSource {
            source: found,
            session: bound,
            native_ref: actual,
            consent: captured,
            ..
        } if *found == id
            && bound == session
            && captured == consent
            && !actual.starts_with(CODEX_PENDING)
            && !actual.starts_with(SECODE_PENDING) =>
        {
            Ok(Read::Present {
                value: ProviderSessionId::new(actual.clone())?,
            })
        }
        _ => Err(scope::unreadable(
            &subject,
            "the source identity, session, consent or actual provider reference differs",
        )),
    }
}
