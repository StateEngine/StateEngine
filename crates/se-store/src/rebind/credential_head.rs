//! Exact owner-only credential head for restart fencing and shutdown.
use super::*;

impl SqliteSnapshot {
    pub(super) fn read_credential_head(&self, id: RecordId) -> StoreResult<Read<CredentialHead>> {
        self.require_local_port()?;
        if !matches!(
            (&self.scope.admission.actor, &self.scope.visibility),
            (Actor::Human(_), Visibility::Owner)
        ) || self.scope.admission.session.is_some()
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "credential head requires owner maintenance",
            ));
        }
        let project = self.project_bytes()?;
        let row: Option<(Vec<u8>, i64)> = self.db.query_row(
            "SELECT secret_sha256,last_seq FROM credentials WHERE project_id=? AND credential_id=?",
            rusqlite::params![project, id.as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| self.read_sql(error))?;
        let Some((digest, last)) = row else {
            return Ok(self.absent("credential head"));
        };
        let hash: [u8; 32] = digest.try_into().map_err(|_| {
            fail(
                StoreErrorCode::ProjectionInconsistent,
                "credential digest length differs",
            )
        })?;
        let record = match crate::credential::read_at(&self.db, &self.info, hash)? {
            Read::Present { value } if value.credential == id => value,
            _ => {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "credential head differs from hash lookup",
                ));
            }
        };
        let event = self.record(last)?;
        let restart = match event.body {
            EventBody::CredentialRotated {
                credential,
                session,
                restart,
                ..
            } if credential == id && session == record.session => Some(restart),
            EventBody::CredentialIssued { credential, .. }
            | EventBody::CredentialActivated { credential, .. }
            | EventBody::CredentialRevoked { credential, .. }
                if credential == id =>
            {
                None
            }
            _ => {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "credential head event differs",
                ));
            }
        };
        Ok(Read::Present {
            value: CredentialHead { record, restart },
        })
    }
}
