//! Protected whole-home session inventory for an explicit bound startup.
use crate::{
    ReadBudget, StateFiles, StoreErrorCode, StoreResult, error::*, identity, open::SqliteReader,
    owner_guard,
};
use se_types::{ProjectId, SessionId};
use std::time::Instant;

impl SqliteReader {
    /// Read every saved session, including sessions under removed projects.
    /// A capacity or deadline failure is an error, never an empty inventory.
    pub fn bound_sessions(
        &self,
        files: &dyn StateFiles,
        budget: ReadBudget,
    ) -> StoreResult<Vec<(ProjectId, SessionId)>> {
        owner_guard::with_source(&self.path, files, budget, |budget, deadline| {
            let mut phase = self.read_phase()?;
            let result = read(&mut phase.db, budget, deadline);
            phase.finish(result)
        })
    }
}

fn read(
    db: &mut rusqlite::Connection,
    budget: &ReadBudget,
    deadline: Instant,
) -> StoreResult<Vec<(ProjectId, SessionId)>> {
    db.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(sql)?;
    let result = (|| {
        let mut query = db
            .prepare("SELECT project_id, session_id FROM sessions ORDER BY first_seq LIMIT ?")
            .map_err(sql)?;
        let maximum =
            usize::try_from(budget.page.limit.get()).map_err(|_| invalid("session limit"))?;
        let mut rows = query
            .query([i64::from(budget.page.limit.get()) + 1])
            .map_err(sql)?;
        let mut output = Vec::new();
        let mut bytes = 0usize;
        while let Some(row) = rows.next().map_err(sql)? {
            if output.len() == maximum || Instant::now() >= deadline {
                return Err(fail(
                    StoreErrorCode::ReadIncomplete,
                    "bound session inventory exceeds its complete read budget",
                ));
            }
            let project: Vec<u8> = row.get(0).map_err(sql)?;
            let session: Vec<u8> = row.get(1).map_err(sql)?;
            let mut scope = vec![1];
            scope.extend_from_slice(&project);
            let project = identity::wire(db, "project", &project, &[0])?;
            let session = identity::wire(db, "session", &session, &scope)?;
            bytes = bytes
                .saturating_add(project.len())
                .saturating_add(session.len());
            if bytes > budget.page.max_bytes.get() as usize {
                return Err(fail(
                    StoreErrorCode::ReadIncomplete,
                    "bound session inventory exceeds its byte budget",
                ));
            }
            output.push((
                project.parse().map_err(|_| invalid("stored project id"))?,
                session.parse().map_err(|_| invalid("stored session id"))?,
            ));
        }
        Ok(output)
    })();
    db.progress_handler(0, None::<fn() -> bool>).map_err(sql)?;
    result
}
