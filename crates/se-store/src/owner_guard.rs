//! Private pre-admission inventory for the native owner guard, never a product reader.
use crate::codec::process;
use crate::{connection, error::*, identity, open::SqliteReader, *};
use rusqlite::Connection;
use se_types::Read;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
pub(crate) fn read(
    reader: &SqliteReader,
    files: &dyn StateFiles,
    budget: ReadBudget,
) -> StoreResult<OwnerGuardInventory> {
    if budget.page.after.is_some()
        || budget.page.limit.get() > 1000
        || budget.page.max_bytes.get() > 2 * 1024 * 1024
        || budget.deadline.is_zero()
        || budget.deadline > Duration::from_secs(5)
    {
        return Err(fail(
            StoreErrorCode::ReadBudgetTooSmall,
            "owner guard requires one finite inventory: at most 1000 items, 2 MiB and five seconds, without a cursor",
        ));
    }
    let start = Instant::now();
    // A reader path alone proves no native custody. Require the actual native port.
    let _file = match files.readback(&reader.path)? {
        Read::Present { value } => value,
        _ => {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "protected owner-guard store access is not present; no empty inventory inferred",
            ));
        }
    };
    reader
        .slots
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < 2).then_some(n + 1)
        })
        .map_err(|_| {
            fail(
                StoreErrorCode::Backpressure,
                "two finite store read snapshots are already in use",
            )
        })?;
    let _slot = Slot(reader.slots.clone());
    let db = reader.connect()?;
    let deadline = start + budget.deadline;
    db.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(sql)?;
    db.execute_batch("BEGIN").map_err(sql)?;
    let result = inventory(&db, &budget, deadline);
    let result = result.map_err(|mut error| {
        if Instant::now() >= deadline {
            error.code = StoreErrorCode::ReadIncomplete;
            error.cause = format!("owner-guard deadline exhausted: {}", error.cause);
        }
        error
    });
    // Always close the finite transaction before releasing its shared read slot.
    db.progress_handler(0, None::<fn() -> bool>).map_err(sql)?;
    db.execute_batch("ROLLBACK").map_err(sql)?;
    result
}
fn inventory(
    db: &Connection,
    budget: &ReadBudget,
    deadline: Instant,
) -> StoreResult<OwnerGuardInventory> {
    let store = connection::info(db)?;
    if store.state != StoreState::Ready {
        return Err(fail(
            StoreErrorCode::NotReady,
            "owner-guard store is in maintenance",
        ));
    }
    if budget.page.max_bytes.get() < 1024 {
        return Err(fail(
            StoreErrorCode::ReadIncomplete,
            "owner-guard metadata exceeds the byte budget; no inventory returned",
        ));
    }
    let has_process_records = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM processes LIMIT 1)",
            [],
            |row| row.get(0),
        )
        .map_err(sql)?;
    let mut bytes = 1024usize;
    let mut count = 0usize;
    let mut charge = |size: usize| -> StoreResult<()> {
        count += 1;
        bytes = bytes
            .checked_add(size)
            .ok_or_else(|| invalid("owner-guard byte accounting overflow"))?;
        if count > budget.page.limit.get() as usize
            || bytes > budget.page.max_bytes.get() as usize
            || Instant::now() >= deadline
        {
            return Err(fail(
                StoreErrorCode::ReadIncomplete,
                "owner-guard inventory exceeds its item/byte/deadline budget; no partial inventory returned",
            ));
        }
        Ok(())
    };
    let mut owners = Vec::new();
    let mut q = db
        .prepare("SELECT human_id FROM owners ORDER BY human_id LIMIT ?")
        .map_err(sql)?;
    let mut rows = q
        .query([i64::from(budget.page.limit.get()) + 1])
        .map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let id: Vec<u8> = row.get(0).map_err(sql)?;
        let owner = identity::wire(db, "human", &id, &[0])?;
        charge(owner.len() + 64)?;
        owners.push(owner.parse().map_err(invalid)?);
    }
    let mut processes = Vec::new();
    let mut q = db.prepare("SELECT project_id,process_id,revision,last_seq,state FROM processes INDEXED BY processes_live WHERE ownership_released=0 AND state NOT IN ('exited','historical') LIMIT ?").map_err(sql)?;
    let mut rows = q
        .query([i64::from(budget.page.limit.get()) + 1])
        .map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let project: Vec<u8> = row.get(0).map_err(sql)?;
        let id: Vec<u8> = row.get(1).map_err(sql)?;
        let revision = crate::codec::revision(crate::sql_value::value(row, 2).map_err(sql)?)?;
        let seq: i64 = row.get(3).map_err(sql)?;
        let state: String = row.get(4).map_err(sql)?;
        let size = process::stored_size(db, seq)?;
        charge(
            size.checked_add(2048)
                .ok_or_else(|| invalid("owner-guard process size overflow"))?,
        )?;
        let identity =
            process::identity(db, seq, &project, &id, revision.value.get(), &state, true)?;
        processes.push(OwnerGuardProcess {
            project: identity::wire(db, "project", &project, &[0])?
                .parse()
                .map_err(invalid)?,
            revision,
            state: process::state(&state)?,
            identity,
        });
    }
    if Instant::now() >= deadline {
        return Err(fail(
            StoreErrorCode::ReadIncomplete,
            "owner-guard deadline exhausted",
        ));
    }
    Ok(OwnerGuardInventory {
        store,
        owners,
        has_process_records,
        processes,
    })
}
