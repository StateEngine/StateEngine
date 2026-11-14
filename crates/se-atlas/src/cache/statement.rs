//! Finite SQL statement and row admission, sharing one snapshot deadline.
use super::*;
pub struct SqlView<'a> {
    pub(super) db: &'a Connection,
    pub(super) count: Cell<usize>,
    pub(super) bytes: Cell<usize>,
    pub(super) readonly: bool,
    pub(super) deadline: Instant,
}
impl SqlView<'_> {
    pub fn prepare(&self, sql: &str) -> AtlasResult<BudgetStatement<'_>> {
        // A previous statement or native operation may have consumed the
        // allowance. Do not start another query on an expired snapshot.
        if crate::clock::now() >= self.deadline {
            return Err(timeout(0));
        }
        let stmt = self.db.prepare(sql).map_err(cache_error)?;
        if self.readonly && !stmt.readonly() {
            return Err(cache_error(
                "mutation attempted inside an Atlas read snapshot",
            ));
        }
        let bytes =
            usize::try_from(stmt.get_status(StatementStatus::MemUsed)).map_err(cache_error)?;
        if self.count.get() >= 8 || self.bytes.get() + bytes > STATEMENT_BYTES {
            return Err(capacity(
                "Atlas SQL statement memory",
                bytes as u64,
                STATEMENT_BYTES.saturating_sub(self.bytes.get()) as u64,
            ));
        }
        self.count.set(self.count.get() + 1);
        self.bytes.set(self.bytes.get() + bytes);
        Ok(BudgetStatement {
            stmt,
            count: &self.count,
            bytes: &self.bytes,
            reserved: bytes,
            deadline: self.deadline,
        })
    }
}
pub struct BudgetStatement<'a> {
    stmt: Statement<'a>,
    count: &'a Cell<usize>,
    bytes: &'a Cell<usize>,
    reserved: usize,
    deadline: Instant,
}
impl BudgetStatement<'_> {
    fn ready(&self) -> rusqlite::Result<()> {
        if crate::clock::now() >= self.deadline {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT),
                Some("Atlas SQL snapshot deadline expired before statement execution".into()),
            ));
        }
        Ok(())
    }
    pub fn execute<P: rusqlite::Params>(&mut self, params: P) -> rusqlite::Result<usize> {
        self.ready()?;
        self.stmt.execute(params)
    }
    pub fn query<P: rusqlite::Params>(&mut self, params: P) -> rusqlite::Result<BudgetRows<'_>> {
        self.ready()?;
        Ok(BudgetRows {
            rows: self.stmt.query(params)?,
            deadline: self.deadline,
            finished: false,
        })
    }
    pub fn query_map<T, P, F>(
        &mut self,
        params: P,
        map: F,
    ) -> rusqlite::Result<BudgetMappedRows<'_, F>>
    where
        P: rusqlite::Params,
        F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        Ok(BudgetMappedRows {
            rows: self.query(params)?,
            map,
        })
    }
    pub fn query_row<T, P, F>(&mut self, params: P, read: F) -> rusqlite::Result<T>
    where
        P: rusqlite::Params,
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        let mut rows = self.query(params)?;
        read(rows.next()?.ok_or(rusqlite::Error::QueryReturnedNoRows)?)
    }
}
impl<'a> Deref for BudgetStatement<'a> {
    type Target = Statement<'a>;
    fn deref(&self) -> &Self::Target {
        &self.stmt
    }
}
impl Drop for BudgetStatement<'_> {
    fn drop(&mut self) {
        self.count.set(self.count.get() - 1);
        self.bytes.set(self.bytes.get() - self.reserved);
    }
}

pub struct BudgetRows<'statement> {
    rows: rusqlite::Rows<'statement>,
    deadline: Instant,
    finished: bool,
}
impl BudgetRows<'_> {
    // Like rusqlite::Rows, a returned row borrows the cursor; this is not an
    // Iterator that can retain an unbounded vector of row references.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> rusqlite::Result<Option<&rusqlite::Row<'_>>> {
        if self.finished {
            return Ok(None);
        }
        if crate::clock::now() >= self.deadline {
            self.finished = true;
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT),
                Some("Atlas SQL snapshot expired before reading the next row".into()),
            ));
        }
        let row = self.rows.next();
        if !matches!(&row, Ok(Some(_))) {
            self.finished = true;
        }
        row
    }
}
pub struct BudgetMappedRows<'statement, F> {
    rows: BudgetRows<'statement>,
    map: F,
}
impl<T, F> Iterator for BudgetMappedRows<'_, F>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    type Item = rusqlite::Result<T>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.rows.next() {
            Ok(Some(row)) => Some((self.map)(row)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}
