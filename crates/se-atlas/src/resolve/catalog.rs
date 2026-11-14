//! SQL-backed export lookup: bounded rows, explicit ambiguity, eight hops.
use super::*;
use crate::{cache::connection::SqlView, errors::cache_error};
use rusqlite::{OptionalExtension, params};
use se_types::code::AtlasText;
pub struct SqlCatalog<'a, 'db> {
    pub sql: &'a SqlView<'db>,
    pub deadline: Instant,
}
impl Catalog for SqlCatalog<'_, '_> {
    fn file(&mut self, path: &RelativePath) -> AtlasResult<Option<FileId>> {
        let key: Option<Vec<u8>> = self
            .sql
            .prepare("SELECT key FROM files WHERE path_key=?1 AND coverage_json='\"Indexed\"'")?
            .query_row([path.as_str()], |r| r.get(0))
            .optional()
            .map_err(cache_error)?;
        key.map(|v| {
            v.try_into()
                .map(FileId)
                .map_err(|_| cache_error("invalid file key"))
        })
        .transpose()
    }
    fn export(&mut self, file: FileId, name: &str, max_hops: u8) -> AtlasResult<Export> {
        let mut visited = Vec::new();
        self.lookup(file, name, max_hops.min(8), &mut visited)
    }
}
impl SqlCatalog<'_, '_> {
    fn lookup(
        &mut self,
        file: FileId,
        name: &str,
        hops: u8,
        visited: &mut Vec<(FileId, String)>,
    ) -> AtlasResult<Export> {
        if crate::clock::now() >= self.deadline
            || visited.iter().any(|v| v.0 == file && v.1 == name)
        {
            return Ok(Export::Incomplete);
        }
        visited.push((file, name.to_owned()));
        let result = (|| {
            let mut statement=self.sql.prepare("SELECT s.key FROM symbols s JOIN files f ON f.id=s.file JOIN names n ON n.id=s.name WHERE f.key=?1 AND f.coverage_json='\"Indexed\"' AND s.exported=1 AND s.parent IN (SELECT id FROM symbols WHERE file=s.file AND parent IS NULL AND kind='Module') AND (n.text=?2 OR s.export_alias=?2) LIMIT 2")?;
            let mut rows = statement
                .query(params![file.0.as_slice(), name])
                .map_err(cache_error)?;
            let mut direct = None;
            if let Some(row) = rows.next().map_err(cache_error)? {
                let key: Vec<u8> = row.get(0).map_err(cache_error)?;
                direct = Some(SymbolId(
                    key.try_into()
                        .map_err(|_| cache_error("invalid symbol key"))?,
                ));
            }
            if rows.next().map_err(cache_error)?.is_some() {
                return Ok(Export::Ambiguous);
            }
            drop(rows);
            drop(statement);
            let mut statement=self.sql.prepare("SELECT target.key,imported.text FROM imports i JOIN files f ON f.id=i.file JOIN files target ON target.id=i.target_file LEFT JOIN names local ON local.id=i.local_name LEFT JOIN names imported ON imported.id=i.imported_name WHERE f.key=?1 AND f.coverage_json='\"Indexed\"' AND target.coverage_json='\"Indexed\"' AND i.reexport=1 AND i.wildcard=0 AND local.text=?2 LIMIT 2")?;
            let mut rows = statement
                .query(params![file.0.as_slice(), name])
                .map_err(cache_error)?;
            let mut redirected = None;
            if let Some(row) = rows.next().map_err(cache_error)? {
                let key: Vec<u8> = row.get(0).map_err(cache_error)?;
                let target = FileId(
                    key.try_into()
                        .map_err(|_| cache_error("invalid export file key"))?,
                );
                let name: Option<String> = row.get(1).map_err(cache_error)?;
                redirected = name.map(|name| (target, name));
            }
            if rows.next().map_err(cache_error)?.is_some()
                || direct.is_some() && redirected.is_some()
            {
                return Ok(Export::Ambiguous);
            }
            drop(rows);
            drop(statement);
            if let Some(symbol) = direct {
                return Ok(Export::Symbol(symbol));
            }
            if let Some((target, name)) = redirected {
                if hops == 0 {
                    return Ok(Export::Incomplete);
                }
                return self.lookup(target, &name, hops - 1, visited);
            }
            Ok(Export::Missing)
        })();
        visited.pop();
        result
    }
}
