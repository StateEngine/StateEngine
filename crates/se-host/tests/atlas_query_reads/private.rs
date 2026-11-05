//! Retained-cache policy checks use the same native reader as the outer test.
use super::*;
pub(super) fn retained(
    reader: &QueryReader<'_>,
    cache: &CacheConnection<'_>,
    pointer: &CodePointer,
    request: &ResumeRequest,
    query: &FindQuery,
    budget: QueryBudget,
) -> Check {
    // A retained pre-policy cache cannot reveal a private source while renewal
    // retires it. All readers apply the same built-in policy before output.
    let mut denied_pointer = pointer.clone();
    denied_pointer.path = RelativePath::new("secrets.py")?;
    cache.write(131072, end(), |sql| {
        sql.prepare("UPDATE files SET path='secrets.py',path_key='secrets.py' WHERE id=1")?
            .execute([])
            .map_err(fail)?;
        sql.prepare("UPDATE changes SET path='secrets.py',pointer_json=?1 WHERE file_key=?2")?
            .execute((
                serde_json::to_string(&denied_pointer).map_err(fail)?,
                pointer.file.0.as_slice(),
            ))
            .map_err(fail)?;
        Ok(())
    })?;
    let mut denied = query.clone();
    denied.kind = SearchKind::Symbol;
    assert!(present(reader.find(&denied)?.data)?.page.items().is_empty());
    assert!(matches!(
        reader
            .outline(&OutlineQuery {
                path: denied_pointer.path.clone(),
                next: None,
                budget
            })?
            .data,
        se_types::Read::Unknown { .. }
    ));
    let target = AtlasTarget::Symbol(SymbolSelector::Id(SymbolId([1; 32])));
    assert!(matches!(
        reader
            .refs(&RefsQuery {
                target: target.clone(),
                kinds: vec![],
                include_name_only: true,
                next: None,
                budget
            })?
            .data,
        se_types::Read::Unknown { .. }
    ));
    assert!(matches!(
        reader
            .impact(&ImpactQuery {
                target,
                depth: 1,
                include_name_only: false,
                next: None,
                budget
            })?
            .data,
        se_types::Read::Unknown { .. }
    ));
    let changes = present(
        reader
            .changes(&ChangesQuery {
                since: ChangeBaseline::Cursor(
                    request
                        .saved_cursor
                        .clone()
                        .ok_or("saved baseline missing")?,
                ),
                scope: SearchScope {
                    paths: vec![],
                    languages: vec![],
                },
                next: None,
                budget,
            })?
            .data,
    )?;
    assert!(changes.items().is_empty());
    assert!(reader.resume_code(request)?.items.is_empty());
    Ok(())
}
