//! Native source and SQL scopes share exact file/directory boundaries.
use super::*;
pub(super) fn check(
    reader: &QueryReader<'_>,
    cache: &CacheConnection<'_>,
    source: &se_atlas::source::RegisteredSource<NativeAtlasSource>,
    query: &FindQuery,
) -> Check {
    let root = &source.scope.registration.canonical_source_root;
    for path in ["src/inside.rs", "src2/outside.rs"] {
        let path = root.join(path);
        fs::create_dir_all(path.parent().ok_or("scope path parent")?)?;
        fs::write(path, "fn directory_marker() {}\n")?;
    }
    cache.write(65536,end(),|sql| {
        sql.prepare("INSERT INTO names(text) VALUES('directory_marker')")?.execute([]).map_err(fail)?;
        for (id,path) in [(51i64,"src/inside.rs"),(52,"src2/outside.rs")] {
            let file=[id as u8;16]; let symbol=[id as u8;32];
            sql.prepare("INSERT INTO files(id,key,path,path_key,language,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?3,?3,'Rust',25,x'01','\"Indexed\"',1,0,0)")?.execute((id,file.as_slice(),path)).map_err(fail)?;
            sql.prepare("INSERT INTO symbols(id,key,file,name,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,exported,doc_line) VALUES(?1,?2,?1,(SELECT id FROM names WHERE text='directory_marker'),'Function',0,24,1,0,1,24,0,'')")?.execute((id,symbol.as_slice())).map_err(fail)?;
            sql.prepare("INSERT INTO symbol_fts(rowid,name,split_name,path,container,doc_line) VALUES(?1,'directory_marker','directory marker',?2,'','')")?.execute((id,path)).map_err(fail)?;
        }
        // A postfilter would lose the only in-scope result behind this newer hit.
        sql.prepare("INSERT INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_record,restricted_record) VALUES('file',?1,0,'edit',NULL,1,NULL,NULL)")?.execute([[52u8;16].as_slice()]).map_err(fail)?;
        sql.prepare("INSERT INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_record,restricted_record) VALUES('symbol',?1,0,'edit',NULL,1,NULL,NULL)")?.execute([[52u8;32].as_slice()]).map_err(fail)?;
        sql.prepare("INSERT INTO activity VALUES('file',?1,1,0)")?.execute([[52u8;16].as_slice()]).map_err(fail)?;
        sql.prepare("INSERT INTO activity VALUES('symbol',?1,1,0)")?.execute([[52u8;32].as_slice()]).map_err(fail)?;
        Ok(())
    })?;
    let mut scoped = query.clone();
    scoped.query = QueryText::new("directory_marker")?;
    scoped.budget = Validate.query_budget(1, 16384)?;
    scoped.scope.paths = vec![RelativePath::new("src")?];
    scoped.scope.languages = vec![Language::Rust];
    for kind in [SearchKind::Symbol, SearchKind::Text] {
        scoped.kind = kind;
        scoped.mode = Some(SearchMode::Literal);
        let page = present(reader.find(&scoped)?.data)?;
        assert_eq!(page.page.items().len(), 1);
        assert!(
            matches!(&page.page.items()[0].target,HitTarget::Code(code) if code.pointer.path.as_str()=="src/inside.rs"),
            "out-of-scope activity consumed the ranked result window"
        );
    }
    scoped.kind = SearchKind::Symbol;
    scoped.query = QueryText::new("directory marker")?;
    assert!(
        present(reader.find(&scoped)?.data)?.page.items().is_empty(),
        "literal mode silently split an identifier"
    );
    scoped.mode = Some(SearchMode::Broad);
    assert_eq!(present(reader.find(&scoped)?.data)?.page.items().len(), 1);
    scoped.kind = SearchKind::Code;
    scoped.mode = Some(SearchMode::Literal);
    scoped.regex = true;
    scoped.query = QueryText::new("directory_marker$")?;
    assert!(
        present(reader.find(&scoped)?.data)?.page.items().is_empty(),
        "a regex was treated as a split metadata lookup"
    );
    scoped.regex = false;
    scoped.query = QueryText::new("directory_marker")?;
    // A newly built cache has no touch rows. Exercise its indexed path walk
    // across multiple SQL batches and pages without retaining invented activity.
    cache.write(65536, end(), |sql| {
        sql.prepare("DELETE FROM touches")?
            .execute([])
            .map_err(fail)?;
        sql.prepare("DELETE FROM activity")?
            .execute([])
            .map_err(fail)?;
        Ok(())
    })?;
    scoped.scope.paths.clear();
    scoped.scope.languages.clear();
    let first = present(reader.find(&scoped)?.data)?;
    assert!(
        matches!(&first.page.items()[0].target,HitTarget::Code(code) if code.pointer.path.as_str()=="src/inside.rs")
    );
    scoped.next = Some(AtlasCursor::new(
        first
            .page
            .next()
            .ok_or("cold path page lost continuation")?
            .as_str(),
    )?);
    let second = present(reader.find(&scoped)?.data)?;
    assert!(
        matches!(&second.page.items()[0].target,HitTarget::Code(code) if code.pointer.path.as_str()=="src2/outside.rs")
    );
    scoped.next = None;
    scoped.scope.paths = vec![RelativePath::new("src/inside.rs")?];
    assert_eq!(present(reader.find(&scoped)?.data)?.page.items().len(), 1);
    scoped.scope.paths = vec![RelativePath::new("src3")?];
    assert!(present(reader.find(&scoped)?.data)?.page.items().is_empty());
    Ok(())
}
