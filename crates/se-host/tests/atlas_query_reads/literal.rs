//! A literal source window must not lose metadata behind an unrelated global cap.
use super::*;
pub(super) fn check(
    reader: &QueryReader<'_>,
    cache: &CacheConnection<'_>,
    source: &se_atlas::source::RegisteredSource<NativeAtlasSource>,
    query: &FindQuery,
) -> Check {
    let root = &source.scope.registration.canonical_source_root;
    fs::create_dir(root.join("literal"))?;
    for id in 0..129 {
        fs::write(
            root.join(format!("literal/{id:03}.rs")),
            "fn local_needle() {}\n",
        )?;
    }
    cache.write(1_000_000, end(), |sql| {
        sql.prepare("INSERT INTO names(text) VALUES('local_needle')")?
            .execute([]).map_err(fail)?;
        for id in 0i64..129 {
            let row = 1000 + id;
            let mut file = [0u8;16];
            file[..8].copy_from_slice(&row.to_be_bytes());
            let mut symbol = [0u8;32];
            symbol[..8].copy_from_slice(&row.to_be_bytes());
            let path = format!("literal/{id:03}.rs");
            sql.prepare("INSERT INTO files(id,key,path,path_key,language,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?3,?3,'Rust',21,x'01','\"Indexed\"',1,0,0)")?
                .execute((row,file.as_slice(),path)).map_err(fail)?;
            sql.prepare("INSERT INTO symbols(id,key,file,name,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,exported,doc_line) VALUES(?1,?2,?1,(SELECT id FROM names WHERE text='local_needle'),'Function',0,20,1,0,1,20,0,'')")?
                .execute((row,symbol.as_slice())).map_err(fail)?;
            if id == 128 {
                sql.prepare("INSERT INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_record,restricted_record) VALUES('file',?1,0,'edit',NULL,1,NULL,NULL)")?
                    .execute([file.as_slice()]).map_err(fail)?;
                sql.prepare("INSERT INTO activity VALUES('file',?1,1,0)")?
                    .execute([file.as_slice()]).map_err(fail)?;
            }
        }
        Ok(())
    })?;
    let mut query = query.clone();
    query.kind = SearchKind::Code;
    query.mode = Some(SearchMode::Literal);
    query.query = QueryText::new("local_needle")?;
    query.scope.paths = vec![RelativePath::new("literal")?];
    query.budget = Validate.query_budget(1, 16384)?;
    let result = present(reader.find(&query)?.data)?;
    assert!(
        matches!(&result.page.items()[0].target, HitTarget::Code(code)
        if code.pointer.path.as_str() == "literal/128.rs" && code.symbol.is_some()),
        "a global metadata cap demoted the newest literal symbol to plain text"
    );
    assert_eq!(result.page.items()[0].reason.match_tier, 1);
    query.scope.paths = vec![RelativePath::new("literal/128.rs")?];
    for (text, tier, symbol) in [
        ("local_needle", 1, true),
        ("local_nee", 2, true),
        ("cal_need", 4, true),
        ("literal/128", 3, false),
    ] {
        query.query = QueryText::new(text)?;
        let result = present(reader.find(&query)?.data)?;
        assert_eq!(result.page.items()[0].reason.match_tier, tier);
        assert!(
            matches!(&result.page.items()[0].target, HitTarget::Code(code)
            if code.symbol.is_some() == symbol)
        );
        if symbol && let HitTarget::Code(code) = &result.page.items()[0].target {
            assert_eq!(code.name, "local_needle");
            assert_eq!(code.kind, Some(SymbolKind::Function));
            let span = code
                .pointer
                .span
                .as_ref()
                .ok_or("literal symbol span absent")?;
            assert_eq!(
                (span.start_byte, span.end_byte, span.start.line),
                (0, 20, 1)
            );
        }
    }
    for text in ["LOCAL_NEEDLE", "local needle"] {
        query.query = QueryText::new(text)?;
        assert!(
            present(reader.find(&query)?.data)?.page.items().is_empty(),
            "literal mode ignored smart case or split identifiers"
        );
    }
    Ok(())
}
