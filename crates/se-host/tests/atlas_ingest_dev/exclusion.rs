use super::*;

pub(super) fn exercise(
    source: &RegisteredSource<NativeAtlasSource>,
    db: &mut CacheConnection<'_>,
    parser: &mut SemanticParser,
    dir: &std::path::Path,
) -> Check {
    let direct = RelativePath::new("choice.js")?;
    let index = RelativePath::new("choice/index.js")?;
    let user = RelativePath::new("choice-user.js")?;
    fs::create_dir(dir.join("choice"))?;
    for path in [&direct, &index] {
        fs::write(
            dir.join(path.as_str()),
            "export function selected(){return 1;}",
        )?;
    }
    fs::write(
        dir.join(user.as_str()),
        "import {selected} from './choice'; selected();",
    )?;
    for (path, serial) in [(&direct, 50), (&index, 51), (&user, 52)] {
        ingest(source, db, parser, path, Language::JavaScript, true, serial)?;
    }
    db.read(deadline(), |sql| {
        let resolved: i64 = sql.prepare("SELECT count(*) FROM imports i JOIN files f ON f.id=i.file WHERE f.path='choice-user.js' AND i.target_file IS NOT NULL")?
            .query_row([], |r| r.get(0)).map_err(|e|se_types::SeError::invalid("development SQL", &e.to_string()))?;
        assert_eq!(resolved, 0, "ambiguous candidate acquired a fabricated target");
        Ok(())
    })?;
    db.write(2_000_000, deadline(), |sql| {
        sql.prepare("DELETE FROM pending_paths")?.execute([]).map_err(|e|se_types::SeError::invalid("development SQL", &e.to_string()))?;
        let before: i64 = sql.prepare("SELECT count(*) FROM changes")?.query_row([], |r|r.get(0)).map_err(|e|se_types::SeError::invalid("development SQL", &e.to_string()))?;
        assert!(observation::excluded(sql, &source.scope, &direct, 53)?);
        assert!(!observation::excluded(sql, &source.scope, &direct, 53)?);
        let after: i64 = sql.prepare("SELECT count(*) FROM changes")?.query_row([], |r|r.get(0)).map_err(|e|se_types::SeError::invalid("development SQL", &e.to_string()))?;
        assert_eq!(before, after, "ignore policy change fabricated a code edit");
        let queued: bool = sql.prepare("SELECT EXISTS(SELECT 1 FROM pending_paths WHERE path_key='choice-user.js' AND serial=53)")?.query_row([], |r|r.get(0)).map_err(|e|se_types::SeError::invalid("development SQL", &e.to_string()))?;
        assert!(queued, "unresolved candidate importer was not queued");
        Ok(())
    })?;
    assert!(
        dir.join(direct.as_str()).is_file(),
        "exclusion must not remove the source"
    );
    ingest(source, db, parser, &user, Language::JavaScript, false, 54)?;
    db.read(deadline(), |sql| {
        let resolved: i64 = sql.prepare("SELECT count(*) FROM imports i JOIN files f ON f.id=i.file JOIN files target ON target.id=i.target_file WHERE f.path='choice-user.js' AND target.path='choice/index.js'")?.query_row([], |r|r.get(0)).map_err(|e|se_types::SeError::invalid("development SQL", &e.to_string()))?;
        assert_eq!(resolved, 1, "unchanged importer did not select the remaining candidate");
        Ok(())
    })?;
    Ok(())
}
