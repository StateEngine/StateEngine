use super::*;
use se_atlas::coverage::CoverageScan;

fn error(e: impl std::fmt::Display) -> se_types::SeError {
    se_types::SeError::invalid("coverage development SQL", &e.to_string())
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn exercise(db: &mut CacheConnection<'_>, initial: &Coverage) -> Check {
    for group in 0..3 {
        db.write(2_000_000, deadline(), |sql| {
            for offset in 0..64 {
                let number = group * 64 + offset;
                let coverage = match number % 5 {
                    0 => FileCoverage::Indexed,
                    1 => FileCoverage::Partial { reasons: vec![CoverageReason::ParseErrors] },
                    2 => FileCoverage::Deferred { reason: CoverageReason::ParserUnqualified },
                    3 => FileCoverage::Failed { error: se_types::SeError::invalid("fixture", "read failure").body },
                    _ => FileCoverage::Stale { reason: CoverageReason::SourceBytesLimit, last_good_generation: Generation(1), observed_hash: None, diagnostic: None },
                };
                sql.prepare("INSERT INTO files(key,path,path_key,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?2,?3,0,0,0)")?
                    .execute(((10_000u128 + number as u128).to_le_bytes().as_slice(), format!("coverage-{number}"), serde_json::to_string(&coverage).map_err(error)?)).map_err(error)?;
            }
            Ok(())
        })?;
        db.checkpoint(deadline())?;
    }
    // Enough references for several windows, with holes in both key ranges.
    for _ in 0..20 {
        db.write(2_000_000, deadline(), |sql| {
            for _ in 0..128 {
                sql.prepare("INSERT INTO refs(file,spelling,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,accuracy) SELECT file,spelling,kind,0,1,1,0,1,1,'NameOnly' FROM refs LIMIT 1")?
                    .execute([]).map_err(error)?;
            }
            Ok(())
        })?;
        db.checkpoint(deadline())?;
    }
    db.write(2_000_000, deadline(), |sql| {
        sql.prepare("DELETE FROM refs WHERE id%7=0")?
            .execute([])
            .map_err(error)?;
        sql.prepare("DELETE FROM files WHERE path LIKE 'coverage-%' AND id%7=0")?
            .execute([])
            .map_err(error)?;
        Ok(())
    })?;
    let expected = db.read(deadline(), |sql| {
        let mut counts = [0u64; 8];
        let mut statement = sql.prepare("SELECT coverage_json FROM files")?;
        let mut rows = statement.query([]).map_err(error)?;
        while let Some(row) = rows.next().map_err(error)? {
            let value: FileCoverage =
                serde_json::from_str(&row.get::<_, String>(0).map_err(error)?).map_err(error)?;
            counts[0] += 1;
            counts[match value {
                FileCoverage::Indexed => 1,
                FileCoverage::Partial { .. } => 2,
                FileCoverage::Deferred { .. } => 3,
                FileCoverage::Failed { .. } => 4,
                FileCoverage::Stale { .. } => 5,
            }] += 1;
        }
        counts[6] = sql
            .prepare("SELECT count(*) FROM refs WHERE target IS NOT NULL")?
            .query_row([], |r| r.get::<_, i64>(0))
            .map_err(error)?
            .try_into()
            .map_err(error)?;
        counts[7] = sql
            .prepare("SELECT count(*) FROM refs WHERE accuracy='NameOnly'")?
            .query_row([], |r| r.get::<_, i64>(0))
            .map_err(error)?
            .try_into()
            .map_err(error)?;
        assert!(counts[6] > 0 && counts[7] > 2048);
        Ok(counts)
    })?;
    let mut scan = CoverageScan::default();
    let mut observed = initial.clone();
    assert!(scan.apply(&mut observed).is_err());
    assert!(scan.step(db, Instant::now()).is_err());
    let mut steps = 1;
    while !scan.step(db, deadline())? {
        assert!(scan.apply(&mut observed).is_err(), "partial totals escaped");
        steps += 1;
        assert!(steps < 100, "keyset did not converge");
    }
    assert!(steps >= 6, "graph was scanned in one transaction");
    scan.apply(&mut observed)?;
    assert_eq!(
        [
            observed.discovered_files,
            observed.indexed_files,
            observed.partial_files,
            observed.deferred_files,
            observed.failed_files,
            observed.stale_files,
            observed.resolved_references,
            observed.name_only_references
        ],
        expected
    );
    for reason in [
        CoverageReason::ParseErrors,
        CoverageReason::ParserUnqualified,
        CoverageReason::SourceBytesLimit,
    ] {
        assert!(observed.reasons.contains(&reason));
    }
    println!(
        "native coverage scan: {steps} bounded windows; exact mixed coverage/reference counts; incomplete and expired scans refused"
    );
    Ok(())
}
