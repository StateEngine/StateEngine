use super::*;
use se_atlas::resolve::{self, catalog::SqlCatalog};
use se_types::code::Language;
#[derive(Clone, Copy)]
pub(super) enum Mode {
    Observed(u64),
    Repair(u64),
}
impl Mode {
    fn serial(self) -> u64 {
        match self {
            Self::Observed(serial) | Self::Repair(serial) => serial,
        }
    }
}
pub(super) fn file(
    source: &Source,
    connection: &mut CacheConnection<'_>,
    policy: &AtlasPolicy,
    parser: &mut crate::atlas_parse::Parser,
    path: &RelativePath,
    mode: Mode,
    deadline: Instant,
) -> AtlasResult<()> {
    let serial = mode.serial();
    timely(deadline)?;
    let language = se_atlas::policy::language(path);
    let (mut budget, profile, observation_budget) =
        parse_budgets(policy, parser, language, deadline);
    let observed = read_or_observe(source, path, budget, observation_budget, language, profile);
    if matches!(&observed, Err(error) if matches!(error.body.detail(),
        Detail::DeadlineExceeded(detail) if detail.op == "Atlas source read"))
    {
        if budget.max_work < policy.parse.max_work {
            return observed.map(|_| ());
        }
        return Err(crate::atlas_parse::stall(budget.max_work));
    }
    guard_file_count(connection, deadline, source, path, policy, &observed)?;
    match observed {
        Err(error) => write_unparsed(
            connection,
            deadline,
            source,
            path,
            language,
            observation::UnparsedObservation::Failed(&error.body),
            serial,
        ),
        Ok(SourceRead::Removed) => connection.write(WAL, deadline, |sql| {
            observation::removed(sql, &source.scope, path, false, serial).map(|_| ())
        }),
        Ok(SourceRead::Deferred { identity, reason }) => write_unparsed(
            connection,
            deadline,
            source,
            path,
            language,
            observation::UnparsedObservation::Deferred {
                identity: &identity,
                reason,
            },
            serial,
        ),
        Ok(SourceRead::Hashed {
            identity,
            content_hash,
            reason,
        }) => write_unparsed(
            connection,
            deadline,
            source,
            path,
            language,
            observation::UnparsedObservation::Hashed {
                cold: false,
                identity: &identity,
                content_hash,
                reason,
            },
            serial,
        ),
        Ok(SourceRead::Bytes(snapshot)) => {
            // Reconciliation always reads/hashes the full unqualified native
            // revision. Stat identity alone never supplies an unchanged shortcut.
            if skip_unchanged(connection, deadline, source, path, mode, &snapshot)? {
                return Ok(());
            }
            let Some(language) = language else {
                return connection.write(WAL, deadline, |sql| {
                    observation::unparsed(
                        sql,
                        &source.scope,
                        path,
                        None,
                        observation::UnparsedObservation::Deferred {
                            identity: &snapshot.identity,
                            reason: CoverageReason::UnsupportedLanguage,
                        },
                        serial,
                    )
                    .map(|_| ())
                });
            };
            // The source read was bounded by this slice. Preserve the actual
            // file policy for the parser so it can distinguish a slice ending
            // early from exhausting the file's own work allowance.
            budget.max_work = policy.parse.max_work;
            timely(deadline)?;
            let parsed = parse_file(source, parser, path, language, budget, &snapshot, deadline)?;
            apply_parsed(source, connection, path, &snapshot, parsed, mode, deadline)
        }
    }
}
fn parse_budgets(
    policy: &AtlasPolicy,
    parser: &crate::atlas_parse::Parser,
    language: Option<Language>,
    deadline: Instant,
) -> (ParseBudget, Option<ParserProfile>, ParseBudget) {
    let mut budget = policy.parse;
    let profile = language.and_then(|language| parser.profile(language));
    if let Some(profile) = profile {
        // Reject an oversized source from its native identity before allocating
        // a body that the qualified parser cannot admit.
        budget.max_source_bytes = budget.max_source_bytes.min(profile.max_source_bytes);
        budget.max_rows = budget.max_rows.min(profile.max_rows);
        // Keep the policy's total parse reservation so the native tree can
        // borrow unused extraction space without exceeding that total.
        budget.reserved_bytes = budget.reserved_bytes.min(profile.anonymous_bytes() as u32);
    }
    budget.max_work = budget
        .max_work
        .min(deadline.saturating_duration_since(se_atlas::clock::now()));
    let mut observation_budget = policy.parse;
    observation_budget.max_work = budget.max_work;
    (budget, profile, observation_budget)
}

fn read_or_observe(
    source: &Source,
    path: &RelativePath,
    budget: ParseBudget,
    observation_budget: ParseBudget,
    language: Option<Language>,
    profile: Option<ParserProfile>,
) -> AtlasResult<SourceRead> {
    if profile.is_none() {
        source.observe(
            path,
            observation_budget,
            if language.is_some() {
                CoverageReason::ParserUnqualified
            } else {
                CoverageReason::UnsupportedLanguage
            },
        )
    } else {
        match source.read(path, budget) {
            Ok(SourceRead::Deferred {
                reason: CoverageReason::SourceBytesLimit,
                ..
            }) => source.observe(path, observation_budget, CoverageReason::SourceBytesLimit),
            read => read,
        }
    }
}

fn guard_file_count(
    connection: &mut CacheConnection<'_>,
    deadline: Instant,
    source: &Source,
    path: &RelativePath,
    policy: &AtlasPolicy,
    observed: &AtlasResult<SourceRead>,
) -> AtlasResult<()> {
    if !matches!(&observed, Ok(SourceRead::Removed)) {
        connection.read(deadline, |sql| {
            let existing: bool = sql
                .prepare("SELECT EXISTS(SELECT 1 FROM files WHERE key=?1)")?
                .query_row([source.scope.file_id(path).0.as_slice()], |r| r.get(0))
                .map_err(sql_error)?;
            if !existing {
                let count: u32 = sql
                    .prepare("SELECT count(*) FROM files")?
                    .query_row([], |r| r.get(0))
                    .map_err(sql_error)?;
                if count >= policy.max_files {
                    return Err(limit(
                        "eligible files",
                        u64::from(count) + 1,
                        u64::from(policy.max_files),
                    ));
                }
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn skip_unchanged(
    connection: &mut CacheConnection<'_>,
    deadline: Instant,
    source: &Source,
    path: &RelativePath,
    mode: Mode,
    snapshot: &SourceSnapshot,
) -> AtlasResult<bool> {
    let unchanged = connection.read(deadline, |sql| {
        let mut statement =
            sql.prepare("SELECT indexed_hash,coverage_json FROM files WHERE key=?1")?;
        let mut rows = statement
            .query([source.scope.file_id(path).0.as_slice()])
            .map_err(sql_error)?;
        if let Some(row) = rows.next().map_err(sql_error)? {
            let hash: Option<Vec<u8>> = row.get(0).map_err(sql_error)?;
            let coverage: String = row.get(1).map_err(sql_error)?;
            Ok(hash.as_deref() == Some(snapshot.content_hash.0.as_slice())
                && coverage == "\"Indexed\"")
        } else {
            Ok(false)
        }
    })?;
    Ok(unchanged && !matches!(mode, Mode::Repair(_)))
}

fn parse_file(
    source: &Source,
    parser: &mut crate::atlas_parse::Parser,
    path: &RelativePath,
    language: Language,
    budget: ParseBudget,
    snapshot: &SourceSnapshot,
    deadline: Instant,
) -> AtlasResult<ParsedFile> {
    let parsed = match parser.parse(source, snapshot, language, budget, deadline) {
        Ok(parsed) => parsed,
        // These are finite failures of this file's parser attempt, not
        // failures of the controller, cache or source-scope boundary.
        Err(error)
            if matches!(
                error.body.detail(),
                Detail::AtlasResourceBudget(_) | Detail::AtlasParseFailed(_)
            ) =>
        {
            ParsedFile {
                file: source.scope.file_id(path),
                language,
                content_hash: snapshot.content_hash,
                coverage: FileCoverage::Failed { error: error.body },
                symbols: Vec::new(),
                imports: Vec::new(),
                references: Vec::new(),
                scopes: Vec::new(),
            }
        }
        Err(error) => return Err(error),
    };
    Ok(parsed)
}

fn apply_parsed(
    source: &Source,
    connection: &mut CacheConnection<'_>,
    path: &RelativePath,
    snapshot: &SourceSnapshot,
    mut parsed: ParsedFile,
    mode: Mode,
    deadline: Instant,
) -> AtlasResult<()> {
    let serial = mode.serial();
    connection.read(deadline, |sql| {
        resolve::resolve(
            &mut parsed,
            path,
            &mut SqlCatalog { sql, deadline },
            deadline,
        )
        .map(|_| ())
    })?;
    if source.verify(snapshot)? != SourceVerification::Unchanged {
        return Err(source_error(
            path.as_str(),
            "changed during parse verification; reconcile required",
        ));
    }
    timely(deadline)?;
    connection.write(WAL, deadline, |sql| {
        file::apply(sql, &source.scope, snapshot, &parsed, false, serial).map(|_| ())
    })
}

fn write_unparsed(
    connection: &mut CacheConnection<'_>,
    deadline: Instant,
    source: &Source,
    path: &RelativePath,
    language: Option<Language>,
    record: observation::UnparsedObservation<'_>,
    serial: u64,
) -> AtlasResult<()> {
    connection.write(WAL, deadline, |sql| {
        observation::unparsed(sql, &source.scope, path, language, record, serial).map(|_| ())
    })
}

pub(super) fn eligible_file(
    source: &Source,
    connection: &mut CacheConnection<'_>,
    policy: &AtlasPolicy,
    parser: &mut crate::atlas_parse::Parser,
    path: &RelativePath,
    mode: Mode,
    deadline: Instant,
) -> AtlasResult<bool> {
    let parent = path.as_str().rsplit_once('/').map_or("", |p| p.0);
    let rules = ignore::Rules::load(source, &policy.ignore, parent, deadline)?;
    if rules.eligible(path.as_str(), false, &policy.ignore, deadline)? {
        file(source, connection, policy, parser, path, mode, deadline)?;
        return Ok(true);
    }
    connection.write(WAL, deadline, |sql| {
        observation::excluded(sql, &source.scope, path, mode.serial()).map(|_| ())
    })?;
    Ok(false)
}
