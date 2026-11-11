use super::*;
use se_atlas::{
    resolve::{self, catalog::SqlCatalog},
    update::{file, observation},
};
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn file(
    source: &RegisteredSource<NativeAtlasSource>,
    db: &mut CacheConnection<'_>,
    parser: &mut SemanticParser,
    path: &RelativePath,
    request: &protocol::Request,
    phase: &mut impl FnMut(protocol::Phase) -> AtlasResult<()>,
) -> AtlasResult<()> {
    let language = se_atlas::policy::language(path);
    phase(protocol::Phase::SourceRead)?;
    let read = source.read(path, parse_budget());
    match read {
        Ok(SourceRead::Bytes(snapshot)) if language.is_some() => {
            let language = language.ok_or_else(|| failure("language disappeared"))?;
            let attempt = (|| {
                db.release_cold_memory(sql_deadline())?;
                se_proc::atlas_worker::release_allocator_pages();
                phase(protocol::Phase::Parse)?;
                let mut parsed = parser.parse(&snapshot, language, parse_budget())?;
                if request.generated_prefixes.iter().any(|p| {
                    path.as_str() == p.as_str()
                        || path
                            .as_str()
                            .strip_prefix(p.as_str())
                            .is_some_and(|tail| tail.starts_with('/'))
                }) {
                    parsed.coverage = FileCoverage::Deferred {
                        reason: CoverageReason::Generated,
                    };
                    parsed.symbols.clear();
                    parsed.references.clear();
                    parsed.imports.clear();
                    parsed.scopes.clear();
                }
                phase(protocol::Phase::Resolve)?;
                db.read(sql_deadline(), |sql| {
                    resolve::resolve(
                        &mut parsed,
                        path,
                        &mut SqlCatalog {
                            sql,
                            deadline: sql_deadline(),
                        },
                        sql_deadline(),
                    )
                    .map(|_| ())
                })?;
                phase(protocol::Phase::Verify)?;
                if source.verify(&snapshot)? != SourceVerification::Unchanged {
                    return Err(failure(format!(
                        "source changed before cold commit: {}",
                        path.as_str()
                    )));
                }
                phase(protocol::Phase::Commit)?;
                db.write(2_000_000, sql_deadline(), |sql| {
                    file::apply(sql, &source.scope, &snapshot, &parsed, true, 0).map(|_| ())
                })?;
                Ok(())
            })();
            if let Err(error) = attempt {
                phase(protocol::Phase::Commit)?;
                failed_file(source, db, path, language, &snapshot, error)?;
            }
        }
        Ok(SourceRead::Bytes(snapshot)) => {
            phase(protocol::Phase::Commit)?;
            db.write(65536, sql_deadline(), |sql| {
                observation::unparsed(
                    sql,
                    &source.scope,
                    path,
                    None,
                    observation::UnparsedObservation::Deferred {
                        identity: &snapshot.identity,
                        reason: CoverageReason::UnsupportedLanguage,
                    },
                    0,
                )
                .map(|_| ())
            })?;
        }
        Ok(SourceRead::Hashed {
            identity,
            content_hash,
            reason,
        }) => {
            phase(protocol::Phase::Commit)?;
            db.write(65536, sql_deadline(), |sql| {
                observation::unparsed(
                    sql,
                    &source.scope,
                    path,
                    language,
                    observation::UnparsedObservation::Hashed {
                        cold: true,
                        identity: &identity,
                        content_hash,
                        reason,
                    },
                    0,
                )
                .map(|_| ())
            })?;
        }
        Ok(SourceRead::Deferred { identity, reason }) => {
            phase(protocol::Phase::Commit)?;
            db.write(65536, sql_deadline(), |sql| {
                observation::unparsed(
                    sql,
                    &source.scope,
                    path,
                    language,
                    observation::UnparsedObservation::Deferred {
                        identity: &identity,
                        reason,
                    },
                    0,
                )
                .map(|_| ())
            })?;
        }
        Ok(SourceRead::Removed) => {
            phase(protocol::Phase::Commit)?;
            db.write(65536, sql_deadline(), |sql| {
                observation::removed(sql, &source.scope, path, true, 0).map(|_| ())
            })?;
        }
        Err(error) => {
            phase(protocol::Phase::Commit)?;
            db.write(65536, sql_deadline(), |sql| {
                observation::unparsed(
                    sql,
                    &source.scope,
                    path,
                    language,
                    observation::UnparsedObservation::Failed(&error.body),
                    0,
                )
                .map(|_| ())
            })?;
        }
    }
    Ok(())
}
/// Preserve a named per-file failure after rollback; an index-wide native/SQL
/// refusal still stops the job if this bounded metadata transaction cannot run.
fn failed_file(
    source: &RegisteredSource<NativeAtlasSource>,
    db: &mut CacheConnection<'_>,
    path: &RelativePath,
    language: Language,
    snapshot: &SourceSnapshot,
    error: SeError,
) -> AtlasResult<()> {
    let diagnostic = SeError::new(se_types::Detail::AtlasUnreadable(
        se_types::details::AtlasUnreadable {
            path: path.as_str().into(),
            reason: error.to_string(),
        },
    ));
    let verified = source.verify(snapshot);
    db.write(65536, sql_deadline(), |sql| {
        if matches!(verified, Ok(SourceVerification::Unchanged)) {
            let failed = ParsedFile {
                file: source.scope.file_id(path),
                language,
                content_hash: snapshot.content_hash,
                coverage: FileCoverage::Failed {
                    error: diagnostic.body.clone(),
                },
                symbols: Vec::new(),
                imports: Vec::new(),
                references: Vec::new(),
                scopes: Vec::new(),
            };
            file::apply(sql, &source.scope, snapshot, &failed, true, 0).map(|_| ())
        } else {
            observation::unparsed(
                sql,
                &source.scope,
                path,
                Some(language),
                observation::UnparsedObservation::Failed(&diagnostic.body),
                0,
            )
            .map(|_| ())
        }
    })
    .map_err(|recording| recording.with_cause(diagnostic.with_cause(error)))
}
