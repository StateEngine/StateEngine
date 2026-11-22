use super::*;
use se_atlas::{
    resolve::{self, catalog::SqlCatalog},
    update::{file, observation},
};
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
    cpu::start()?;
    let read = source.read_with_wall_timeout(path, parse_budget(), Duration::from_secs(5));
    let observation = match &read {
        Ok(SourceRead::Bytes(snapshot)) if language.is_some() => {
            let language = language.ok_or_else(|| failure("language disappeared"))?;
            let attempt = db.release_cold_memory(sql_deadline()).and_then(|()| {
                se_proc::atlas_worker::release_allocator_pages();
                phase(protocol::Phase::Parse)?;
                let parsed = parse(source, parser, request, path, snapshot, language)?;
                commit(source, db, path, phase, snapshot, parsed)
            });
            if let Err(error) = attempt {
                phase(protocol::Phase::Commit)?;
                failed_file(source, db, path, language, snapshot, error)?;
            }
            return Ok(());
        }
        // The guard above failed, so `language` is `None` for this arm.
        Ok(SourceRead::Bytes(snapshot)) => observation::UnparsedObservation::Deferred {
            identity: &snapshot.identity,
            reason: CoverageReason::UnsupportedLanguage,
        },
        Ok(SourceRead::Hashed {
            identity,
            content_hash,
            reason,
        }) => observation::UnparsedObservation::Hashed {
            cold: true,
            identity,
            content_hash: *content_hash,
            reason: *reason,
        },
        Ok(SourceRead::Deferred { identity, reason }) => {
            observation::UnparsedObservation::Deferred {
                identity,
                reason: *reason,
            }
        }
        Ok(SourceRead::Removed) => {
            phase(protocol::Phase::Commit)?;
            return db.write(65536, sql_deadline(), |sql| {
                observation::removed(sql, &source.scope, path, true, 0).map(|_| ())
            });
        }
        Err(error) if matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(detail) if detail.op == "Atlas source read") =>
        {
            return Err(crate::deadline::stall(Duration::from_secs(5)));
        }
        Err(error) => observation::UnparsedObservation::Failed(&error.body),
    };
    unparsed(source, db, path, language, phase, observation)
}
/// Record a file whose bytes were not parsed, after announcing the commit.
fn unparsed(
    source: &RegisteredSource<NativeAtlasSource>,
    db: &mut CacheConnection<'_>,
    path: &RelativePath,
    language: Option<Language>,
    phase: &mut impl FnMut(protocol::Phase) -> AtlasResult<()>,
    observation: observation::UnparsedObservation<'_>,
) -> AtlasResult<()> {
    phase(protocol::Phase::Commit)?;
    db.write(65536, sql_deadline(), |sql| {
        observation::unparsed(sql, &source.scope, path, language, observation, 0).map(|_| ())
    })
}
/// Parse one supported file within the CPU budget, deferring it past that
/// budget and keeping only coverage for generated paths.
fn parse(
    source: &RegisteredSource<NativeAtlasSource>,
    parser: &mut SemanticParser,
    request: &protocol::Request,
    path: &RelativePath,
    snapshot: &SourceSnapshot,
    language: Language,
) -> AtlasResult<ParsedFile> {
    let mut parsed =
        match cpu::check().and_then(|()| parser.parse(snapshot, language, parse_budget())) {
            Ok(parsed) => parsed,
            Err(error) if cpu::is_limit(&error) => deferred(source, snapshot, language),
            Err(error) => return Err(error),
        };
    match cpu::check() {
        Ok(()) => (),
        Err(error) if cpu::is_limit(&error) => parsed = deferred(source, snapshot, language),
        Err(error) => return Err(error),
    }
    if generated(request, path) {
        parsed.coverage = FileCoverage::Deferred {
            reason: CoverageReason::Generated,
        };
        parsed.symbols.clear();
        parsed.references.clear();
        parsed.imports.clear();
        parsed.scopes.clear();
    }
    Ok(parsed)
}
/// Resolve, verify and commit a parsed file. Any error leaves the caller to
/// record a named per-file failure after rollback.
fn commit(
    source: &RegisteredSource<NativeAtlasSource>,
    db: &mut CacheConnection<'_>,
    path: &RelativePath,
    phase: &mut impl FnMut(protocol::Phase) -> AtlasResult<()>,
    snapshot: &SourceSnapshot,
    mut parsed: ParsedFile,
) -> AtlasResult<()> {
    phase(protocol::Phase::Resolve)?;
    db.read(sql_deadline(), |sql| {
        let mut catalog = SqlCatalog {
            sql,
            deadline: sql_deadline(),
        };
        resolve::resolve(&mut parsed, path, &mut catalog, sql_deadline()).map(|_| ())
    })?;
    phase(protocol::Phase::Verify)?;
    if source.verify(snapshot)? != SourceVerification::Unchanged {
        return Err(failure(format!(
            "source changed before cold commit: {}",
            path.as_str()
        )));
    }
    phase(protocol::Phase::Commit)?;
    db.write(2_000_000, sql_deadline(), |sql| {
        file::apply(sql, &source.scope, snapshot, &parsed, true, 0).map(|_| ())
    })
}
/// A path at or under one of the request's generated prefixes.
fn generated(request: &protocol::Request, path: &RelativePath) -> bool {
    request.generated_prefixes.iter().any(|prefix| {
        path.as_str() == prefix.as_str()
            || path
                .as_str()
                .strip_prefix(prefix.as_str())
                .is_some_and(|tail| tail.starts_with('/'))
    })
}
fn deferred(
    source: &RegisteredSource<NativeAtlasSource>,
    snapshot: &SourceSnapshot,
    language: Language,
) -> ParsedFile {
    ParsedFile {
        file: source.scope.file_id(&snapshot.path),
        language,
        content_hash: snapshot.content_hash,
        coverage: FileCoverage::Deferred {
            reason: CoverageReason::ParseWorkLimit,
        },
        symbols: Vec::new(),
        imports: Vec::new(),
        references: Vec::new(),
        scopes: Vec::new(),
    }
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
