//! One finite parse, no source persistence and no resident parser pool.
mod budget;
mod extract;
mod imports;
mod javascript;
mod python;
mod rust;
mod syntax;
use crate::{
    errors::{AtlasResult, capacity},
    lifecycle::*,
    model::*,
    scope::Scope,
};
pub use budget::{ParserPlacement, ParserProfile};
use std::{
    ops::ControlFlow,
    time::{Duration, Instant},
};

pub struct SemanticParser {
    scope: Scope,
    profiles: Vec<ParserProfile>,
}
impl SemanticParser {
    pub fn new(scope: Scope, profiles: Vec<ParserProfile>) -> AtlasResult<Self> {
        if profiles.len() > 6
            || profiles
                .iter()
                .enumerate()
                .any(|(i, p)| profiles[..i].iter().any(|v| v.language == p.language))
        {
            return Err(se_types::SeError::invalid(
                "Atlas parser profiles",
                "at most one qualified profile per grammar",
            ));
        }
        Ok(Self { scope, profiles })
    }
}
impl AtlasParser for SemanticParser {
    fn parse(
        &mut self,
        snapshot: &SourceSnapshot,
        language: Language,
        budget: ParseBudget,
    ) -> AtlasResult<ParsedFile> {
        let file = self.scope.file_id(&snapshot.path);
        let defer = |reason| ParsedFile {
            file,
            language,
            content_hash: snapshot.content_hash,
            coverage: FileCoverage::Deferred { reason },
            symbols: Vec::new(),
            imports: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
        };
        if budget.max_work.is_zero()
            || budget.max_work > Duration::from_millis(200)
            || budget.max_source_bytes > 524288
            || budget.max_rows == 0
            || budget.max_rows > 65536
        {
            return Err(se_types::SeError::invalid(
                "Atlas parse budget",
                "finite <=200 ms, <=512 KiB and 1..65536 rows",
            ));
        }
        if generated(&snapshot.bytes) {
            return Ok(defer(CoverageReason::Generated));
        }
        if std::str::from_utf8(&snapshot.bytes).is_err() {
            return Ok(defer(CoverageReason::UnsupportedEncoding));
        }
        let Some(profile) = self.profiles.iter().find(|p| p.language == language) else {
            return Ok(defer(CoverageReason::ParserUnqualified));
        };
        if snapshot.bytes.len() > budget.max_source_bytes.min(profile.max_source_bytes) as usize {
            return Ok(defer(CoverageReason::SourceBytesLimit));
        }
        let reservation = snapshot.bytes.capacity() as u64
            + u64::from(profile.measured_parser_bytes)
            + u64::from(profile.extraction_bytes);
        if reservation > u64::from(budget.reserved_bytes) {
            return Err(capacity(
                "Atlas source/parser/extraction reservation",
                reservation,
                u64::from(budget.reserved_bytes),
            ));
        }
        let _lease = budget::Lease::take()?;
        let deadline = Instant::now() + budget.max_work;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&grammar(language))
            .map_err(|e| failure(&snapshot.path, language, e.to_string()))?;
        let mut progress = |_: &tree_sitter::ParseState| {
            if Instant::now() >= deadline {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let tree = parser.parse_with_options(
            &mut |offset, _| snapshot.bytes.get(offset..).unwrap_or_default(),
            None,
            Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
        );
        let Some(tree) = tree else {
            return Ok(defer(CoverageReason::ParseWorkLimit));
        };
        let arena = budget::Arena::new(
            profile.extraction_bytes,
            budget.max_rows.min(profile.max_rows),
        );
        let result = extract::extract(&self.scope, snapshot, language, &tree, deadline, arena);
        // Tree and parser are owned by this call. Neither a failed parse nor a
        // caller forgetting release_scratch can retain them between work quanta.
        drop(tree);
        drop(parser);
        result
    }
    fn release_scratch(&mut self) {}
}
fn grammar(language: Language) -> tree_sitter::Language {
    match language {
        Language::JavaScript | Language::Jsx => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
    }
}
fn generated(bytes: &[u8]) -> bool {
    let prefix = &bytes[..bytes.len().min(4096)];
    [
        b"@generated".as_slice(),
        b"automatically generated",
        b"do not edit",
    ]
    .iter()
    .any(|needle| {
        prefix
            .windows(needle.len())
            .any(|part| part.eq_ignore_ascii_case(needle))
    })
}
fn failure(path: &RelativePath, language: Language, reason: String) -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::AtlasParseFailed(
        se_types::details::AtlasParseFailed {
            path: se_types::code::AtlasText::as_str(path).into(),
            language: format!("{language:?}"),
            reason,
        },
    ))
}
