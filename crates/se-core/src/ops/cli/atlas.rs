//! Human CLI selectors become the same bounded inputs used by MCP.
use super::*;
use se_types::code::*;
fn common(c: Command) -> Command {
    c.arg(value("root").help("Registered worktree ID when the project has several"))
        .arg(value("cursor"))
        .arg(value("limit").default_value("10"))
        .arg(value("budget").default_value("4096"))
        .arg(toggle("explain"))
}
fn scoped(c: Command) -> Command {
    c.arg(
        value("in")
            .action(ArgAction::Append)
            .help("Registered relative path; repeat up to 32 times"),
    )
    .arg(value("language").action(ArgAction::Append).value_parser([
        "javascript",
        "jsx",
        "typescript",
        "tsx",
        "rust",
        "python",
    ]))
}
fn targeted(c: Command) -> Command {
    c.arg(positional("target", 1, false))
        .arg(value("path"))
        .arg(value("container"))
        .arg(
            value("kind")
                .help("Symbol kind, e.g. Struct or Namespace")
                .value_parser([
                    "Module",
                    "Namespace",
                    "Class",
                    "Interface",
                    "Trait",
                    "Struct",
                    "Enum",
                    "TypeAlias",
                    "Function",
                    "Method",
                    "Constant",
                    "Static",
                    "Variable",
                    "Parameter",
                    "Field",
                    "EnumVariant",
                    "Macro",
                ])
                .conflicts_with_all(["file", "record", "commit", "symbol_id", "line"]),
        )
        .arg(value("line").requires("path"))
        .arg(value("column").requires("line").default_value("0"))
        .arg(toggle("file").conflicts_with_all(["record", "commit", "symbol_id", "line"]))
        .arg(toggle("record").conflicts_with_all(["file", "commit", "symbol_id", "line"]))
        .arg(toggle("commit").conflicts_with_all(["file", "record", "symbol_id", "line"]))
        .arg(
            toggle("symbol_id")
                .long("symbol-id")
                .conflicts_with_all(["file", "record", "commit", "line"]),
        )
}
pub(super) fn command(name: &str, c: Command) -> Command {
    let c = common(c);
    match name {
        "atlas.find" => scoped(c)
            .about("Find code, text and project records; try authenticate or 'packet budget'")
            .arg(positional("query", 1, true))
            .arg(value("kind").default_value("all").value_parser([
                "all", "code", "symbol", "text", "path", "message", "working", "edit",
                "commit",
            ]))
            .arg(value("mode").value_parser(["exact", "literal", "phrase", "broad", "related"]))
            .arg(
                value("order")
                    .default_value("relevance")
                    .value_parser(["relevance", "recency"]),
            )
            .arg(toggle("full"))
            .arg(toggle("regex").help("Match a regular expression in live source (all/code/text; automatic or literal mode)")),
        "atlas.refs" => targeted(c)
            .about("Find references to a symbol or --file path; spelling candidates are labelled")
            .arg(
                value("ref_kind")
                    .long("ref-kind")
                    .action(ArgAction::Append)
                    .value_parser(["call", "type-use", "import", "export", "value-use"]),
            )
            .arg(toggle("resolved_only").long("resolved-only")),
        "atlas.impact" => targeted(c)
            .about("Show bounded dependents, possible tests and linked records")
            .arg(value("depth").default_value("2"))
            .arg(toggle("include_name_only").long("include-name-only")),
        "atlas.changes" => scoped(c)
            .about(
                "Read changes from an Atlas cursor, observed Git commit or Unix millisecond time",
            )
            .arg(value("since").required(true)),
        "atlas.outline" => c
            .about("Show declarations and project records linked to this file")
            .arg(positional("path", 1, true)),
        _ => c,
    }
}
fn parse<T: serde::de::DeserializeOwned>(name: &str, value: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(value.into()))
        .map_err(|_| SeError::invalid(name, "a value listed in this command's help"))
}
fn options(m: &ArgMatches, json: bool) -> Result<AtlasOptions> {
    Ok(AtlasOptions {
        root: text(m, "root").map(|s| s.parse()).transpose()?,
        cursor: text(m, "cursor").map(AtlasCursor::new).transpose()?,
        limit: required(m, "limit")?
            .parse()
            .map_err(|_| SeError::invalid("limit", "1..50"))?,
        byte_budget: required(m, "budget")?
            .parse()
            .map_err(|_| SeError::invalid("budget", "1024..32768"))?,
        format: if json {
            AtlasFormat::Json
        } else {
            AtlasFormat::Compact
        },
        explain: flag(m, "explain"),
    })
}
fn scope(m: &ArgMatches) -> Result<(Vec<RelativePath>, Vec<Language>)> {
    let paths = m
        .get_many::<String>("in")
        .into_iter()
        .flatten()
        .map(RelativePath::new)
        .collect::<Result<Vec<_>>>()?;
    let languages = m
        .get_many::<String>("language")
        .into_iter()
        .flatten()
        .map(|s| match s.as_str() {
            "javascript" => Ok(Language::JavaScript),
            "jsx" => Ok(Language::Jsx),
            "typescript" => Ok(Language::TypeScript),
            "tsx" => Ok(Language::Tsx),
            "rust" => Ok(Language::Rust),
            "python" => Ok(Language::Python),
            _ => Err(SeError::invalid("language", "a supported source language")),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((paths, languages))
}
fn hex(text: &str) -> Result<Vec<u8>> {
    se_types::decode_hex(text)
        .ok_or_else(|| SeError::invalid("object ID", "a complete hexadecimal ID"))
}
fn oid(text: &str) -> Result<GitObjectId> {
    let bytes = hex(text)?;
    match bytes.len() {
        20 => {
            Ok(GitObjectId::Sha1(bytes.try_into().map_err(|_| {
                SeError::invalid("commit", "40 hex characters")
            })?))
        }
        32 => {
            Ok(GitObjectId::Sha256(bytes.try_into().map_err(|_| {
                SeError::invalid("commit", "64 hex characters")
            })?))
        }
        _ => Err(SeError::invalid("commit", "40 or 64 hex characters")),
    }
}
fn target(m: &ArgMatches) -> Result<AtlasTarget> {
    if let Some(line) = text(m, "line") {
        let line: u32 = line
            .parse()
            .map_err(|_| SeError::invalid("line", "a positive line number"))?;
        if let Some(name) = text(m, "target") {
            // A name plus a line keeps the symbol name and narrows by the
            // definition's start line, so an indented declaration resolves.
            return Ok(AtlasTarget::Symbol(SymbolSelector::Name {
                name: QueryText::new(name)?,
                path: Some(RelativePath::new(required(m, "path")?)?),
                container: text(m, "container").map(QueryText::new).transpose()?,
                kind: text(m, "kind").map(|s| parse("kind", &s)).transpose()?,
                line: Some(line),
                column: explicit_column(m)?,
            }));
        }
        return Ok(AtlasTarget::Symbol(SymbolSelector::At {
            path: RelativePath::new(required(m, "path")?)?,
            position: Position {
                line,
                byte_column: required(m, "column")?
                    .parse()
                    .map_err(|_| SeError::invalid("column", "a zero-based byte column"))?,
            },
        }));
    }
    let value = text(m, "target").ok_or_else(|| {
        SeError::invalid(
            "Atlas target",
            "a symbol name, --file path, --record key, --commit ID, or --path FILE --line N",
        )
    })?;
    if flag(m, "file") {
        return Ok(AtlasTarget::File(RelativePath::new(value)?));
    }
    if flag(m, "record") {
        return Ok(AtlasTarget::Record(RecordKey::new(value)?));
    }
    if flag(m, "commit") {
        return Ok(AtlasTarget::Commit(oid(&value)?));
    }
    if flag(m, "symbol_id") {
        return Ok(AtlasTarget::Symbol(SymbolSelector::Id(SymbolId(
            hex(&value)?
                .try_into()
                .map_err(|_| SeError::invalid("symbol ID", "64 hex characters"))?,
        ))));
    }
    Ok(AtlasTarget::Symbol(SymbolSelector::Name {
        name: QueryText::new(value)?,
        path: text(m, "path").map(RelativePath::new).transpose()?,
        container: text(m, "container").map(QueryText::new).transpose()?,
        kind: text(m, "kind").map(|s| parse("kind", &s)).transpose()?,
        line: None,
        column: None,
    }))
}
/// Only a column the user actually typed constrains the named query; the
/// default zero stays off the wire and off the resolution.
fn explicit_column(m: &ArgMatches) -> Result<Option<u32>> {
    if m.value_source("column") != Some(clap::parser::ValueSource::CommandLine) {
        return Ok(None);
    }
    let column: u32 = required(m, "column")?
        .parse()
        .map_err(|_| SeError::invalid("column", "a zero-based byte column"))?;
    Ok(Some(column))
}
pub(super) fn decode(name: &str, m: &ArgMatches, json: bool) -> Result<AnyOp> {
    let options = options(m, json)?;
    let op = match name {
        "atlas.find" => {
            let (paths, languages) = scope(m)?;
            AnyOp::AtlasFind(AtlasFind {
                query: QueryText::new(required(m, "query")?)?,
                kind: parse("kind", &required(m, "kind")?)?,
                paths,
                languages,
                mode: text(m, "mode").map(|s| parse("mode", &s)).transpose()?,
                order: parse("order", &required(m, "order")?)?,
                full: flag(m, "full"),
                regex: flag(m, "regex"),
                options,
            })
        }
        "atlas.refs" => AnyOp::AtlasRefs(AtlasRefs {
            target: target(m)?,
            kinds: m
                .get_many::<String>("ref_kind")
                .into_iter()
                .flatten()
                .map(|s| match s.as_str() {
                    "call" => Ok(ReferenceKind::Call),
                    "type-use" => Ok(ReferenceKind::TypeUse),
                    "import" => Ok(ReferenceKind::Import),
                    "export" => Ok(ReferenceKind::Export),
                    "value-use" => Ok(ReferenceKind::ValueUse),
                    _ => Err(SeError::invalid("reference kind", "a listed kind")),
                })
                .collect::<Result<Vec<_>>>()?,
            include_name_only: !flag(m, "resolved_only"),
            options,
        }),
        "atlas.impact" => AnyOp::AtlasImpact(AtlasImpact {
            target: target(m)?,
            depth: required(m, "depth")?
                .parse()
                .map_err(|_| SeError::invalid("depth", "1..3"))?,
            include_name_only: flag(m, "include_name_only"),
            options,
        }),
        "atlas.changes" => {
            let (paths, languages) = scope(m)?;
            let since = required(m, "since")?;
            let since = if since.bytes().all(|b| b.is_ascii_digit()) {
                ChangeBaseline::ObservedUnixMillis(
                    since.parse().map_err(|_| {
                        SeError::invalid("since", "representable Unix milliseconds")
                    })?,
                )
            } else if matches!(since.len(), 40 | 64) && since.bytes().all(|b| b.is_ascii_hexdigit())
            {
                ChangeBaseline::ObservedCommit(oid(&since)?)
            } else {
                ChangeBaseline::Cursor(AtlasCursor::new(since)?)
            };
            AnyOp::AtlasChanges(AtlasChanges {
                since,
                paths,
                languages,
                options,
            })
        }
        "atlas.outline" => AnyOp::AtlasOutline(AtlasOutline {
            path: RelativePath::new(required(m, "path")?)?,
            options,
        }),
        _ => return Err(unknown(name)),
    };
    op.validate()?;
    Ok(op)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target_from(args: &[&str]) -> std::result::Result<AtlasTarget, Box<dyn std::error::Error>> {
        let command = command("atlas.refs", Command::new("refs"));
        let matches = command
            .try_get_matches_from(args)
            .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)?;
        Ok(target(&matches)?)
    }
    #[test]
    fn a_named_target_with_a_line_keeps_the_name()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let target = target_from(&["refs", "Foo", "--path", "foo.rs", "--line", "1"])?;
        assert!(
            matches!(
                target,
                AtlasTarget::Symbol(SymbolSelector::Name {
                    line: Some(1),
                    path: Some(_),
                    ..
                })
            ),
            "the line remedy must keep the symbol name: {target:?}"
        );
        Ok(())
    }
    #[test]
    fn a_line_without_a_name_keeps_the_positional_lookup()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let target = target_from(&["refs", "--path", "foo.rs", "--line", "1"])?;
        assert!(
            matches!(target, AtlasTarget::Symbol(SymbolSelector::At { .. })),
            "a bare position must stay a position lookup: {target:?}"
        );
        Ok(())
    }
    #[test]
    fn an_explicit_column_travels_with_the_name()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let target = target_from(&[
            "refs", "Foo", "--path", "foo.rs", "--line", "1", "--column", "5",
        ])?;
        assert!(
            matches!(
                target,
                AtlasTarget::Symbol(SymbolSelector::Name {
                    line: Some(1),
                    column: Some(5),
                    ..
                })
            ),
            "an explicit column must constrain the named query: {target:?}"
        );
        Ok(())
    }
    #[test]
    fn a_nonnumeric_column_refuses() {
        assert!(
            target_from(&[
                "refs", "Foo", "--path", "foo.rs", "--line", "1", "--column", "wide"
            ])
            .is_err(),
            "main refuses a nonnumeric column"
        );
    }
    #[test]
    fn the_default_column_stays_off_the_query()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let target = target_from(&["refs", "Foo", "--path", "foo.rs", "--line", "1"])?;
        assert!(
            matches!(
                target,
                AtlasTarget::Symbol(SymbolSelector::Name { column: None, .. })
            ),
            "the default column must not constrain the query: {target:?}"
        );
        Ok(())
    }
    #[test]
    fn a_named_target_without_a_line_stays_plain()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let target = target_from(&["refs", "Foo", "--path", "foo.rs"])?;
        assert!(
            matches!(
                target,
                AtlasTarget::Symbol(SymbolSelector::Name {
                    line: None,
                    path: Some(_),
                    ..
                })
            ),
            "no line means no line filter: {target:?}"
        );
        Ok(())
    }
}
