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
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SeError::invalid("object ID", "a complete hexadecimal ID"));
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| SeError::invalid("ID", "hexadecimal"))?;
            let lo = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| SeError::invalid("ID", "hexadecimal"))?;
            Ok(((hi << 4) | lo) as u8)
        })
        .collect()
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
        return Ok(AtlasTarget::Symbol(SymbolSelector::At {
            path: RelativePath::new(required(m, "path")?)?,
            position: Position {
                line: line
                    .parse()
                    .map_err(|_| SeError::invalid("line", "a positive line number"))?,
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
    }))
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
