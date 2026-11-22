//! Human CLI selectors become the same bounded inputs used by MCP.
use super::*;
use se_types::code::*;
fn common(c: Command) -> Command {
    c.arg(value("root").help("Registered worktree ID when the project has several"))
        .arg(value("cursor"))
        .arg(value("limit").help("Page size; find 20, refs/impact/changes 50, outline 300"))
        .arg(value("budget").default_value("16384"))
        .arg(toggle("explain"))
        .arg(
            toggle("require_complete")
                .long("require-complete")
                .help("Exit 2 when the answer is incomplete or stale, even with hits"),
        )
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
                .conflicts_with_all(["file", "record", "commit", "symbol_id"]),
        )
        .arg(value("line").requires("path"))
        .arg(value("column").requires("line").default_value("0"))
        .arg(toggle("file").conflicts_with_all(["record", "commit", "symbol_id", "line"]))
        .arg(
            toggle("symbol")
                .help("Treat the target as a symbol name, not a path")
                .conflicts_with_all(["file", "record", "commit", "symbol_id"]),
        )
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
            .about("Read changes since a duration (10m), ISO UTC time, commit SHA, cursor or Unix ms")
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
        limit: text(m, "limit")
            .map(|s| {
                s.parse()
                    .map_err(|_| SeError::invalid("limit", "a positive page size"))
            })
            .transpose()?,
        byte_budget: required(m, "budget")?
            .parse()
            .map_err(|_| SeError::invalid("budget", "1024..262144"))?,
        format: if json {
            AtlasFormat::Json
        } else {
            AtlasFormat::Compact
        },
        explain: flag(m, "explain"),
        require_complete: flag(m, "require_complete"),
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
    if text(m, "kind").is_some() && text(m, "target").is_none() {
        return Err(SeError::invalid(
            "Atlas --kind without a symbol name",
            "a symbol name to narrow; a position lookup takes no --kind",
        ));
    }
    if let Some(line) = text(m, "line") {
        let line: u32 = line
            .parse()
            .map_err(|_| SeError::invalid("line", "a positive line number"))?;
        if let Some(name) = text(m, "target") {
            if m.value_source("column") == Some(clap::parser::ValueSource::CommandLine) {
                return Err(SeError::invalid(
                    "an Atlas name with a column",
                    "a name with only a line, or a position lookup: --path FILE --line N --column C",
                ));
            }
            // A name plus a line keeps the symbol name and narrows by the
            // definition's start line, so an indented declaration resolves.
            return Ok(AtlasTarget::Symbol(SymbolSelector::Name {
                name: QueryText::new(name)?,
                path: Some(RelativePath::new(required(m, "path")?)?),
                container: text(m, "container").map(QueryText::new).transpose()?,
                kind: text(m, "kind").map(|s| parse("kind", &s)).transpose()?,
                line: Some(line),
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
    // A bare positional resolves as a path, then path:line, then a symbol name;
    // --symbol or any symbol narrowing keeps it a name.
    if !flag(m, "symbol")
        && ["path", "container", "kind"]
            .iter()
            .all(|id| text(m, id).is_none())
    {
        return Ok(AtlasTarget::Auto(QueryText::new(value)?));
    }
    Ok(AtlasTarget::Symbol(SymbolSelector::Name {
        name: QueryText::new(value)?,
        path: text(m, "path").map(RelativePath::new).transpose()?,
        container: text(m, "container").map(QueryText::new).transpose()?,
        kind: text(m, "kind").map(|s| parse("kind", &s)).transpose()?,
        line: None,
    }))
}
/// `--since`: Unix milliseconds, a duration back from now (`30s`, `10m`, `2h`,
/// `7d`), an ISO-8601 UTC time, a commit SHA or 7+ hex prefix, or a cursor.
fn since(text: &str, now: i64) -> Result<ChangeBaseline> {
    let invalid = || {
        SeError::invalid(
            "since",
            "a duration such as 10m, an ISO UTC time such as 2026-11-20T09:30Z, a commit SHA, an Atlas cursor or Unix milliseconds",
        )
    };
    if text.bytes().all(|b| b.is_ascii_digit()) {
        return text
            .parse()
            .map(ChangeBaseline::ObservedUnixMillis)
            .map_err(|_| invalid());
    }
    if text.len() >= 7 && text.len() <= 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(match text.len() {
            40 | 64 => ChangeBaseline::ObservedCommit(oid(text)?),
            _ => ChangeBaseline::ObservedCommitPrefix(text.to_ascii_lowercase()),
        });
    }
    if let Some(count) = text.strip_suffix(['s', 'm', 'h', 'd'])
        && !count.is_empty()
        && count.bytes().all(|b| b.is_ascii_digit())
    {
        let scale = match text.as_bytes()[text.len() - 1] {
            b's' => 1_000,
            b'm' => 60_000,
            b'h' => 3_600_000,
            _ => 86_400_000,
        };
        let ago = count.parse::<i64>().ok().and_then(|n| n.checked_mul(scale));
        return Ok(ChangeBaseline::ObservedUnixMillis(
            now.saturating_sub(ago.ok_or_else(invalid)?),
        ));
    }
    if let Some(time) = iso_millis(text) {
        return Ok(ChangeBaseline::ObservedUnixMillis(time));
    }
    // Cursors carry a 32-byte digest, so a short word is a typo, not a cursor.
    let cursor = (text.len() >= 43)
        .then(|| AtlasCursor::new(text).ok())
        .flatten();
    cursor.map(ChangeBaseline::Cursor).ok_or_else(invalid)
}
/// `YYYY-MM-DD[THH:MM[:SS]][Z]`, read as UTC.
fn iso_millis(text: &str) -> Option<i64> {
    let text = text.strip_suffix('Z').unwrap_or(text);
    let (date, time) = text.split_once(['T', ' ']).unwrap_or((text, "00:00"));
    let num = |s: &str, len: usize| {
        (s.len() == len && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<i64>().ok())?
    };
    let (mut d, mut t) = (date.split('-'), time.split(':'));
    let (y, m, day) = (num(d.next()?, 4)?, num(d.next()?, 2)?, num(d.next()?, 2)?);
    let (h, min) = (num(t.next()?, 2)?, num(t.next()?, 2)?);
    let s = t.next().map_or(Some(0), |s| num(s, 2))?;
    if d.next().is_some()
        || t.next().is_some()
        || !(1..=12).contains(&m)
        || !(1..=31).contains(&day)
        || h > 23
        || min > 59
        || s > 60
    {
        return None;
    }
    // Days from the civil calendar, March-based so leap days fall last.
    let y = if m <= 2 { y - 1 } else { y };
    let (era, yoe) = (y.div_euclid(400), y.rem_euclid(400));
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(((days * 24 + h) * 60 + min) * 60_000 + s * 1_000)
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
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
            AnyOp::AtlasChanges(AtlasChanges {
                since: since(&required(m, "since")?, now)?,
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
    fn an_explicit_column_beside_a_name_refuses() {
        assert!(
            matches!(
                target_from(&[
                    "refs", "Foo", "--path", "foo.rs", "--line", "1", "--column", "5"
                ]),
                Err(refused)
                    if refused
                        .to_string()
                        .contains("position lookup: --path FILE --line N --column C")
            ),
            "the refusal must point to the position selector"
        );
    }
    #[test]
    fn kind_and_line_narrow_the_named_target_together()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let target = target_from(&[
            "refs", "Foo", "--path", "foo.rs", "--kind", "Struct", "--line", "1",
        ])?;
        assert!(
            matches!(
                target,
                AtlasTarget::Symbol(SymbolSelector::Name {
                    kind: Some(SymbolKind::Struct),
                    line: Some(1),
                    ..
                })
            ),
            "kind and line must compose on the named target: {target:?}"
        );
        Ok(())
    }
    #[test]
    fn a_kind_without_a_name_refuses() {
        assert!(
            matches!(
                target_from(&["refs", "--path", "foo.rs", "--line", "1", "--kind", "Struct"]),
                Err(refused) if refused.to_string().contains("symbol name")
            ),
            "--kind beside a bare position must refuse"
        );
    }
    #[test]
    fn a_nonnumeric_column_refuses_on_the_position_lookup() {
        assert!(
            target_from(&[
                "refs", "--path", "foo.rs", "--line", "1", "--column", "wide"
            ])
            .is_err(),
            "a nonnumeric column must refuse on the position lookup"
        );
    }
    #[test]
    fn the_default_column_stays_off_the_query()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let target = target_from(&["refs", "Foo", "--path", "foo.rs", "--line", "1"])?;
        assert!(
            matches!(
                target,
                AtlasTarget::Symbol(SymbolSelector::Name { line: Some(1), .. })
            ),
            "the default column must not change the line filter: {target:?}"
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
