//! Legacy-import event facts.
use super::*;
pub fn metadata<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    use EventBody::*;
    Ok(match body {
        ImportStarted {
            import,
            source,
            source_sha256,
            format,
            policy_version,
        } => (
            "import.started",
            json!({"import":import,"source":source,"source_sha256":source_sha256,"format":format,"policy_version":policy_version}),
        ),
        ImportProgress { checkpoint, counts } => (
            "import.progress",
            json!({"checkpoint":checkpoint,"counts":counts}),
        ),
        ImportFinished {
            import,
            expected,
            counts,
            complete,
            omissions,
        } => (
            "import.finished",
            json!({"import":import,"expected":expected,"counts":counts,"complete":complete,"omissions":omissions}),
        ),
        ImportUnreadable {
            import,
            family,
            evidence,
            code,
        } => (
            "import.unreadable",
            json!({"import":import,"family":family,"evidence":evidence,"code":code}),
        ),
        LegacyRetained {
            import,
            family,
            format_version,
            legacy_id,
            mapped_id,
            source,
            bytes,
            retained_from,
        } => (
            "legacy.retained",
            json!({"import":import,"family":family,"format_version":format_version,"legacy_id":legacy_id,"mapped_id":mapped_id,"source":source,"bytes_sha256":bytes.as_ref().map(|b| b.sha256),"retained_from":retained_from}),
        ),
        AliasImported {
            alias,
            principal,
            source,
            expected,
        } => (
            "alias.imported",
            json!({"alias":alias,"principal":principal,"source":source,"expected":expected}),
        ),
        _ => return Err(invalid("import metadata dispatch")),
    })
}
