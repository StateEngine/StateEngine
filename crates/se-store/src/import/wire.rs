//! Legacy-import event facts decode against the store's identity rows.
use super::*;
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(crate) fn decode(c: &Connection, seq: i64, kind: &str) -> StoreResult<EventBody<StoredText>> {
    use codec::field;
    let v = codec::facts(c, seq)?;
    use EventBody::*;
    Ok(match kind {
        "import.started" => ImportStarted {
            import: field(&v, "import")?,
            source: field(&v, "source")?,
            source_sha256: field(&v, "source_sha256")?,
            format: field(&v, "format")?,
            policy_version: field(&v, "policy_version")?,
        },
        "import.progress" => ImportProgress {
            checkpoint: field(&v, "checkpoint")?,
            counts: field(&v, "counts")?,
        },
        "import.finished" => ImportFinished {
            import: field(&v, "import")?,
            expected: field(&v, "expected")?,
            counts: field(&v, "counts")?,
            complete: field(&v, "complete")?,
            omissions: field(&v, "omissions")?,
        },
        "import.unreadable" => ImportUnreadable {
            import: field(&v, "import")?,
            family: field(&v, "family")?,
            evidence: field(&v, "evidence")?,
            code: field(&v, "code")?,
        },
        "legacy.retained" => {
            let sha256: Option<[u8; 32]> = field(&v, "bytes_sha256")?;
            let bytes = sha256
                .map(|sha256| {
                    let StoredText::Present(text) = codec::stored_text(c, seq, "legacy")? else {
                        return Err(invalid("legacy provenance payload erased"));
                    };
                    use sha2::{Digest, Sha256};
                    if Sha256::digest(text.as_bytes()).as_slice() != sha256 {
                        return Err(fail(
                            StoreErrorCode::Unreadable,
                            "legacy payload digest differs",
                        ));
                    }
                    Ok(LegacyBytes {
                        bytes: text.into_bytes(),
                        sha256,
                    })
                })
                .transpose()?;
            LegacyRetained {
                import: field(&v, "import")?,
                family: field(&v, "family")?,
                format_version: field(&v, "format_version")?,
                legacy_id: field(&v, "legacy_id")?,
                mapped_id: {
                    let target = v
                        .get("mapped_id")
                        .ok_or_else(|| invalid("legacy target absent"))?;
                    if target.get("kind").and_then(Value::as_str) == Some("principal") {
                        let project: Option<Vec<u8>> = c
                            .query_row("SELECT project_id FROM events WHERE seq=?", [seq], |r| {
                                r.get(0)
                            })
                            .map_err(sql)?;
                        let mut scope = vec![1];
                        scope.extend(
                            project.ok_or_else(|| invalid("legacy principal needs project"))?,
                        );
                        LegacyTarget::Principal(actor_value(
                            c,
                            target
                                .get("id")
                                .ok_or_else(|| invalid("legacy target actor absent"))?,
                            &scope,
                        )?)
                    } else {
                        serde_json::from_value(target.clone()).map_err(invalid)?
                    }
                },
                source: field(&v, "source")?,
                bytes,
                retained_from: field(&v, "retained_from")?,
            }
        }
        "alias.imported" => AliasImported {
            alias: field(&v, "alias")?,
            principal: {
                let project: Vec<u8> = c
                    .query_row("SELECT project_id FROM events WHERE seq=?", [seq], |r| {
                        r.get(0)
                    })
                    .map_err(sql)?;
                let mut scope = vec![1];
                scope.extend(project);
                actor_value(
                    c,
                    v.get("principal")
                        .ok_or_else(|| invalid("alias principal absent"))?,
                    &scope,
                )?
            },
            source: field(&v, "source")?,
            expected: field(&v, "expected")?,
        },
        _ => return Err(invalid("import decode dispatch")),
    })
}
