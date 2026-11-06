//! Captured means exact trusted path and both before/after observations matched.
use super::*;
use crate::{
    cache::connection::SqlView,
    errors::{AtlasResult, cache_error},
    lifecycle::EditEvidence,
    model::*,
};
use rusqlite::params;
use se_types::{EventId, code::AtlasText};
pub fn captured(
    sql: &SqlView<'_>,
    evidence: &EditEvidence,
    observed_unix_ms: i64,
    serial: u64,
) -> AtlasResult<u32> {
    if evidence.before.is_none() && evidence.after.is_none() {
        return Err(se_types::SeError::invalid(
            "Atlas edit evidence",
            "at least one witnessed revision",
        ));
    }
    let generation: u64 = unsigned(
        sql,
        "SELECT index_generation+1 FROM meta WHERE singleton=1",
        [],
    )?;
    let mut cursor = (0u64, 0u32);
    let mut matched = 0;
    loop {
        // One row at a time: provenance repair cannot accumulate change history.
        let mut statement=sql.prepare("SELECT c.generation,c.ordinal,a.hint_json FROM changes c LEFT JOIN authors a ON a.generation=c.generation AND a.ordinal=c.ordinal WHERE c.path=?1 AND c.previous_hash IS ?2 AND c.current_hash IS ?3 AND (c.generation,c.ordinal)>(?4,?5) AND c.generation>(SELECT retention_floor FROM meta WHERE singleton=1) ORDER BY c.generation,c.ordinal LIMIT 1")?;
        let mut rows = statement
            .query(params![
                evidence.path.as_str(),
                evidence.before.as_ref().map(|s| s.0.as_slice()),
                evidence.after.as_ref().map(|s| s.0.as_slice()),
                n(cursor.0),
                cursor.1
            ])
            .map_err(cache_error)?;
        let Some(row) = rows.next().map_err(cache_error)? else {
            break;
        };
        let target = (
            column(row, 0).map_err(cache_error)?,
            row.get::<_, u32>(1).map_err(cache_error)?,
        );
        let previous = row
            .get::<_, Option<String>>(2)
            .map_err(cache_error)?
            .map(|v| serde_json::from_str::<AuthorHint>(&v))
            .transpose()
            .map_err(cache_error)?
            .unwrap_or(AuthorHint::Unknown);
        drop(rows);
        drop(statement);
        cursor = target;
        let hint = merge(previous.clone(), evidence)?;
        if hint == previous {
            continue;
        }
        execute(
            sql,
            "INSERT INTO authors VALUES(?1,?2,?3,?4) ON CONFLICT(generation,ordinal) DO UPDATE SET resolved_at_generation=excluded.resolved_at_generation,hint_json=excluded.hint_json",
            params![n(target.0), target.1, n(generation), json(&hint)?],
        )?;
        matched += 1;
    }
    if matched > 0 {
        execute(
            sql,
            "INSERT INTO generations VALUES(?1,?2,?3,'Authors')",
            params![n(generation), observed_unix_ms, n(serial)],
        )?;
        execute(
            sql,
            "UPDATE meta SET index_generation=?1,published_generation=?1 WHERE singleton=1",
            [n(generation)],
        )?;
        execute(
            sql,
            "UPDATE files SET last_author_generation=?1 WHERE path=?2",
            params![n(generation), evidence.path.as_str()],
        )?;
    }
    Ok(matched)
}
fn merge(previous: AuthorHint, evidence: &EditEvidence) -> AtlasResult<AuthorHint> {
    let (mut ids, mut omitted) = match previous {
        AuthorHint::Unknown => {
            return Ok(AuthorHint::Captured {
                agent: evidence.agent.clone(),
                evidence: evidence.event.clone(),
            });
        }
        AuthorHint::Captured {
            agent,
            evidence: old,
        } if agent == evidence.agent => {
            return Ok(AuthorHint::Captured {
                agent,
                evidence: if old.as_str() <= evidence.event.as_str() {
                    old
                } else {
                    evidence.event.clone()
                },
            });
        }
        AuthorHint::Captured { evidence, .. } => (vec![evidence], Some(0)),
        AuthorHint::Mixed { evidence, omitted } => (evidence, omitted),
    };
    if ids.contains(&evidence.event) {
        return Ok(AuthorHint::Mixed {
            evidence: ids,
            omitted,
        });
    }
    if ids.len() < 8 {
        ids.push(evidence.event.clone())
    } else {
        omitted = None;
    }
    // None means more distinct IDs may have been discarded; do not invent an
    // exact count when the bounded retained set cannot deduplicate the tail.
    ids.sort_by(|a: &EventId, b| a.as_str().cmp(b.as_str()));
    let hint = AuthorHint::Mixed {
        evidence: ids,
        omitted,
    };
    if json(&hint)?.len() > 2048 {
        return Err(cache_error("author evidence exceeds 2048 bytes"));
    }
    Ok(hint)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_agent_selects_stable_evidence_and_other_agents_conflict() -> AtlasResult<()> {
        let agent = se_types::AgentId::from_parts(1, [1; 10])?;
        let first = EventId::from_parts(1, [2; 10])?;
        let second = EventId::from_parts(1, [3; 10])?;
        let mut evidence = EditEvidence {
            agent: agent.clone(),
            event: second.clone(),
            path: RelativePath::new("file.rs")?,
            before: Some(ContentHash([1; 32])),
            after: Some(ContentHash([2; 32])),
        };
        let initial = merge(AuthorHint::Unknown, &evidence)?;
        evidence.event = first.clone();
        let stable = merge(initial, &evidence)?;
        assert_eq!(
            stable,
            AuthorHint::Captured {
                agent,
                evidence: first.clone()
            }
        );
        evidence.event = second;
        assert_eq!(merge(stable.clone(), &evidence)?, stable);
        evidence.agent = se_types::AgentId::from_parts(1, [4; 10])?;
        assert!(matches!(
            merge(stable, &evidence)?,
            AuthorHint::Mixed { .. }
        ));
        Ok(())
    }
}
