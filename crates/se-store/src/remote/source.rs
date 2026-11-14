//! Stable source-address policy; absence preserves legacy machine-grant verbs.
use super::*;
use se_types::remote::RemoteAgentAddress;

pub(crate) fn permission(
    c: &Connection,
    address: &RemoteAgentAddress,
) -> StoreResult<Option<SourcePermission>> {
    c.query_row(
        "SELECT allowed,revision FROM remote_source_permissions WHERE address=?",
        [encode(address)?],
        |r| Ok((r.get::<_, bool>(0)?, r.get::<_, i64>(1)?)),
    )
    .optional()
    .map_err(sql)?
    .map(|(allowed, revision)| {
        Ok(SourcePermission {
            address: address.clone(),
            allowed,
            revision: crate::codec::revision(u64::try_from(revision).map_err(invalid)?)?,
        })
    })
    .transpose()
}

pub(crate) fn admit_source(
    c: &Connection,
    source: Option<&se_types::remote::RemoteSourceSession>,
) -> StoreResult<()> {
    if let Some(source) = source {
        admit_address(c, &source.address())?;
    }
    Ok(())
}
pub(crate) fn admit_address(c: &Connection, address: &RemoteAgentAddress) -> StoreResult<()> {
    if crate::connection::info(c)?.schema_version >= 12 && pending(c, address)?.is_some() {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "this source address has an unresolved revocation and is blocked; its Owner can finish the revoke or explicitly allow it with se remote permissions --local in a terminal on the destination",
        ));
    }
    if crate::connection::info(c)?.schema_version >= 12
        && permission(c, address)?.is_some_and(|p| !p.allowed)
    {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "this source agent address is revoked; the destination Owner can allow it again with se remote permissions --local in a terminal on the destination",
        ));
    }
    Ok(())
}

pub(crate) fn pending(
    c: &Connection,
    address: &RemoteAgentAddress,
) -> StoreResult<Option<se_types::IdempotencyKey>> {
    let key: Option<String> = c
        .query_row(
            "SELECT request_key FROM remote_source_revocations WHERE address=?",
            [encode(address)?],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    key.map(|key| se_types::IdempotencyKey::new(key).map_err(invalid))
        .transpose()
}

pub(crate) fn remember_source(
    c: &Connection,
    record: &MessageAttribution,
    seq: i64,
) -> StoreResult<()> {
    if crate::connection::info(c)?.schema_version >= 12
        && let Some(source) = &record.attribution.source
    {
        c.execute(
            "INSERT OR IGNORE INTO remote_source_contacts(address,first_seq) VALUES(?,?)",
            rusqlite::params![encode(&source.address())?, seq],
        )
        .map_err(sql)?;
    }
    Ok(())
}
