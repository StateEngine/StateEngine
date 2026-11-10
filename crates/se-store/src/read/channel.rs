//! Bounded native Owner views; no channel metadata is exposed as an agent tool.
mod output;
mod rejections;
mod resume;
use super::*;
use crate::channel::*;
use crate::connection::project_id;

impl SqliteSnapshot {
    pub(super) fn read_channel_route(
        &mut self,
        message: &se_types::MessageId,
    ) -> StoreResult<Option<ReplyRoute>> {
        if self.info.schema_version < 6 {
            return Ok(None);
        }
        let record = match self.message(message.clone())? {
            Read::Present { value } => value,
            Read::Absent { .. } => return Ok(None),
            _ => return Err(fail(StoreErrorCode::Unreadable, "mail route unreadable")),
        };
        if !matches!(self.scope.visibility, Visibility::Owner)
            && self.scope.admission.actor != record.recipient
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "phone reply route belongs to its exact recipient",
            ));
        }
        let p = project_id(&self.db, &self.scope.admission.scope, false)?;
        let s = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let m = key(&self.db, "message", message.as_str(), &s, false)?;
        let json:Option<String>=self.db.query_row("SELECT cc.state_json FROM channel_updates u JOIN channel_connections cc ON cc.id=u.connection_id WHERE cc.project_id=? AND u.message_id=? AND u.receipt_id IS NOT NULL",crate::sql_value::sql_params![p,m],|r|r.get(0)).optional().map_err(|e|self.read_sql(e))?;
        json.map(|json| {
            let state: crate::channel::Connection = serde_json::from_str(&json).map_err(invalid)?;
            Ok(ReplyRoute {
                owner: state.owner,
                original: message.clone(),
                active: matches!(state.pairing, Pairing::Paired { .. }),
            })
        })
        .transpose()
    }
    pub(super) fn read_active_channels(&self) -> StoreResult<Vec<crate::channel::Connection>> {
        let owner = self.channel_owner()?;
        if self.info.schema_version < 6 {
            return Ok(vec![]);
        }
        let project = if matches!(self.scope.admission.scope, Scope::Project(_)) {
            Some(project_id(&self.db, &self.scope.admission.scope, false)?)
        } else {
            None
        };
        let rows:Vec<String>=self.db.prepare_cached("SELECT state_json FROM channel_connections WHERE active=1 AND owner_id=? AND (? IS NULL OR project_id=?) LIMIT 101").map_err(|e|self.read_sql(e))?.query_map(crate::sql_value::sql_params![owner,project,project],|r|r.get(0)).map_err(|e|self.read_sql(e))?.collect::<Result<_,_>>().map_err(|e|self.read_sql(e))?;
        if rows.len() > MAX_CONNECTIONS {
            return Err(fail(
                StoreErrorCode::ReadIncomplete,
                "active channel bound exceeded",
            ));
        }
        rows.into_iter()
            .map(|s| serde_json::from_str(&s).map_err(invalid))
            .collect()
    }
    pub(super) fn read_update_handled(
        &self,
        id: &ChannelId,
        update: &crate::channel::ExternalId,
    ) -> StoreResult<bool> {
        self.require_channel(id)?;
        self.db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM channel_updates WHERE connection_id=? AND update_id=?)",
                crate::sql_value::sql_params![id.as_str(), update],
                |r| r.get(0),
            )
            .map_err(|e| self.read_sql(e))
    }
    pub(super) fn read_channel_version(&self) -> StoreResult<Version> {
        self.channel_owner()?;
        Ok(Version {
            store: self.info.id.clone(),
            incarnation: self.info.incarnation,
            head: self
                .info
                .head
                .as_ref()
                .map(StorePosition::sequence)
                .unwrap_or(0),
        })
    }
    fn channel_owner(&self) -> StoreResult<Vec<u8>> {
        let Actor::Human(owner) = &self.scope.admission.actor else {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "channel inspection requires native Owner",
            ));
        };
        if !matches!(self.scope.visibility, Visibility::Owner)
            || self.scope.admission.session.is_some()
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "channel inspection requires native Owner visibility",
            ));
        }
        key(&self.db, "human", owner.as_str(), &[0], false)
    }
    pub(super) fn read_channel(
        &self,
        id: &ChannelId,
    ) -> StoreResult<Read<crate::channel::Connection>> {
        let owner = self.channel_owner()?;
        if self.info.schema_version < 6 {
            return Ok(self.absent("channel"));
        }
        let row: Option<(Vec<u8>, Vec<u8>, String)> = self
            .db
            .query_row(
                "SELECT owner_id,project_id,state_json FROM channel_connections WHERE id=?",
                [id.as_str()],
                |r| {
                    Ok((
                        crate::sql_value::value(r, 0)?,
                        crate::sql_value::value(r, 1)?,
                        crate::sql_value::value(r, 2)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| self.read_sql(e))?;
        let Some((recorded_owner, project, json)) = row else {
            return Ok(self.absent("channel"));
        };
        if owner != recorded_owner
            || (matches!(self.scope.admission.scope, Scope::Project(_))
                && project_id(&self.db, &self.scope.admission.scope, false)? != project)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "channel outside admitted Owner/project",
            ));
        }
        Ok(Read::Present {
            value: serde_json::from_str(&json).map_err(invalid)?,
        })
    }
    pub(super) fn read_channels(
        &self,
        after: u64,
    ) -> StoreResult<ChannelRows<crate::channel::Connection>> {
        let owner = self.channel_owner()?;
        if self.info.schema_version < 6 {
            return Ok(ChannelRows {
                items: vec![],
                after,
                omitted: 0,
            });
        }
        let project = if matches!(self.scope.admission.scope, Scope::Project(_)) {
            Some(project_id(&self.db, &self.scope.admission.scope, false)?)
        } else {
            None
        };
        let total: u64 = self.db.query_row("SELECT count(*) FROM channel_connections WHERE owner_id=? AND (? IS NULL OR project_id=?) AND last_seq>?", crate::sql_value::sql_params![owner,project,project,after],|r|crate::sql_value::value(r, 0)).map_err(|e|self.read_sql(e))?;
        let rows: Vec<(u64,String)> = self.db.prepare_cached("SELECT last_seq,state_json FROM channel_connections WHERE owner_id=? AND (? IS NULL OR project_id=?) AND last_seq>? ORDER BY last_seq LIMIT 100").map_err(|e|self.read_sql(e))?.query_map(crate::sql_value::sql_params![owner,project,project,after], |r|Ok((crate::sql_value::value(r, 0)?,crate::sql_value::value(r, 1)?))).map_err(|e|self.read_sql(e))?.collect::<Result<_,_>>().map_err(|e|self.read_sql(e))?;
        let end = rows.last().map(|r| r.0).unwrap_or(after);
        let items: Vec<crate::channel::Connection> = rows
            .into_iter()
            .map(|(_, s)| serde_json::from_str(&s).map_err(invalid))
            .collect::<StoreResult<_>>()?;
        Ok(ChannelRows {
            omitted: total.saturating_sub(items.len() as u64),
            items,
            after: end,
        })
    }
    pub(super) fn read_saved_receipt(
        &self,
        id: &ChannelId,
        receipt: &ReceiptId,
    ) -> StoreResult<Read<SavedUpdate>> {
        let state = self.require_channel(id)?;
        let row:Option<(String,u64,Vec<u8>,i64)>=self.db.query_row("SELECT u.connection_id,u.handled_seq,u.message_id,e.recorded_at_us FROM channel_updates u JOIN events e ON e.seq=u.handled_seq WHERE u.receipt_id=?",[receipt.as_str()],|r|Ok((r.get(0)?,crate::sql_value::value(r,1)?,r.get(2)?,r.get(3)?))).optional().map_err(|e|self.read_sql(e))?;
        let Some((connection, ordinal, message, at_us)) = row else {
            return Ok(self.absent("saved channel receipt"));
        };
        if connection != id.as_str() {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "receipt belongs to another channel",
            ));
        }
        let scope = scope_key(&self.db, &Scope::Project(state.target.project), false)?;
        let event = crate::read::load_event(
            &self.db,
            i64::try_from(ordinal).map_err(invalid)?,
            &self.info,
        )?;
        Ok(Read::Present {
            value: SavedUpdate {
                ordinal,
                receipt: receipt.clone(),
                connection: id.clone(),
                message: wire(&self.db, "message", &message, &scope)?
                    .try_into()
                    .map_err(invalid)?,
                event: event.header.event,
                at_us,
            },
        })
    }
    pub(super) fn read_saved(
        &self,
        id: &ChannelId,
        after: u64,
    ) -> StoreResult<ChannelRows<SavedUpdate>> {
        self.require_channel(id)?;
        let total: u64 = if after == 0 {
            self.db
                .query_row(
                    "SELECT saved_count FROM channel_connections WHERE id=?",
                    [id.as_str()],
                    |r| crate::sql_value::value(r, 0),
                )
                .map_err(|e| self.read_sql(e))?
        } else {
            self.db.query_row("SELECT count(*) FROM channel_updates WHERE connection_id=? AND handled_seq<? AND receipt_id IS NOT NULL",crate::sql_value::sql_params![id.as_str(),after],|r|crate::sql_value::value(r,0)).map_err(|e|self.read_sql(e))?
        };
        let rows: Vec<(u64,String,Vec<u8>,i64)> = self.db.prepare_cached("SELECT u.handled_seq,u.receipt_id,u.message_id,e.recorded_at_us FROM channel_updates u JOIN events e ON e.seq=u.handled_seq WHERE u.connection_id=? AND (?2=0 OR u.handled_seq<?2) AND u.receipt_id IS NOT NULL ORDER BY u.handled_seq DESC LIMIT 100").map_err(|e|self.read_sql(e))?.query_map(crate::sql_value::sql_params![id.as_str(),after],|r|Ok((crate::sql_value::value(r, 0)?,crate::sql_value::value(r, 1)?,crate::sql_value::value(r, 2)?,crate::sql_value::value(r, 3)?))).map_err(|e|self.read_sql(e))?.collect::<Result<_,_>>().map_err(|e|self.read_sql(e))?;
        let end = rows.last().map(|r| r.0).unwrap_or(after);
        let state = self.require_channel(id)?;
        let scope = scope_key(&self.db, &Scope::Project(state.target.project), false)?;
        let mut items = Vec::new();
        for (seq, receipt, message, at_us) in rows {
            let event = crate::read::load_event(&self.db, seq as i64, &self.info)?;
            items.push(SavedUpdate {
                ordinal: seq,
                receipt: ReceiptId::new(receipt).map_err(invalid)?,
                connection: id.clone(),
                message: wire(&self.db, "message", &message, &scope)?
                    .try_into()
                    .map_err(invalid)?,
                event: event.header.event,
                at_us,
            });
        }
        Ok(ChannelRows {
            omitted: total.saturating_sub(items.len() as u64),
            items,
            after: end,
        })
    }
    pub(super) fn read_outbox(
        &self,
        id: &ChannelId,
        after: u64,
    ) -> StoreResult<ChannelRows<Outbound>> {
        self.read_outputs(id, after, None, None)
    }
    pub(super) fn read_channel_cursor(
        &self,
        id: &ChannelId,
    ) -> StoreResult<Option<crate::channel::ReceiveCursor>> {
        let state = self.require_channel(id)?;
        self.db
            .query_row(
                "SELECT cursor FROM channel_receive WHERE connector=? AND bot_id=?",
                rusqlite::params![state.connector.as_str(), state.bot.id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| self.read_sql(e))
    }

    pub(crate) fn require_channel(
        &self,
        id: &ChannelId,
    ) -> StoreResult<crate::channel::Connection> {
        match self.read_channel(id)? {
            Read::Present { value } => Ok(value),
            Read::Absent { .. } => Err(fail(StoreErrorCode::ReferenceMissing, "channel absent")),
            Read::Unreadable { .. } | Read::Unknown { .. } => {
                Err(fail(StoreErrorCode::Unreadable, "channel unreadable"))
            }
        }
    }
}
