//! Translate complete ledger operations; recorded historical actors are data.
use super::*;
use std::collections::BTreeMap;
const EXCLUDED_PREFIXES: &[&str] = &[
    "campaign.",
    "job.",
    "handoff.",
    "atlas.",
    "bottleneck.",
    "suite.",
    "mutation.",
    "runner.",
    "lock.",
    "runtime.",
    "process.",
    "credential.",
    "machine.",
    "policy.",
];
struct LedgerDecode<'a> {
    cx: &'a NodeContext,
    owner: &'a HumanId,
    ts: i64,
    result: DecodedRow,
    retained: Vec<Value>,
    revisions: BTreeMap<String, Revision>,
}
impl LedgerDecode<'_> {
    fn resolve_agent<R: ImportSnapshot>(&self, read: &mut R, id: &str) -> StoreResult<Actor> {
        Ok(Actor::Agent(if self.revisions.contains_key(id) {
            declared_agent(id)?
        } else {
            agent(read, id)?
        }))
    }
    fn retained_body(
        &self,
        family: ImportFamily,
        legacy_id: String,
        mapped_id: LegacyTarget,
        bytes: Option<LegacyBytes>,
    ) -> EventBody<InputText> {
        EventBody::LegacyRetained {
            import: self.cx.import,
            family,
            format_version: 1,
            legacy_id,
            mapped_id,
            source: self.cx.source.clone(),
            bytes,
            retained_from: None,
        }
    }
    fn resolve_actor<R: ImportSnapshot>(
        &self,
        read: &mut R,
        row: &Value,
        kind: &str,
    ) -> StoreResult<Actor> {
        let is_agent = row.get("actor_type").and_then(Value::as_str) == Some("agent");
        let by = if is_agent
            && row
                .get("actor_id")
                .and_then(Value::as_str)
                .is_some_and(|id| self.revisions.contains_key(id))
        {
            Actor::Agent(declared_agent(str_at(row, "actor_id")?)?)
        } else if kind == "agent.created" && is_agent && row.get("actor_id") == row.get("agent_id")
        {
            Actor::Agent(declared_agent(str_at(row, "agent_id")?)?)
        } else {
            actor(self.cx, read, row)?
        };
        if (kind != "agent.created"
            || row.get("agent_id").and_then(Value::as_str) != Some(actor_id(&by)))
            && !self.revisions.contains_key(actor_id(&by))
        {
            require(read.principal(by.clone())?)?;
        }
        Ok(by)
    }
    fn decode_agent_created(
        &mut self,
        row: &Value,
        by: &Actor,
    ) -> StoreResult<EventBody<InputText>> {
        self.result.family = ImportFamily::Agents;
        let agent = declared_agent(str_at(row, "agent_id")?)?;
        // The current owner explicitly adopts imported agents. Source
        // ownership and permissions remain correspondence, never grants.
        self.revisions
            .insert(agent.to_string(), source_revision(1)?);
        self.retained.push(json!({"agent_id":agent,"owner_human_id":row.get("owner_human_id").and_then(Value::as_str),"origin_model":row.get("origin_model").and_then(Value::as_str),"description":row.get("description").and_then(Value::as_str),"created_by":row.get("created_by").and_then(Value::as_str),"permissions":row.get("permissions").map(|p|json!({"can_create":p.get("can_create").and_then(Value::as_bool)}))}));
        let created_by = (matches!(by, Actor::Agent(_))
            && row.get("agent_id").and_then(Value::as_str) != Some(actor_id(by))
            && row.get("created_by").and_then(Value::as_str) == Some(actor_id(by)))
        .then(|| by.clone());
        Ok(EventBody::PrincipalRegistered {
            principal: Actor::Agent(agent),
            kind: PrincipalKind::Agent,
            owner: self.owner.clone(),
            created_by,
            name: str_at(row, "agent_name")?.into(),
            role: str_at(row, "agent_role")?.into(),
            ephemeral: None,
            expected: Expected::Absent,
        })
    }
    fn decode_event<R: ImportSnapshot>(
        &mut self,
        read: &mut R,
        row: &Value,
        kind: &str,
        key: &str,
        by: &Actor,
    ) -> StoreResult<Option<EventBody<InputText>>> {
        let body = match kind {
            "agent.created" => self.decode_agent_created(row, by)?,
            "agent.renamed" => {
                self.result.family = ImportFamily::Agents;
                let id = str_at(row, "agent_id")?;
                let principal = self.resolve_agent(read, id)?;
                let want = match self.revisions.get(id) {
                    Some(r) => Expected::Revision(*r),
                    None => expected(read.principal(principal.clone())?)?,
                };
                if let Expected::Revision(r) = want {
                    let next = r
                        .value
                        .get()
                        .checked_add(1)
                        .ok_or_else(|| invalid("principal revision overflow"))?;
                    self.revisions.insert(id.into(), source_revision(next)?);
                }
                EventBody::PrincipalRenamed {
                    expected: want,
                    principal,
                    name: str_at(row, "agent_name")?.into(),
                }
            }
            "agent.alias_added" => {
                self.result.family = ImportFamily::Agents;
                let id = str_at(row, "agent_id")?;
                let principal = self.resolve_agent(read, id)?;
                if !self.revisions.contains_key(id) {
                    require(read.principal(principal.clone())?)?;
                }
                let source_key = format!("{key}:alias-source");
                let body = self.retained_body(
                    ImportFamily::Agents,
                    source_key.clone(),
                    LegacyTarget::Principal(principal.clone()),
                    None,
                );
                self.result.events.push(event(
                    self.cx,
                    by.clone(),
                    &source_key,
                    self.ts,
                    None,
                    body,
                )?);
                EventBody::AliasImported {
                    alias: str_at(row, "alias")?.into(),
                    principal,
                    source: event_id(&self.cx.admission.scope, &source_key)?,
                    expected: Expected::Absent,
                }
            }
            "agent.amended" | "agent.permission_granted" => {
                // Historical configuration is retained without granting authority.
                self.retained.push(json!({"type":kind,"agent_id":row.get("agent_id").and_then(Value::as_str),"agent_name":row.get("agent_name").and_then(Value::as_str),"agent_role":row.get("agent_role").and_then(Value::as_str),"description":row.get("description").and_then(Value::as_str),"can_create":row.get("can_create").and_then(Value::as_bool)}));
                return Ok(None);
            }
            "decision.proposed"
            | "decision.ratified"
            | "decision.rejected"
            | "decision.retracted"
            | "decision.superseded"
            | "decision.tier" => {
                // Retired ledger records retain their complete source payload and
                // provenance without creating current decision projections.
                let bytes = serde_json::to_vec(row).map_err(invalid)?;
                self.retained_body(
                    ImportFamily::Decisions,
                    key.to_owned(),
                    LegacyTarget::Record(record_id("retired-decision", key)?),
                    Some(LegacyBytes {
                        sha256: Sha256::digest(&bytes).into(),
                        bytes,
                    }),
                )
            }
            _ => {
                return Err(invalid(format!(
                    "unsupported Node ledger event {kind}; source operation remains uncommitted"
                )));
            }
        };
        Ok(Some(body))
    }
}
pub(super) fn decode<R: ImportSnapshot>(
    cx: &NodeContext,
    read: &mut R,
    row: &Value,
) -> StoreResult<DecodedRow> {
    if !matches!(
        row.get("schema_version").and_then(Value::as_u64),
        Some(1 | 2)
    ) {
        return Err(invalid("unsupported Node ledger version"));
    }
    let txn = str_at(row, "txn_id")?;
    let ts = time::micros(str_at(row, "ts")?)?;
    let rows = row
        .get("events")
        .and_then(Value::as_array)
        .filter(|r| !r.is_empty() && r.len() <= 4096)
        .ok_or_else(|| invalid("Node ledger operation must contain 1..4096 source events"))?;
    let Actor::Human(owner) = &cx.admission.actor else {
        return Err(invalid("owner import admission required"));
    };
    let family = if rows.iter().any(|r| {
        r.get("type")
            .and_then(Value::as_str)
            .is_some_and(|k| k.starts_with("agent."))
    }) {
        ImportFamily::Agents
    } else {
        ImportFamily::Decisions
    };
    let mut state = LedgerDecode {
        cx,
        owner,
        ts,
        result: registration::result(
            family,
            format!("ledger:{txn}"),
            LegacyTarget::Record(record_id("ledger", txn)?),
        ),
        retained: Vec::new(),
        revisions: BTreeMap::new(),
    };
    let (mut excluded, mut user_events) = (0u64, 0u64);
    for (index, row) in rows.iter().enumerate() {
        let key = format!("ledger:{txn}:{index}");
        if seen(read, cx, event_id(&cx.admission.scope, &key)?)? {
            state.result.duplicate = true;
            continue;
        }
        let kind = str_at(row, "type")?;
        if kind == "ledger.chain_anchor" || EXCLUDED_PREFIXES.iter().any(|p| kind.starts_with(p)) {
            excluded += 1;
            continue;
        }
        user_events += 1;
        if user_events > 18 {
            return Err(invalid(
                "source operation exceeds the 18-user-event atomic import bound",
            ));
        }
        let by = state.resolve_actor(read, row, kind)?;
        let Some(body) = state.decode_event(read, row, kind, &key, &by)? else {
            continue;
        };
        // Allocate immutable, source-bound exception dictionary entries before
        // either the event actor or principal revision can allocate an ID.
        if let EventBody::PrincipalRegistered {
            principal: Actor::Agent(agent),
            ..
        } = &body
        {
            let identity = state.retained_body(
                ImportFamily::Agents,
                agent.to_string(),
                LegacyTarget::Principal(Actor::Agent(agent.clone())),
                None,
            );
            state.result.events.push(event(
                cx,
                cx.admission.actor.clone(),
                &format!("{key}:identity"),
                ts,
                None,
                identity,
            )?);
        }
        state
            .result
            .events
            .push(event(cx, by, &key, ts, None, body)?);
    }
    if !state.retained.is_empty() || excluded > 0 {
        state.result.retained = Some(
            json!({"historical_configuration":state.retained,"excluded_non_user_events":excluded,"user_events":user_events}),
        );
    }
    state.result.duplicate &= user_events == 0;
    state.result.dropped_by_policy = user_events == 0 && !state.result.duplicate;
    Ok(state.result)
}
