//! Translate complete ledger operations; recorded historical actors are data.
use super::*;
use std::collections::BTreeMap;

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
    let mut result = DecodedRow {
        events: Vec::new(),
        family: if rows.iter().any(|r| {
            r.get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.starts_with("agent."))
        }) {
            ImportFamily::Agents
        } else {
            ImportFamily::Decisions
        },
        legacy_id: format!("ledger:{txn}"),
        target: LegacyTarget::Record(record_id("ledger", txn)?),
        retained: None,
        resume: Vec::new(),
        duplicate: false,
        dropped_by_policy: false,
        dispositions: None,
    };
    let mut revisions: BTreeMap<String, Revision> = BTreeMap::new();
    let mut retained = Vec::new();
    let mut excluded = 0u64;
    let mut user_events = 0u64;
    let mut proposed_keys = BTreeMap::<String, String>::new();
    let mut principal_revisions = BTreeMap::<String, Revision>::new();
    let mut governing = BTreeMap::<String, Option<(DecisionId, Revision)>>::new();
    let Actor::Human(owner) = &cx.admission.actor else {
        return Err(invalid("owner import admission required"));
    };
    for (index, row) in rows.iter().enumerate() {
        let key = format!("ledger:{txn}:{index}");
        if seen(read, cx, event_id(&cx.admission.scope, &key)?)? {
            result.duplicate = true;
            continue;
        }
        let kind = str_at(row, "type")?;
        if kind == "ledger.chain_anchor"
            || [
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
            ]
            .iter()
            .any(|prefix| kind.starts_with(prefix))
        {
            excluded += 1;
            continue;
        }
        user_events += 1;
        if user_events > 18 {
            return Err(invalid(
                "source operation exceeds the 18-user-event atomic import bound",
            ));
        }
        let by = if row.get("actor_type").and_then(Value::as_str) == Some("agent")
            && row
                .get("actor_id")
                .and_then(Value::as_str)
                .is_some_and(|id| principal_revisions.contains_key(id))
        {
            Actor::Agent(declared_agent(str_at(row, "actor_id")?)?)
        } else if kind == "agent.created"
            && row.get("actor_type").and_then(Value::as_str) == Some("agent")
            && row.get("actor_id") == row.get("agent_id")
        {
            Actor::Agent(declared_agent(str_at(row, "agent_id")?)?)
        } else {
            actor(cx, read, row)?
        };
        if (kind != "agent.created"
            || row.get("agent_id").and_then(Value::as_str) != Some(actor_id(&by)))
            && !principal_revisions.contains_key(actor_id(&by))
        {
            require(read.principal(by.clone())?)?;
        }
        let mut afterward = Vec::new();
        let body = match kind {
            "agent.created" => {
                result.family = ImportFamily::Agents;
                let agent = declared_agent(str_at(row, "agent_id")?)?;
                // The current owner explicitly adopts imported agents. Source
                // ownership and permissions remain correspondence, never grants.
                principal_revisions.insert(
                    agent.to_string(),
                    Revision {
                        value: std::num::NonZeroU64::new(1).ok_or_else(|| invalid("revision"))?,
                    },
                );
                retained.push(json!({"agent_id":agent,"owner_human_id":row.get("owner_human_id").and_then(Value::as_str),"origin_model":row.get("origin_model").and_then(Value::as_str),"description":row.get("description").and_then(Value::as_str),"created_by":row.get("created_by").and_then(Value::as_str),"permissions":row.get("permissions").map(|p|json!({"can_create":p.get("can_create").and_then(Value::as_bool)}))}));

                EventBody::PrincipalRegistered {
                    principal: Actor::Agent(agent),
                    kind: PrincipalKind::Agent,
                    owner: owner.clone(),
                    created_by: if matches!(by, Actor::Agent(_))
                        && row.get("agent_id").and_then(Value::as_str) != Some(actor_id(&by))
                        && row.get("created_by").and_then(Value::as_str) == Some(actor_id(&by))
                    {
                        Some(by.clone())
                    } else {
                        None
                    },
                    name: str_at(row, "agent_name")?.into(),
                    role: str_at(row, "agent_role")?.into(),
                    expected: Expected::Absent,
                }
            }
            "agent.renamed" => {
                result.family = ImportFamily::Agents;
                let id = str_at(row, "agent_id")?;
                let principal = Actor::Agent(if principal_revisions.contains_key(id) {
                    declared_agent(id)?
                } else {
                    agent(read, id)?
                });
                let want = match principal_revisions.get(id) {
                    Some(r) => Expected::Revision(*r),
                    None => expected(read.principal(principal.clone())?)?,
                };
                if let Expected::Revision(r) = want {
                    principal_revisions.insert(
                        id.into(),
                        source_revision(
                            r.value
                                .get()
                                .checked_add(1)
                                .ok_or_else(|| invalid("principal revision overflow"))?,
                        )?,
                    );
                }
                EventBody::PrincipalRenamed {
                    expected: want,
                    principal,
                    name: str_at(row, "agent_name")?.into(),
                }
            }
            "agent.alias_added" => {
                result.family = ImportFamily::Agents;
                let id = str_at(row, "agent_id")?;
                let principal = Actor::Agent(if principal_revisions.contains_key(id) {
                    declared_agent(id)?
                } else {
                    agent(read, id)?
                });
                if !principal_revisions.contains_key(id) {
                    require(read.principal(principal.clone())?)?;
                }
                let source_key = format!("{key}:alias-source");
                result.events.push(event(
                    cx,
                    by.clone(),
                    &source_key,
                    ts,
                    None,
                    EventBody::LegacyRetained {
                        import: cx.import,
                        family: ImportFamily::Agents,
                        format_version: 1,
                        legacy_id: source_key.clone(),
                        mapped_id: LegacyTarget::Principal(principal.clone()),
                        source: cx.source.clone(),
                        bytes: None,
                        retained_from: None,
                    },
                )?);
                EventBody::AliasImported {
                    alias: str_at(row, "alias")?.into(),
                    principal,
                    source: event_id(&cx.admission.scope, &source_key)?,
                    expected: Expected::Absent,
                }
            }
            "agent.amended" | "agent.permission_granted" => {
                // Historical configuration is retained without granting authority.
                retained.push(json!({"type":kind,"agent_id":row.get("agent_id").and_then(Value::as_str),"agent_name":row.get("agent_name").and_then(Value::as_str),"agent_role":row.get("agent_role").and_then(Value::as_str),"description":row.get("description").and_then(Value::as_str),"can_create":row.get("can_create").and_then(Value::as_bool)}));
                continue;
            }
            "decision.proposed" => {
                let id = DecisionId::from_legacy(str_at(row, "decision_id")?).map_err(invalid)?;
                let revision = Revision {
                    value: std::num::NonZeroU64::new(1).ok_or_else(|| invalid("revision"))?,
                };
                revisions.insert(id.to_string(), revision);
                proposed_keys.insert(id.to_string(), str_at(row, "key")?.into());
                if row.get("supersedes_key").is_some() {
                    retained
                        .push(json!({"decision_id":id,"supersedes_key":row.get("supersedes_key")}));
                }
                EventBody::DecisionProposed {
                    decision: id,
                    key: str_at(row, "key")?.into(),
                    statement: InputText::Inline(str_at(row, "statement")?.into()),
                    rationale: optional(row, "rationale").map(InputText::Inline),
                    prior: None,
                    kind: DecisionKind::Decision,
                }
            }
            "decision.ratified" | "decision.rejected" | "decision.retracted" => {
                if !matches!(by, Actor::Human(_)) {
                    return Err(invalid(
                        "Node decision transition does not record a human actor",
                    ));
                }
                let decision =
                    DecisionId::from_legacy(str_at(row, "decision_id")?).map_err(invalid)?;
                let revision = match revisions.get(decision.as_str()) {
                    Some(r) => *r,
                    None => require(read.decision(decision.clone())?)?.revision,
                };
                let want = Expected::Revision(revision);
                let next = revision
                    .value
                    .get()
                    .checked_add(1)
                    .and_then(std::num::NonZeroU64::new)
                    .ok_or_else(|| invalid("decision revision overflow"))?;
                revisions.insert(decision.to_string(), Revision { value: next });
                if kind == "decision.ratified" {
                    // Retain the actual historical human transition as approval
                    // evidence before the typed transition, not a new human act.
                    let approval_key = format!("{key}:source-approval");
                    let bytes = serde_json::to_vec(
                        &json!({"type":kind,"decision_id":decision,"actor_type":row.get("actor_type").and_then(Value::as_str),"actor_id":row.get("actor_id").and_then(Value::as_str),"rationale":row.get("rationale").and_then(Value::as_str),"transaction":txn,"source_evidence":cx.source}),
                    )
                    .map_err(invalid)?;
                    let hash = Sha256::digest(&bytes).into();
                    result.events.push(event(
                        cx,
                        by.clone(),
                        &approval_key,
                        ts,
                        None,
                        EventBody::LegacyRetained {
                            import: cx.import,
                            family: ImportFamily::Decisions,
                            format_version: 1,
                            legacy_id: approval_key.clone(),
                            mapped_id: LegacyTarget::Decision(decision.clone()),
                            source: cx.source.clone(),
                            bytes: Some(LegacyBytes {
                                bytes,
                                sha256: hash,
                            }),
                            retained_from: None,
                        },
                    )?);
                    let label = if let Some(key) = proposed_keys.get(decision.as_str()) {
                        key.clone()
                    } else {
                        let head = require(read.decision(decision.clone())?)?;
                        let original = head.original.as_deref().unwrap_or(&head.current);
                        let EventBody::DecisionProposed { key, .. } = &original.body else {
                            return Err(invalid("imported decision proposal metadata absent"));
                        };
                        key.clone()
                    };
                    let prior = match governing.get(&label) {
                        Some(prior) => prior.clone(),
                        None => read.import_prior(&label)?,
                    };
                    let replacement_revision = Revision { value: next };
                    let approval = event_id(&cx.admission.scope, &approval_key)?;
                    if let Some((prior, prior_revision)) = prior
                        && prior != decision
                    {
                        revisions.insert(
                            prior.to_string(),
                            source_revision(
                                prior_revision
                                    .value
                                    .get()
                                    .checked_add(1)
                                    .ok_or_else(|| invalid("source decision revision overflow"))?,
                            )?,
                        );
                        afterward.push(event(
                            cx,
                            by.clone(),
                            &format!("{key}:superseded"),
                            ts,
                            None,
                            EventBody::DecisionSuperseded {
                                prior,
                                replacement: decision.clone(),
                                prior_expected: prior_revision,
                                replacement_expected: replacement_revision,
                                approval: approval.clone(),
                            },
                        )?);
                    }

                    governing.insert(label, Some((decision.clone(), replacement_revision)));
                    EventBody::DecisionRatified {
                        decision,
                        expected: want,
                        approval,
                    }
                } else if kind == "decision.rejected" {
                    EventBody::DecisionRejected {
                        decision,
                        expected: want,
                        reason: InputText::Inline(str_at(row, "rationale")?.into()),
                    }
                } else {
                    let label = if let Some(label) = proposed_keys.get(decision.as_str()) {
                        label.clone()
                    } else {
                        let head = require(read.decision(decision.clone())?)?;
                        match &head.original.as_deref().unwrap_or(&head.current).body {
                            EventBody::DecisionProposed { key, .. } => key.clone(),
                            _ => return Err(invalid("source decision proposal absent")),
                        }
                    };
                    governing.insert(label, None);
                    EventBody::DecisionRetracted {
                        decision,
                        expected: want,
                        reason: InputText::Inline(str_at(row, "rationale")?.into()),
                    }
                }
            }
            "decision.tier" => {
                retained.push(json!({"type":kind,"decision_id":row.get("decision_id"),"tier":row.get("tier")}));
                continue;
            }
            _ => {
                return Err(invalid(format!(
                    "unsupported Node ledger event {kind}; source operation remains uncommitted"
                )));
            }
        };
        let registration = match &body {
            EventBody::PrincipalRegistered {
                principal: Actor::Agent(agent),
                ..
            } => Some(agent.clone()),
            _ => None,
        };
        // Allocate immutable, source-bound exception dictionary entries before
        // either the event actor or principal revision can allocate an ID.
        if let Some(agent) = registration {
            result.events.push(event(
                cx,
                cx.admission.actor.clone(),
                &format!("{key}:identity"),
                ts,
                None,
                EventBody::LegacyRetained {
                    import: cx.import,
                    family: ImportFamily::Agents,
                    format_version: 1,
                    legacy_id: agent.to_string(),
                    mapped_id: LegacyTarget::Principal(Actor::Agent(agent)),
                    source: cx.source.clone(),
                    bytes: None,
                    retained_from: None,
                },
            )?);
        }
        result.events.push(event(cx, by, &key, ts, None, body)?);
    }
    if !retained.is_empty() || excluded > 0 {
        result.retained = Some(
            json!({"historical_configuration":retained,"excluded_non_user_events":excluded,"user_events":user_events}),
        );
    }
    result.duplicate &= user_events == 0;
    result.dropped_by_policy = user_events == 0 && !result.duplicate;
    Ok(result)
}
