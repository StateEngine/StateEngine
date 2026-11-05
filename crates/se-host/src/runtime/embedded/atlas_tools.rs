//! SE Code uses the same registered Atlas tools, planner, snapshot and renderer.
use super::{EmbeddedHost, binding, store};
use se_core::{
    commit::{Cx, OpStep},
    dispatch::Kernel,
    ops,
    ports::CustodyPlan,
    registry::{Feature, McpExposure},
};
use se_types::{Result, SeError, code::AtlasFormat};
use secode_stateengine_api as api;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn invalid(what: &str) -> SeError {
    SeError::invalid("embedded Atlas tools", what)
}
impl EmbeddedHost {
    pub(super) async fn atlas_tools(
        &self,
        session: &api::BoundSession,
        page: api::PageRequest,
        options: api::CallOptions,
    ) -> Result<api::Page<api::ToolDefinition>> {
        self.bindings.verify(session)?;
        let (router, deadline, _cancel) = self.ready(&options).await?;
        if session.generation != options.generation
            || !(1..=100).contains(&page.limit)
            || !(1..=65536).contains(&page.max_bytes)
            || page.max_bytes > self.config.limits.payload_bytes.get()
        {
            return Err(invalid(
                "the bound generation, 1..100 tools and 1..65536 bytes within the negotiated payload cap",
            ));
        }
        let epoch = self
            .native
            .lock()
            .map_err(|_| invalid("an unpoisoned native epoch"))?
            .as_ref()
            .map(|(epoch, _)| epoch.clone())
            .ok_or_else(|| invalid("a ready native host epoch"))?;
        let scope = binding::session_scope(session)?;
        let checked = scope.clone();
        let revision = session.binding_revision;
        let fingerprint = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&json!([
                    "atlas-tools-v1",
                    session.identity.project.0,
                    session.identity.agent.0,
                    session.identity.session.0,
                    session.generation.0,
                    revision.0.get()
                ]))
                .map_err(|_| invalid("a serializable catalogue scope"))?
            )
        );
        store::read(&router, scope, &deadline, move |read| {
            binding::check(read, &checked, revision)?;
            catalogue(page, epoch, &fingerprint)
        })
        .await
    }
    pub(super) async fn atlas_call(
        &self,
        session: &api::BoundSession,
        call: api::ToolCall,
        options: api::CallOptions,
    ) -> Result<api::ToolOutput> {
        self.bindings.verify(session)?;
        let (router, deadline, _cancel) = self.ready(&options).await?;
        if session.generation != options.generation
            || call.identity != api::RequestIdentity::ReadOnly
        {
            return Err(invalid(
                "the bound generation and ReadOnly identity for Atlas queries",
            ));
        }
        let operation = ops::decode_tool(&call.name, call.arguments)?;
        let presentation = operation
            .atlas_options()
            .ok_or_else(|| invalid("one of the five registered Atlas read tools"))?
            .clone();
        let family = operation.meta().family;
        let owner = router.execution.atlas.clone();
        let ticket = owner.records.ticket()?;
        let scope = binding::session_scope(session)?;
        let checked = scope.clone();
        let revision = session.binding_revision;
        let now = super::super::start::now_unix_micros()? / 1000;
        let output = store::read(&router, scope, &deadline, move |read| {
            binding::check(read, &checked, revision)?;
            let mut cx = Cx {
                read,
                admission: &checked.admission,
            };
            let terminal = se_core::admission::HumanTerminal::Refused {
                reason: "a native bound-session tool has no human terminal authority".into(),
            };
            match Kernel::read_only().plan(operation, &mut cx, &terminal)? {
                OpStep::Custody(CustodyPlan::AtlasRead(request)) => {
                    crate::atlas_queries::owner_read(
                        &owner,
                        ticket,
                        &request,
                        cx.read,
                        &checked.admission,
                        now,
                    )
                }
                _ => Err(invalid("the registered read-only Atlas execution plan")),
            }
        })
        .await?;
        if output.family() != family {
            return Err(invalid("the requested typed Atlas output family"));
        }
        let content = if presentation.format == AtlasFormat::Json {
            serde_json::to_value(&output).map_err(|_| invalid("a serializable Atlas answer"))?
        } else {
            Value::String(
                crate::atlas_queries::compact(
                    &output,
                    presentation.byte_budget.saturating_sub(192) as usize,
                    presentation.explain,
                )?
                .ok_or_else(|| invalid("the registered Atlas compact renderer"))?,
            )
        };
        let encoded = serde_json::to_vec(&json!({"schema":family.schema(),"content":content}))
            .map_err(|_| invalid("a serializable Atlas tool result"))?;
        if encoded.len() > presentation.byte_budget as usize {
            return Err(invalid(
                "an answer within byte_budget; narrow the query or request up to 32768 bytes",
            ));
        }
        Ok(api::ToolOutput {
            schema: family.schema(),
            content,
            window: None,
        })
    }
}
fn catalogue(
    page: api::PageRequest,
    epoch: api::HostEpoch,
    fingerprint: &str,
) -> Result<api::Page<api::ToolDefinition>> {
    let metas: Vec<_> = ops::CATALOGUE
        .iter()
        .filter(|m| m.feature == Feature::Atlas && matches!(m.mcp, McpExposure::Tool { .. }))
        .collect();
    let offset = if let Some(cursor) = &page.after {
        let parts: Vec<_> = cursor.0.split('.').collect();
        if cursor.0.len() > 100 || parts.len() != 3 || parts[0] != "at1" || parts[2] != fingerprint
        {
            return Err(invalid(
                "a catalogue cursor for this bound session and generation",
            ));
        }
        let value: usize = parts[1]
            .parse()
            .map_err(|_| invalid("a canonical catalogue position"))?;
        if value.to_string() != parts[1] {
            return Err(invalid("a canonical catalogue position"));
        }
        value
    } else {
        0
    };
    if offset > metas.len() {
        return Err(invalid("a catalogue position within the registered tools"));
    }
    let mut items = Vec::new();
    let mut bytes = 0;
    let mut stop = api::StopReason::Exhausted;
    for meta in metas.iter().skip(offset) {
        if items.len() == page.limit as usize {
            stop = api::StopReason::ItemLimit;
            break;
        }
        let McpExposure::Tool {
            name, description, ..
        } = meta.mcp
        else {
            return Err(invalid("an exposed Atlas catalogue row"));
        };
        let (input_schema, mut output_schema) = ops::schemas(meta.name)
            .ok_or_else(|| invalid("the generated input and output schema"))?;
        // Hoist definitions so their root-relative references remain valid in
        // the union of default compact text and the explicitly requested JSON.
        let definitions = output_schema
            .as_object_mut()
            .and_then(|v| v.remove("$defs"));
        let mut output_schema = json!({"oneOf":[{"type":"string"},output_schema]});
        if let Some(definitions) = definitions {
            output_schema["$defs"] = definitions;
        }
        let cost = serde_json::to_vec(&json!({"name":name,"description":description,"input_schema":input_schema,"output_schema":output_schema})).map_err(|_|invalid("a serializable tool definition"))?.len();
        if bytes + cost > page.max_bytes as usize {
            if items.is_empty() {
                return Err(invalid(&format!(
                    "at least {cost} bytes to return the first complete tool definition"
                )));
            }
            stop = api::StopReason::ByteLimit;
            break;
        }
        bytes += cost;
        items.push(api::ToolDefinition {
            name: name.into(),
            description: description.into(),
            input_schema,
            output_schema,
        });
    }
    let end = offset + items.len();
    let more = end < metas.len();
    let next = more.then(|| api::Cursor(format!("at1.{end}.{fingerprint}")));
    Ok(api::Page {
        window: api::Window {
            source: api::Source::Host { epoch },
            start_cursor: page.after,
            end_cursor: next.clone(),
            returned: items.len() as u64,
            limit: page.limit,
            bytes: bytes as u64,
            max_bytes: page.max_bytes,
            omitted_before: api::Omission::None,
            omitted_after: if more {
                api::Omission::Known {
                    count: (metas.len() - end) as u64,
                    reason: if stop == api::StopReason::ByteLimit {
                        api::OmissionReason::Budget
                    } else {
                        api::OmissionReason::Limit
                    },
                }
            } else {
                api::Omission::None
            },
            unreadable: 0,
            stop_reason: stop,
            complete: !more,
        },
        items,
        next,
    })
}
