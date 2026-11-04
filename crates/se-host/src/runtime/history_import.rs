//! Explicit owner history migration over native read pins and the existing
//! bounded writer. A read transaction never survives native IO or an await.
mod batch;
mod chain;
mod commit;
mod default_profiles;
mod file;
mod node;
mod ownership;
mod plan;
mod project;
mod read;
mod rows;
mod source;
mod state;
use self::node::{NodeContext, NodeKind};
use super::{BlockingClass, ExecutionContext};
use crate::client::lease::Deadline;
use se_core::{
    ops::{
        AnyOutput, ImportNode, ImportReceipt,
        store_import::{ImportFamilyReceipt, ImportResume},
    },
    scope,
    store_error::store_error,
};
use se_store::*;
use se_types::{NativePath, Read, Result};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

async fn job<T: Send + 'static>(
    context: &ExecutionContext,
    deadline: &Deadline,
    work: impl FnOnce(&ExecutionContext) -> Result<T> + Send + 'static,
) -> Result<T> {
    let copy = context.clone();
    context
        .blocking
        .run(BlockingClass::Foreground, deadline, move || work(&copy))
        .await
}
fn now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| scope::unreadable("import observation clock", &e.to_string()))?
        .as_micros()
        .try_into()
        .map_err(|_| scope::unreadable("import observation clock", "timestamp overflow"))
}
fn id(
    source: &NativePath,
    scope: &Scope,
    source_owner: &se_types::HumanId,
    mappings: &std::collections::BTreeMap<se_types::HumanId, se_types::HumanId>,
) -> Result<RecordId> {
    let key = if mappings.is_empty() {
        serde_json::to_string(&(2u32, source, scope, source_owner))
    } else {
        serde_json::to_string(&(3u32, source, scope, source_owner, mappings))
    }
    .map_err(|e| scope::unreadable("import run identity", &e.to_string()))?;
    node::record_id("run", &key).map_err(|e| store_error(&e))
}
fn family(value: ImportFamily) -> Result<String> {
    let value = serde_json::to_value(value)
        .map_err(|e| scope::unreadable("import family", &e.to_string()))?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| scope::unreadable("import family", "closed family tag is absent"))
}
fn receipt(
    file: &plan::File,
    state: &str,
    counts: &ImportCounts,
    reason: Option<String>,
    deferred: u64,
) -> Result<ImportFamilyReceipt> {
    Ok(ImportFamilyReceipt {
        family: family(file.family)?,
        source: file.path.display().to_string(),
        state: state.into(),
        read: counts.read,
        imported: counts.imported,
        duplicate: counts.duplicate,
        unreadable: counts.unreadable,
        dropped_by_policy: counts.dropped_by_policy,
        deferred,
        reason,
    })
}
fn total(into: &mut ImportCounts, other: &ImportCounts) -> Result<()> {
    let add = |a: u64, b: u64| {
        a.checked_add(b)
            .ok_or_else(|| scope::unreadable("import total", "counter overflow"))
    };
    into.deferred = add(into.deferred, other.deferred)?;
    into.read = add(into.read, other.read)?;
    into.imported = add(into.imported, other.imported)?;
    into.duplicate = add(into.duplicate, other.duplicate)?;
    into.unreadable = add(into.unreadable, other.unreadable)?;
    into.dropped_by_policy = add(into.dropped_by_policy, other.dropped_by_policy)?;
    Ok(())
}
async fn ensure(context: &ExecutionContext, cx: NodeContext, deadline: &Deadline) -> Result<()> {
    let source = cx.source.path.clone().ok_or_else(|| {
        scope::unreadable(
            "Node import source",
            "a retained native file path is required",
        )
    })?;
    let batch = job(context, deadline, move |context| {
        state::start(context, &cx, source)
    })
    .await?;
    if let Some(batch) = batch {
        commit::append(context, batch, deadline).await?;
    }
    Ok(())
}
/// The owner operation's only entry. `Kernel::plan` already enforced the
/// owner-only surface; repeat its native/store generation checks on every job.
pub(super) async fn execute(
    context: ExecutionContext,
    input: ImportNode,
    mut admission: Admission,
    kernel: se_core::dispatch::Kernel,
    deadline: &Deadline,
) -> Result<AnyOutput> {
    if !matches!(admission.actor, Actor::Human(_)) || admission.session.is_some() {
        return Err(scope::unreadable(
            "history import",
            "owner admission is required",
        ));
    }
    admission.scope = Scope::Registry;
    let from = PathBuf::from(&input.from_node);
    let bound = deadline.clone();
    let Actor::Human(owner) = &admission.actor else {
        unreachable!()
    };
    let owner = owner.clone();
    let selected = input.source_owner.clone();
    let human_mappings = std::sync::Arc::new(input.mappings()?);
    let plan_mappings = human_mappings.clone();
    let plan = job(&context, deadline, move |_| {
        plan::inspect(&from, &owner, selected.as_ref(), &plan_mappings, &bound)
    })
    .await?;
    let root_path = NativePath::from_local(plan.root.clone())?;
    let root_id = id(
        &root_path,
        &Scope::Registry,
        &plan.source_owner,
        &human_mappings,
    )?;
    let source = plan.source.clone();
    let root_admission = admission.clone();
    let mut root = job(&context, deadline, move |context| {
        state::context(context, root_admission, root_id, source, now()?)
    })
    .await?;
    root.human_mappings = human_mappings.clone();
    ensure(&context, root.clone(), deadline).await?;
    let bindcx = root.clone();
    let bind_input = input.clone();
    let binding = job(&context, deadline, move |context| {
        read::snapshot(context, &bindcx.admission, |read| {
            se_core::ops::store_import::bind(
                &kernel,
                &bind_input,
                bindcx.import,
                bindcx.source.clone(),
                &se_core::commit::Cx {
                    read,
                    admission: &bindcx.admission,
                },
            )
        })
    })
    .await?;
    commit::append(&context, binding, deadline).await?;
    let registry = plan::File {
        path: plan.registry,
        family: ImportFamily::Projects,
        kind: NodeKind::Projects,
        observation: None,
        anchor: Some(plan.source.clone()),
    };
    let registry = file::file(&context, root.clone(), registry, deadline).await?;
    let mut complete = registry.receipt.unreadable == 0 && registry.receipt.deferred == 0;
    let mut counts = registry.counts;
    let mut families = vec![registry.receipt];
    let mut resume = registry.resume;
    if !complete || families[0].state != "present" {
        let finishcx = root.clone();
        if let Some(batch) = job(&context, deadline, move |context| {
            state::finish(context, &finishcx, counts, false)
        })
        .await?
        {
            commit::append(&context, batch, deadline).await?;
        }
        return Ok(ImportReceipt {
            import_id: se_types::hex_lower(root_id.as_bytes()),
            source: input.from_node,
            complete: false,
            originals_retained: true,
            families,
            resume,
        }
        .into());
    }
    let source_root = plan.root.clone();
    for project in plan.projects {
        let result = project::execute(
            &context,
            admission.clone(),
            project::Source {
                root_path: &root_path,
                source_root: &source_root,
                source_owner: &plan.source_owner,
                human_mappings: &human_mappings,
                registry: &plan.source,
            },
            project,
            deadline,
        )
        .await?;
        complete &= result.complete;
        total(&mut counts, &result.counts)?;
        families.extend(result.families);
        resume.extend(result.resume);
    }
    let finishcx = root.clone();
    let batch = job(&context, deadline, move |context| {
        state::finish(context, &finishcx, counts, complete)
    })
    .await?;
    if let Some(batch) = batch {
        commit::append(&context, batch, deadline).await?;
    }
    resume.sort_by(|a, b| {
        (
            &a.session,
            &a.agent,
            &a.provider,
            &a.native_reference,
            &a.state,
        )
            .cmp(&(
                &b.session,
                &b.agent,
                &b.provider,
                &b.native_reference,
                &b.state,
            ))
    });
    resume.dedup_by(|a, b| {
        a.session == b.session
            && a.agent == b.agent
            && a.provider == b.provider
            && a.native_reference == b.native_reference
            && a.state == b.state
    });
    Ok(ImportReceipt {
        import_id: se_types::hex_lower(root_id.as_bytes()),
        source: input.from_node,
        complete,
        originals_retained: true,
        families,
        resume,
    }
    .into())
}
