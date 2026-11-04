//! One project owns its import run, dependency replay and final removal.
use super::*;
pub(super) struct ProjectResult {
    pub complete: bool,
    pub counts: ImportCounts,
    pub families: Vec<ImportFamilyReceipt>,
    pub resume: Vec<ImportResume>,
}
pub(super) struct Source<'a> {
    pub root_path: &'a NativePath,
    pub source_root: &'a std::path::Path,
    pub source_owner: &'a se_types::HumanId,
    pub human_mappings:
        &'a std::sync::Arc<std::collections::BTreeMap<se_types::HumanId, se_types::HumanId>>,
    pub human_names: &'a human_plan::Names,
    pub registry: &'a SourceEvidence,
}
pub(super) async fn execute(
    context: &ExecutionContext,
    mut admission: Admission,
    source: Source<'_>,
    project: plan::Project,
    deadline: &Deadline,
) -> Result<ProjectResult> {
    let Source {
        root_path,
        source_root,
        source_owner,
        human_mappings,
        human_names,
        registry: registry_source,
    } = source;
    let mut families = Vec::new();
    let mut resume = Vec::new();
    let root = source_root.to_path_buf();
    let source_id = project.id.clone();
    let bound = deadline.clone();
    let files = job(context, deadline, move |_| {
        plan::sources(&root, &source_id, &bound)
    })
    .await?;
    admission.scope = Scope::Project(project.id);
    let project_id = id(root_path, &admission.scope, source_owner)?;
    let own = admission.clone();
    let source = registry_source.clone();
    let mut cx = job(context, deadline, move |context| {
        state::context(context, own, project_id, source, now()?)
    })
    .await?;
    cx.human_mappings = human_mappings.clone();
    cx.human_names = human_names.clone();
    ensure(context, cx.clone(), deadline).await?;
    let ownercx = cx.clone();
    if let Some(batch) = job(context, deadline, move |context| {
        state::owner_project(context, &ownercx)
    })
    .await?
    {
        commit::append(context, batch, deadline).await?;
    }
    let mut project_counts = ImportCounts::default();
    let mut project_complete = true;
    let mut results = Vec::new();
    for source in &files {
        let mut sourcecx = cx.clone();
        sourcecx.prerequisites_pending = results
            .iter()
            .any(|r: &file::FileResult| r.receipt.deferred > 0);
        results.push(file::file(context, sourcecx, source.clone(), deadline).await?);
    }
    loop {
        let before = results.iter().map(|r| r.receipt.deferred).sum::<u64>();
        if before == 0 {
            break;
        }
        for (index, source) in files.iter().enumerate() {
            if results[index].receipt.deferred == 0 {
                continue;
            }
            let mut sourcecx = cx.clone();
            sourcecx.prerequisites_pending = files
                .iter()
                .zip(results.iter())
                .any(|(f, r)| matches!(f.kind, NodeKind::Ledger) && r.receipt.deferred > 0);
            let mut result = file::file(context, sourcecx, source.clone(), deadline).await?;
            result.resume.append(&mut results[index].resume);
            results[index] = result;
        }
        if results.iter().map(|r| r.receipt.deferred).sum::<u64>() >= before {
            break;
        }
    }
    for result in results {
        project_complete &= matches!(result.receipt.state.as_str(), "present" | "absent")
            && result.receipt.unreadable == 0
            && result.receipt.deferred == 0;
        total(&mut project_counts, &result.counts)?;
        families.push(result.receipt);
        resume.extend(result.resume);
    }
    // Source configuration wins; only absent imported profiles adopt defaults now.
    default_profiles::ensure(context, &cx, deadline).await?;
    // Final removal is sequenced after all historical data, using its
    // current registration and the ordinary no-live-custody checks.
    if project.tombstone && project_complete {
        let removedcx = cx.clone();
        if let Some(batch) = job(context, deadline, move |context| {
            state::tombstone(context, &removedcx)
        })
        .await?
        {
            commit::append(context, batch, deadline).await?;
        }
    }
    let resumecx = cx.clone();
    resume.extend(
        job(context, deadline, move |context| {
            state::resume(context, &resumecx)
        })
        .await?,
    );
    let finishcx = cx.clone();
    let finishcounts = project_counts.clone();
    let batch = job(context, deadline, move |context| {
        state::finish(context, &finishcx, finishcounts, project_complete)
    })
    .await?;
    if let Some(batch) = batch {
        commit::append(context, batch, deadline).await?;
    }
    Ok(ProjectResult {
        complete: project_complete,
        counts: project_counts,
        families,
        resume,
    })
}
