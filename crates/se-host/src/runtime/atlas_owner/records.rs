use super::*;
use crate::atlas_runtime::record_fence::RecordFeedScope;
use se_atlas::cache::connection::CacheConnection;
use se_core::admission::read_scope;
/// One authoritative record per chunk. The ticket predates the core snapshot;
/// only an exhausted, committed feed can certify this exact root and epoch.
pub(super) fn chunk(
    context: &ExecutionContext,
    owner: &HumanId,
    controller: &NativeController<NativeRenewal>,
    root: &RootId,
) -> Result<bool> {
    let Some(ticket) = context.atlas.records.ticket()? else {
        return Ok(false);
    };
    let admitted = admission(
        context,
        owner,
        Scope::Project(controller.summary(root)?.project),
    );
    let phase = executor::checked_pooled_phase(&context.reads, context.generation)?;
    let mut snapshot = phase
        .into_snapshot(read_scope(&admitted))
        .map_err(|e| store_error(&e))?;
    let result = controller.runtime().with_writer(
        root,
        Instant::now() + Duration::from_millis(100),
        |cache, source| {
            let after = cursor(cache)?;
            let feed = crate::atlas_records::next_feed(&mut snapshot, &admitted, after, source)?;
            let complete = match feed {
                Some(feed) => {
                    se_atlas::records::apply(
                        cache,
                        &feed,
                        Instant::now() + Duration::from_millis(100),
                    )?
                    .complete
                }
                None => true,
            };
            if complete {
                return context
                    .atlas
                    .records
                    .mark_current(RecordFeedScope::from(cache.identity()), ticket);
            }
            Ok(false)
        },
    );
    executor::close_read(result, snapshot.close())
}
fn cursor(cache: &CacheConnection<'_>) -> Result<Option<se_types::EventId>> {
    cache.read(Instant::now() + Duration::from_millis(100), |sql| {
        let after: Option<String> = sql
            .prepare("SELECT last_event FROM record_feed WHERE singleton=1")?
            .query_row([], |r| r.get(0))
            .map_err(|e| se_core::scope::unreadable("Atlas feed cursor", &e.to_string()))?;
        after.map(|id| id.parse()).transpose()
    })
}
