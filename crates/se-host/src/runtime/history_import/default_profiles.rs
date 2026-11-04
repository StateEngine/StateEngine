//! Current-owner defaults repair profile-less historical registrations only.
use super::*;
use se_types::PageRequest;

pub(super) async fn ensure(
    context: &ExecutionContext,
    cx: &NodeContext,
    deadline: &Deadline,
) -> Result<()> {
    let mut after = None;
    for _ in 0..64 {
        let readcx = cx.clone();
        let (next, complete, batches) = job(context, deadline, move |context| {
            read::snapshot(context, &readcx.admission, |read| {
                let page = read
                    .principals(ReadBudget {
                        page: PageRequest {
                            after,
                            limit: std::num::NonZeroU32::new(100)
                                .ok_or_else(|| scope::unreadable("import agents", "zero limit"))?,
                            max_bytes: std::num::NonZeroU32::new(1024 * 1024)
                                .ok_or_else(|| scope::unreadable("import agents", "zero bytes"))?,
                        },
                        deadline: std::time::Duration::from_millis(250),
                    })
                    .map_err(|e| store_error(&e))?;
                let mut batches = Vec::new();
                for principal in page.items() {
                    let original = principal.original.as_deref().unwrap_or(&principal.current);
                    let EventBody::PrincipalRegistered {
                        principal: Actor::Agent(agent),
                        ..
                    } = &original.body
                    else {
                        continue;
                    };
                    if original.header.door != Door::Import {
                        continue;
                    }
                    match read.profile(agent.clone()).map_err(|e| store_error(&e))? {
                        Read::Present { .. } => continue,
                        Read::Absent { .. } => (),
                        Read::Unreadable { source, reason, .. } => {
                            return Err(scope::unreadable(&source, &reason));
                        }
                        Read::Unknown { what } => {
                            return Err(scope::unreadable("imported agent profile", &what));
                        }
                    }
                    let profile =
                        node::profile::safe_default(&readcx, None).map_err(|e| store_error(&e))?;
                    let mut event = batch::event(
                        &readcx,
                        &format!("owner-default-profile:{agent}"),
                        EventBody::ProfileSaved {
                            agent: agent.clone(),
                            profile,
                            expected: Expected::Absent,
                        },
                    )?;
                    event.header.cause = Some(original.header.event.clone());
                    batches.push(batch::atomic(&readcx, vec![event], None));
                }
                Ok((page.next().cloned(), page.window().complete(), batches))
            })
        })
        .await?;
        for batch in batches {
            commit::append(context, batch, deadline).await?;
        }
        if next.is_none() {
            return if complete {
                Ok(())
            } else {
                Err(scope::unreadable(
                    "imported agent profiles",
                    "principal inventory is incomplete",
                ))
            };
        }
        after = next;
    }
    Err(scope::unreadable(
        "imported agent profiles",
        "principal inventory exceeds its finite 6400-record bound",
    ))
}
