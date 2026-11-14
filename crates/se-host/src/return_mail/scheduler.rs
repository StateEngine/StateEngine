//! Keyset pages give every retained contact a turn without resident route tasks.
use super::*;
use std::time::Duration;
use tokio::task::JoinSet;

enum Job {
    Recover(PendingContact),
    Exchange(Route),
}

impl RemoteBroker {
    pub(super) async fn courier(
        self: Arc<Self>,
        context: ExecutionContext,
        source: VerifiedSourceSession,
        status: Arc<Mutex<Option<se_types::ErrorBody>>>,
    ) -> Result<()> {
        let mut route_cursor = None;
        let mut pending_cursor = 0;
        let mut scan_failure = None;
        let mut routes_done = false;
        let mut pending_done = false;
        loop {
            if self.check_open().is_err() || source.context().check_current().is_err() {
                return Ok(());
            }
            let address = source.source().address();
            let after = route_cursor.clone();
            let pages = background_read(&context, move |p| {
                Ok((
                    if routes_done {
                        (Vec::new(), false)
                    } else {
                        p.remote_mail_catalog(&address, after.as_ref(), 20)?
                    },
                    if pending_done {
                        (Vec::new(), false)
                    } else {
                        p.remote_pending_contact_page(&address, pending_cursor, 20)?
                    },
                ))
            })
            .await;
            let ((routes, more_routes), (pending, more_pending)) = match pages {
                Ok(pages) => pages,
                Err(error) => {
                    *status.lock().map_err(|_| poisoned())? = Some(error.into_body());
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            routes_done = !more_routes;
            pending_done = !more_pending;
            route_cursor = if more_routes {
                routes.last().cloned()
            } else {
                None
            };
            pending_cursor = if more_pending {
                pending.last().map_or(0, |(_, seq)| *seq)
            } else {
                0
            };
            let mut routes = routes.into_iter();
            let mut pending = pending.into_iter();
            let mut jobs = Vec::with_capacity(40);
            // Interleave recovery and delivery so neither stream can starve the other.
            loop {
                let next_pending = pending.next();
                let next_route = routes.next();
                if next_pending.is_none() && next_route.is_none() {
                    break;
                }
                if let Some((contact, _)) = next_pending {
                    jobs.push(Job::Recover(contact));
                }
                if let Some(route) = next_route {
                    jobs.push(Job::Exchange(route));
                }
            }
            if let Some(body) = self.run_mail_jobs(&context, &source, jobs).await? {
                *status.lock().map_err(|_| poisoned())? = Some(body.clone());
                if scan_failure.is_none() {
                    scan_failure = Some(body);
                }
            }
            if !more_routes && !more_pending {
                *status.lock().map_err(|_| poisoned())? = scan_failure.take();
                routes_done = false;
                pending_done = false;
            }
            tokio::time::sleep(if more_routes || more_pending {
                Duration::from_millis(25)
            } else {
                Duration::from_secs(2)
            })
            .await;
        }
    }
}

impl RemoteBroker {
    async fn run_mail_jobs(
        self: &Arc<Self>,
        context: &ExecutionContext,
        source: &VerifiedSourceSession,
        jobs: Vec<Job>,
    ) -> Result<Option<se_types::ErrorBody>> {
        let mut failure = None;
        let mut queued = jobs.into_iter();
        let mut running = JoinSet::new();
        loop {
            while running.len() < 4 {
                let Some(job) = queued.next() else { break };
                let broker = self.clone();
                let context = context.clone();
                let source = source.clone();
                running.spawn(async move {
                        tokio::time::timeout(Duration::from_secs(10), async {
                            source.context().check_current()?;
                            match job {
                                Job::Recover(contact) => broker.recover_contact(&context, &source, contact).await,
                                Job::Exchange(route) => broker.mail_cycle(&context, &source, &route).await,
                            }
                        }).await.unwrap_or_else(|_| Err(refused(
                            "return-mail contact timed out; saved messages and original send keys remain available for retry",
                        )))
                    });
            }
            let Some(result) = running.join_next().await else {
                break;
            };
            let error = match result {
                Ok(result) => result.err(),
                Err(_) => Some(refused(
                    "return-mail contact task ended without a completion witness; saved mail remains pending",
                )),
            };
            if let Some(error) = error {
                let body = error.into_body();
                if failure.is_none() {
                    failure = Some(body);
                }
            }
            if source.context().check_current().is_err() {
                return Ok(failure);
            }
        }
        Ok(failure)
    }
}
