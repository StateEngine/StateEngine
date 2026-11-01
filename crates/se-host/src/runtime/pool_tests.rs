use super::{BlockingClass, BlockingPool};
use crate::client::{ClientOptions, lease::Deadline};
use std::sync::{Arc, atomic::AtomicBool, mpsc};
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinHandle};
type Check = Result<(), Box<dyn std::error::Error>>;
struct Job {
    entered: oneshot::Receiver<()>,
    release: mpsc::Sender<()>,
    task: JoinHandle<se_types::Result<()>>,
}
fn deadline(duration: Duration) -> se_types::Result<Deadline> {
    Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: duration,
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}
fn launch(pool: BlockingPool, class: BlockingClass, duration: Duration) -> se_types::Result<Job> {
    let bound = deadline(duration)?;
    let (entered, started) = oneshot::channel();
    let (release, wait) = mpsc::channel();
    let task = tokio::spawn(async move {
        pool.run(class, &bound, move || {
            let _ = entered.send(());
            wait.recv_timeout(Duration::from_secs(8))
                .map_err(|error| se_core::scope::unreadable("test release", &error.to_string()))
        })
        .await
    });
    Ok(Job {
        entered: started,
        release,
        task,
    })
}
async fn entered(job: &mut Job) -> Check {
    tokio::time::timeout(Duration::from_secs(3), &mut job.entered).await??;
    Ok(())
}
async fn blocked(job: &mut Job) -> Check {
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut job.entered)
            .await
            .is_err(),
        "job entered while its bounded slot was occupied"
    );
    Ok(())
}
fn runtime(capacity: u32) -> Result<tokio::runtime::Runtime, std::io::Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(capacity as usize)
        .build()
}
fn configured(rt: &tokio::runtime::Runtime, capacity: u32) -> se_types::Result<BlockingPool> {
    let capacity = std::num::NonZeroU32::new(capacity)
        .ok_or_else(|| se_types::SeError::invalid("test pool capacity", "nonzero"))?;
    BlockingPool::with_jobs(rt.handle().clone(), capacity)
}
#[test]
fn shared_jobs_and_one_maintenance_respect_configured_capacity() -> Check {
    for capacity in [2, 4, 8] {
        let rt = runtime(capacity)?;
        rt.block_on(async {
            let pool = configured(&rt, capacity)?;
            let mut jobs = Vec::new();
            for _ in 0..capacity {
                jobs.push(launch(
                    pool.clone(),
                    BlockingClass::Foreground,
                    Duration::from_secs(5),
                )?);
            }
            for job in &mut jobs {
                entered(job).await?;
            }
            let mut overflow = launch(
                pool.clone(),
                BlockingClass::Foreground,
                Duration::from_secs(5),
            )?;
            blocked(&mut overflow).await?;
            jobs[0].release.send(())?;
            entered(&mut overflow).await?;
            for job in &jobs[1..] {
                job.release.send(())?;
            }
            overflow.release.send(())?;
            for job in jobs {
                job.task.await??;
            }
            overflow.task.await??;
            let mut maintenance = launch(
                pool.clone(),
                BlockingClass::Background,
                Duration::from_secs(5),
            )?;
            entered(&mut maintenance).await?;
            let mut queued = launch(
                pool.clone(),
                BlockingClass::Background,
                Duration::from_secs(5),
            )?;
            blocked(&mut queued).await?;
            let mut foreground = launch(
                pool.clone(),
                BlockingClass::Foreground,
                Duration::from_secs(5),
            )?;
            entered(&mut foreground).await?;
            foreground.release.send(())?;
            foreground.task.await??;
            blocked(&mut queued).await?;
            maintenance.release.send(())?;
            entered(&mut queued).await?;
            queued.release.send(())?;
            maintenance.task.await??;
            queued.task.await??;
            pool.quiesce(&deadline(Duration::from_secs(3))?).await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}
#[test]
fn expired_waiter_keeps_its_slot_and_shutdown_joins_full_configured_capacity() -> Check {
    for capacity in [2, 4, 8] {
        let rt = runtime(capacity)?;
        rt.block_on(async {
            let pool = configured(&rt, capacity)?;
            let mut expired = launch(
                pool.clone(),
                BlockingClass::Foreground,
                Duration::from_millis(80),
            )?;
            let mut held = Vec::new();
            for _ in 1..capacity {
                held.push(launch(
                    pool.clone(),
                    BlockingClass::Foreground,
                    Duration::from_secs(5),
                )?);
            }
            entered(&mut expired).await?;
            for job in &mut held {
                entered(job).await?;
            }
            assert!(expired.task.await?.is_err());
            let mut maintenance = launch(
                pool.clone(),
                BlockingClass::Background,
                Duration::from_secs(5),
            )?;
            blocked(&mut maintenance).await?;
            let shutdown_pool = pool.clone();
            let mut shutdown = tokio::spawn(async move {
                shutdown_pool
                    .quiesce(&deadline(Duration::from_secs(5))?)
                    .await
            });
            assert!(
                tokio::time::timeout(Duration::from_millis(30), &mut shutdown)
                    .await
                    .is_err()
            );
            expired.release.send(())?;
            entered(&mut maintenance).await?;
            // Even with every other slot free, actual maintenance custody keeps
            // the complete configured pool from being declared quiescent.
            for job in &held {
                job.release.send(())?;
            }
            for job in held {
                job.task.await??;
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(30), &mut shutdown)
                    .await
                    .is_err()
            );
            maintenance.release.send(())?;
            maintenance.task.await??;
            shutdown.await??;
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}
#[test]
fn invalid_configured_capacity_refuses() -> Check {
    let rt = runtime(2)?;
    for capacity in [1, 9, u32::MAX] {
        assert!(configured(&rt, capacity).is_err());
    }
    Ok(())
}
