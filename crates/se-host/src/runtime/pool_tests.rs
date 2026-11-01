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
fn runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
}
#[test]
fn two_shared_jobs_and_only_one_maintenance_job() -> Check {
    let rt = runtime()?;
    rt.block_on(async {
        let pool = BlockingPool::new(rt.handle().clone());
        let mut first = launch(
            pool.clone(),
            BlockingClass::Foreground,
            Duration::from_secs(5),
        )?;
        let mut second = launch(
            pool.clone(),
            BlockingClass::Foreground,
            Duration::from_secs(5),
        )?;
        entered(&mut first).await?;
        entered(&mut second).await?;
        let mut third = launch(
            pool.clone(),
            BlockingClass::Foreground,
            Duration::from_secs(5),
        )?;
        blocked(&mut third).await?;
        first.release.send(())?;
        entered(&mut third).await?;
        second.release.send(())?;
        third.release.send(())?;
        first.task.await??;
        second.task.await??;
        third.task.await??;
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
        Ok(())
    })
}
#[test]
fn expired_waiter_keeps_its_slot_and_shutdown_joins_queued_maintenance() -> Check {
    let rt = runtime()?;
    rt.block_on(async {
        let pool = BlockingPool::new(rt.handle().clone());
        let mut expired = launch(
            pool.clone(),
            BlockingClass::Foreground,
            Duration::from_millis(80),
        )?;
        let mut held = launch(
            pool.clone(),
            BlockingClass::Foreground,
            Duration::from_secs(5),
        )?;
        entered(&mut expired).await?;
        entered(&mut held).await?;
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
        // Releasing one foreground slot is insufficient while the other job and
        // the already queued maintenance job still own actual native work.
        held.release.send(())?;
        held.task.await??;
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut shutdown)
                .await
                .is_err()
        );
        maintenance.release.send(())?;
        maintenance.task.await??;
        shutdown.await??;
        Ok(())
    })
}
