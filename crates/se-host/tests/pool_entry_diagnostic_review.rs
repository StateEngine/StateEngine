//! Independent delayed-admission control for the test entry diagnostic.
#![cfg(feature = "runtime")]
pub use se_host::client;
#[path = "../src/runtime/pool.rs"]
#[allow(dead_code)]
mod actual_pool;
mod probe {
    use super::actual_pool::{BlockingClass, BlockingPool};
    #[allow(dead_code)]
    mod actual_helper {
        include!("../src/runtime/pool_tests.rs");

        #[test]
        fn expired_before_first_poll_does_not_claim_os_spawn_failure() -> Check {
            let rt = runtime(2)?;
            rt.block_on(async {
                let pool = configured(&rt, 2)?;
                let mut job = launch(
                    pool,
                    BlockingClass::Foreground,
                    Duration::from_millis(80),
                )?;
                // Observe the original result without polling a completed join
                // again when the helper itself joins the task on failure.
                let original = job.task;
                let (witness, observed) = oneshot::channel();
                job.task = tokio::spawn(async move {
                    let result = original.await.expect("pool task panicked or was cancelled");
                    let _ = witness.send(result.as_ref().err().map(|error| {
                        (error.code(), error.to_string())
                    }));
                    result
                });
                // This current-thread executor has not polled the new task.
                // Exhaust its admission budget without creating OS pressure.
                std::thread::sleep(Duration::from_millis(120));
                let diagnostic = entered(&mut job)
                    .await
                    .expect_err("expired job unexpectedly entered")
                    .to_string();
                let (actual_code, actual_error) = tokio::time::timeout(
                    Duration::from_secs(3), observed,
                ).await??.expect("expired job succeeded");
                let receipt = serde_json::json!({
                    "diagnostic": diagnostic,
                    "actual_code": format!("{actual_code:?}"),
                    "actual_error": actual_error,
                    "task_panicked": false,
                });
                let output = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../target/judge-diagnostics/pool-entry");
                std::fs::create_dir_all(&output)?;
                std::fs::write(output.join("expired-before-first-poll.json"),
                    serde_json::to_vec_pretty(&receipt)?)?;
                assert_eq!(actual_code, se_types::Code::DeadlineExceeded);
                assert!(diagnostic.contains(&actual_error),
                    "diagnostic omits the observed pool error: {receipt}");
                assert!(
                    !diagnostic.contains("worker-thread spawn refused"),
                    "diagnostic invents an OS thread failure for ordinary admission expiry: {receipt}"
                );
                Ok(())
            })
        }
    }
}
