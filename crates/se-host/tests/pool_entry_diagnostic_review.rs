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
                // This current-thread executor has not polled the new task.
                // Exhaust its admission budget without creating OS pressure.
                std::thread::sleep(Duration::from_millis(120));
                let diagnostic = entered(&mut job)
                    .await
                    .expect_err("expired job unexpectedly entered")
                    .to_string();
                let actual = job.task.await?.expect_err("expired job succeeded");
                let receipt = serde_json::json!({
                    "diagnostic": diagnostic,
                    "actual_code": format!("{:?}", actual.code()),
                    "actual_error": actual.to_string(),
                    "task_panicked": false,
                });
                let output = std::path::Path::new("target/judge-diagnostics/pool-entry");
                std::fs::create_dir_all(output)?;
                std::fs::write(output.join("expired-before-first-poll.json"),
                    serde_json::to_vec_pretty(&receipt)?)?;
                assert_eq!(actual.code(), se_types::Code::DeadlineExceeded);
                assert!(
                    !diagnostic.contains("worker-thread spawn refused"),
                    "diagnostic invents an OS thread failure for ordinary admission expiry: {receipt}"
                );
                Ok(())
            })
        }
    }
}
