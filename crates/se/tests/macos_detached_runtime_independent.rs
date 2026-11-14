//! Independent public CLI startup, concurrent-owner and failed-startup controls.
#![cfg(target_os = "macos")]
#[path = "support/macos_detached_cli.rs"]
mod support;
use std::sync::{Arc, Barrier};
use support::*;

#[test]
fn detached_runtime_outlives_its_cli_and_concurrent_start_retains_one_birth() -> Check {
    let f = Fixture::new()?;
    let first = f.birth()?;
    let status = f.ok(&["status"])?;
    assert_eq!(status["runtime"]["state"], "running");
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(f.birth()?, first, "host did not survive starting CLI exit");
    f.down(&first)?;
    let barrier = Arc::new(Barrier::new(2));
    let outputs = std::thread::scope(|scope| {
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let gate = barrier.clone();
            let fixture = &f;
            tasks.push(scope.spawn(move || {
                gate.wait();
                fixture.call(&["up"]).map_err(|e| e.to_string())
            }));
        }
        tasks
            .into_iter()
            .map(|t| t.join().map_err(|_| "start thread panicked")?)
            .collect::<Result<Vec<_>, _>>()
    })
    .map_err(|e| e.to_string())?;
    let mut successes = Vec::new();
    for output in outputs {
        successes.push(successful(&output)?);
    }
    let current = f.birth()?;
    assert_eq!(
        successes[0]["process"], successes[1]["process"],
        "concurrent up returned different owners"
    );
    assert_eq!(successes[0]["generation"], successes[1]["generation"]);
    assert_eq!(f.birth()?, current);
    f.down(&current)
}

#[test]
fn a_child_bind_failure_retires_custody_and_allows_a_later_start() -> Check {
    let f = Fixture::new()?;
    f.down(&f.birth()?)?;
    let blocker = occupied_port()?;
    let selected = blocker.local_addr()?.port();
    port(&f, selected)?;
    let output = f.call(&["up"])?;
    assert!(
        !output.status.success(),
        "occupied native listener reported running"
    );
    let detail = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        detail.contains(&selected.to_string()),
        "native refusal omitted the failing port: {detail}"
    );
    assert!(
        detail.contains("listen") || detail.contains("bind"),
        "native child failure was not reported: {detail}"
    );
    f.absent()?;
    drop(blocker);
    let running = f.ok(&["up"])?;
    assert_eq!(running["state"], "running");
    let current = f.birth()?;
    f.down(&current)
}

fn occupied_port() -> Check<std::net::TcpListener> {
    let offset = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .subsec_nanos()
        % 10000;
    for attempt in 0..10000 {
        let port = 20000 + ((offset + attempt) % 10000) as u16;
        match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)) {
            Ok(listener) => return Ok(listener),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => (),
            Err(error) => return Err(error.into()),
        }
    }
    Err("supported listener range has no available fixture port".into())
}
