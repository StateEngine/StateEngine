//! Independent scheduling controls, overlaid unchanged on base and candidate.
use super::*;
use std::sync::mpsc;

#[test]
fn an_idle_edge_requires_a_full_quiet_interval() {
    let status = Status::default();
    let closed = AtomicBool::new(false);
    let edge = Instant::now();
    status.set_idle(true);
    assert!(!status.wait(&closed, None));
    let elapsed = edge.elapsed();
    eprintln!("first quiet edge: {elapsed:?}");
    assert!(
        elapsed >= Duration::from_millis(240),
        "maintenance admitted before quiet"
    );
}

#[test]
fn new_idle_edges_restart_quiet_even_with_retry_debt() {
    let status = Status::default();
    let closed = Arc::new(AtomicBool::new(false));
    status.set(Maint::Pending);
    status.set_idle(true);
    let worker_status = status.clone();
    let worker_closed = closed.clone();
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let shutdown = worker_status.wait(&worker_closed, Some(Duration::from_millis(40)));
        send.send((Instant::now(), shutdown)).unwrap();
    });
    let mut last_edge = Instant::now();
    let mut premature = None;
    for _ in 0..6 {
        std::thread::sleep(Duration::from_millis(55));
        status.set_idle(false);
        last_edge = Instant::now();
        status.set_idle(true);
        if premature.is_none() {
            premature = receive.try_recv().ok();
        }
    }
    let outcome = premature.or_else(|| receive.recv_timeout(Duration::from_secs(3)).ok());
    closed.store(true, Ordering::Release);
    status.wake();
    worker.join().unwrap();
    let (returned, shutdown) = outcome.expect("quiet waiter did not finish");
    assert!(!shutdown);
    assert!(
        premature.is_none(),
        "maintenance ran between short traffic gaps"
    );
    let elapsed = returned.saturating_duration_since(last_edge);
    eprintln!("last quiet edge with debt: {elapsed:?}");
    assert!(
        elapsed >= Duration::from_millis(240),
        "retry cap bypassed latest quiet edge"
    );
    assert!(
        status.pending(),
        "waiting silently cleared unpaid maintenance"
    );
}

#[test]
fn debt_retries_without_another_writer_edge() {
    let status = Status::default();
    status.set(Maint::Pending);
    let start = Instant::now();
    assert!(!status.wait(&AtomicBool::new(false), Some(Duration::from_millis(45))));
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(40));
    assert!(elapsed < Duration::from_secs(2));
    assert!(status.pending());
}

#[test]
fn shutdown_interrupts_indefinite_and_quiet_waits() {
    for quiet in [false, true] {
        let status = Status::default();
        let closed = Arc::new(AtomicBool::new(false));
        if quiet {
            status.set_idle(true);
        }
        let worker_status = status.clone();
        let worker_closed = closed.clone();
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(worker_status.wait(&worker_closed, None)).unwrap();
        });
        std::thread::sleep(Duration::from_millis(25));
        let start = Instant::now();
        closed.store(true, Ordering::Release);
        status.wake();
        let result = receive.recv_timeout(Duration::from_secs(2));
        worker.join().unwrap();
        assert!(
            result.unwrap(),
            "shutdown was consumed as ordinary maintenance"
        );
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "shutdown waited for quiet"
        );
    }
}

#[test]
fn consuming_an_edge_returns_to_an_indefinite_idle_wait() {
    let status = Status::default();
    let closed = Arc::new(AtomicBool::new(false));
    status.set_idle(true);
    assert!(!status.wait(&closed, None));
    let worker_status = status.clone();
    let worker_closed = closed.clone();
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        send.send(worker_status.wait(&worker_closed, None)).unwrap();
    });
    let repeated = receive.recv_timeout(Duration::from_millis(320)).ok();
    closed.store(true, Ordering::Release);
    status.wake();
    let shutdown = if repeated.is_some() {
        None
    } else {
        receive.recv_timeout(Duration::from_secs(2)).ok()
    };
    worker.join().unwrap();
    assert!(
        repeated.is_none(),
        "a consumed edge caused another maintenance wake"
    );
    assert_eq!(shutdown, Some(true));
}
