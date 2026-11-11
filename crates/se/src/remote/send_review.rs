//! The CLI must flush provisional facts before dispatch and retain later refusal.
use super::*;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Default)]
struct Observed(Rc<RefCell<(Vec<u8>, usize)>>);
impl Write for Observed {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().1 += 1;
        Ok(())
    }
}
impl Observed {
    fn rows(&self) -> io::Result<Vec<serde_json::Value>> {
        self.0
            .borrow()
            .0
            .split(|b| *b == b'\n')
            .filter(|v| !v.is_empty())
            .map(|v| serde_json::from_slice(v).map_err(io::Error::other))
            .collect()
    }
}
fn input() -> io::Result<RemoteSendCall> {
    serde_json::from_value(serde_json::json!({
        "host":"example", "request":{
            "target":{"project":"prj_01920e00-7f00-7000-8000-000000000000",
                "agent":"ag_01920e00-7f00-7000-8000-000000000000"},
            "session":"ses_01920e00-7f00-7000-8000-000000000000",
            "idempotency_key":"synthetic-review-key", "body":"private synthetic body"}
    }))
    .map_err(io::Error::other)
}
fn preparation(input: &RemoteSendCall) -> io::Result<RemoteSendPreparation> {
    Ok(RemoteSendPreparation {
        host: se_types::remote::RemoteHostId(se_types::Sha256::from_bytes([3; 32])),
        grant: "rgr_01920e00-7f00-7000-8000-000000000000"
            .parse()
            .map_err(io::Error::other)?,
        target: input.request.target.clone(),
        session: input.request.session.clone(),
        idempotency_key: input.request.idempotency_key.clone(),
        body_bytes: u32::try_from(input.request.body.len()).map_err(io::Error::other)?,
    })
}
fn bootstrap() -> Bootstrap {
    Bootstrap {
        home: std::path::PathBuf::new(),
        cwd: std::path::PathBuf::new(),
        project: None,
        selections: Default::default(),
        config: crate::config::Loaded {
            value: Default::default(),
            origin: crate::config::Origin::BuiltIn,
        },
        session: None,
        log: None,
        no_color: true,
        json: true,
        retry_invocation: None,
        legacy_environment_present: false,
    }
}

#[test]
fn pending_and_bound_facts_are_flushed_before_their_dispatches() -> io::Result<()> {
    let input = input()?;
    let prepared = preparation(&input)?;
    let mut stderr = Observed::default();
    let observer = stderr.clone();
    let mut stdout = Vec::new();
    let mut calls = 0;
    let code = run(
        &bootstrap(),
        AnyOp::RemoteSend(input.clone()),
        true,
        false,
        &mut stdout,
        &mut stderr,
        &mut |_, operation, _| {
            calls += 1;
            let rows = observer
                .rows()
                .map_err(|cause| SeError::invalid("review status JSON", &cause.to_string()))?;
            assert_eq!(rows.len(), calls);
            assert_eq!(observer.0.borrow().1, calls);
            assert_eq!(rows[0]["status"], "local_pending");
            assert_eq!(rows[0]["idempotency_key"], "synthetic-review-key");
            assert!(rows[0].get("host").is_none());
            assert!(rows[0].get("grant").is_none());
            assert!(rows[0].get("body").is_none());
            match operation {
                AnyOp::RemotePrepareSend(v) => {
                    assert_eq!(v.host, input.host);
                    assert_eq!(v.request.body, input.request.body);
                    Ok(prepared.clone().into())
                }
                AnyOp::RemoteSend(v) => {
                    assert_eq!(rows[1]["status"], "binding_ready");
                    assert_eq!(rows[1]["grant"], prepared.grant.to_string());
                    let binding = v.expected_binding.as_ref();
                    assert_eq!(binding.map(|binding| binding.host), Some(prepared.host));
                    assert_eq!(binding.map(|binding| &binding.grant), Some(&prepared.grant));
                    assert_eq!(v.request.idempotency_key, input.request.idempotency_key);
                    assert_eq!(v.request.body, input.request.body);
                    Err(SeError::invalid(
                        "synthetic final refusal",
                        "retry the same binding",
                    ))
                }
                _ => panic!("unexpected operation"),
            }
        },
    )?;
    assert_eq!((code, calls), (1, 2));
    assert!(stdout.is_empty());
    let rows = stderr.rows()?;
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[2]["status"], "failed");
    assert_eq!(rows[2]["idempotency_key"], rows[0]["idempotency_key"]);
    assert_eq!(rows[2]["binding"]["host"], rows[1]["host"]);
    assert_eq!(rows[2]["binding"]["grant"], rows[1]["grant"]);
    assert!(!String::from_utf8_lossy(&stderr.0.borrow().0).contains("private synthetic body"));
    Ok(())
}

#[test]
fn preparation_mismatch_never_dispatches_a_mutating_send() -> io::Result<()> {
    for mismatch in 0..6 {
        let mut input = input()?;
        let mut p = preparation(&input)?;
        match mismatch {
            0 => {
                p.idempotency_key = "different-synthetic-key"
                    .parse()
                    .map_err(io::Error::other)?
            }
            1 => {
                p.target.agent = "ag_01920e00-7f00-7000-8000-000000000001"
                    .parse()
                    .map_err(io::Error::other)?
            }
            2 => {
                p.session = "ses_01920e00-7f00-7000-8000-000000000001"
                    .parse()
                    .map_err(io::Error::other)?
            }
            3 => p.body_bytes += 1,
            4 | 5 => {
                input.expected_binding = Some(Box::new(RemoteBindingSelection {
                    host: if mismatch == 4 {
                        se_types::remote::RemoteHostId(se_types::Sha256::from_bytes([4; 32]))
                    } else {
                        p.host
                    },
                    grant: if mismatch == 5 {
                        "rgr_01920e00-7f00-7000-8000-000000000001"
                            .parse()
                            .map_err(io::Error::other)?
                    } else {
                        p.grant.clone()
                    },
                }));
            }
            _ => panic!("unexpected synthetic mismatch case"),
        }
        let mut calls = 0;
        let mut stderr = Observed::default();
        let mut stdout = Vec::new();
        let code = run(
            &bootstrap(),
            AnyOp::RemoteSend(input),
            true,
            false,
            &mut stdout,
            &mut stderr,
            &mut |_, op, _| {
                calls += 1;
                assert!(matches!(op, AnyOp::RemotePrepareSend(_)));
                Ok(p.clone().into())
            },
        )?;
        assert_eq!((code, calls), (1, 1));
        assert!(stdout.is_empty());
        let rows = stderr.rows()?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["status"], "failed");
        assert_eq!(rows[1]["idempotency_key"], rows[0]["idempotency_key"]);
    }
    Ok(())
}

#[test]
fn unflushed_status_never_allows_the_next_dispatch() -> io::Result<()> {
    struct FailFlush {
        flushes: usize,
        fail_at: usize,
    }
    impl Write for FailFlush {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.flushes == self.fail_at {
                Err(io::Error::other("synthetic flush failure"))
            } else {
                Ok(())
            }
        }
    }
    for fail_at in 1..=2 {
        let input = input()?;
        let p = preparation(&input)?;
        let mut calls = 0;
        let result = run(
            &bootstrap(),
            AnyOp::RemoteSend(input),
            true,
            false,
            &mut Vec::new(),
            &mut FailFlush {
                flushes: 0,
                fail_at,
            },
            &mut |_, op, _| {
                calls += 1;
                assert!(matches!(op, AnyOp::RemotePrepareSend(_)));
                Ok(p.clone().into())
            },
        );
        assert!(result.is_err());
        assert_eq!(calls, fail_at - 1);
    }
    Ok(())
}
