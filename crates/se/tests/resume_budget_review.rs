//! Independent default-resume checks through the installed CLI and MCP stdio.
//! Sessions and captured turns are native-store fixtures, not provider executions.
#![cfg(target_os = "linux")]
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "The shared capture fixture also serves activation consumers."
)]
mod capture;
#[path = "../../test-support/directory.rs"]
mod directory;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_store::*;
use se_types::{Read, Secret, SessionId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Consumer {
    root: directory::PrivateDirectory,
    home: PathBuf,
    project: String,
    agent: String,
    session: SessionId,
    messages: Vec<String>,
    working: String,
    mail: String,
    calls: usize,
    provider: Provider,
}
impl Consumer {
    fn raw_command(&self, session: bool) -> TestResult<Command> {
        let mut c = Command::new(env!("CARGO_BIN_EXE_se"));
        c.env_clear()
            .env("PATH", std::env::var_os("PATH").ok_or("PATH absent")?)
            .env("HOME", self.root.join("owner"))
            .env("USERPROFILE", self.root.join("owner"))
            .env("XDG_RUNTIME_DIR", self.root.join("runtime"))
            .current_dir(&*self.root);
        if session {
            c.env("SE_SESSION", self.session.as_str());
        }
        Ok(c)
    }
    fn command(&self, session: bool) -> TestResult<Command> {
        let mut c = self.raw_command(session)?;
        c.arg("--home").arg(&self.home);
        Ok(c)
    }
    fn json(&self, words: &[&str], session: bool) -> TestResult<(Value, Vec<u8>)> {
        let out = self.command(session)?.arg("--json").args(words).output()?;
        assert!(
            matches!(out.status.code(), Some(0 | 2)),
            "CLI refusal: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok((serde_json::from_slice(&out.stdout)?, out.stdout))
    }
    fn mcp(&self, args: Value) -> TestResult<(Value, usize)> {
        let request = json!({"jsonrpc":"2.0","id":"review-λ-\"-\\","method":"tools/call",
            "params":{"name":"stateengine_resume","arguments":args}});
        let mut child = self
            .command(true)?
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        writeln!(child.stdin.take().ok_or("stdin")?, "{request}")?;
        let out = child.wait_with_output()?;
        assert!(
            out.status.success(),
            "MCP transport: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let reply: Value = serde_json::from_slice(&out.stdout)?;
        assert_eq!(reply["id"], request["id"]);
        assert_ne!(reply["result"]["isError"], true, "{reply}");
        let body = serde_json::from_str(
            reply["result"]["content"][0]["text"]
                .as_str()
                .ok_or("MCP text")?,
        )?;
        Ok((body, out.stdout.len()))
    }
    fn record(&mut self, door: &str, body: &Value, bytes: usize) -> TestResult {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/judge-diagnostics/resume-budget-review");
        fs::create_dir_all(&parent)?;
        let label = format!("{}-{}-{door}-{}", self.agent, self.session, self.calls);
        self.calls += 1;
        fs::write(
            parent.join(format!("{label}.json")),
            serde_json::to_vec_pretty(
                &json!({"bytes":bytes,"body":body,"provider":format!("{:?}", self.provider),"saved_notes":!self.working.is_empty()}),
            )?,
        )?;
        Ok(())
    }
    fn check(&self, body: &Value, since: Option<&Value>) -> TestResult {
        assert_eq!(body["principal"]["agent"]["id"], self.agent);
        assert_eq!(body["principal"]["project"]["id"], self.project);
        assert_eq!(body["principal"]["session_id"], self.session.as_str());
        assert_eq!(body["complete"], false);
        assert_eq!(body["resume_status"], "needs_read");
        if self.working.is_empty() {
            assert_eq!(body["working_state"]["state"], "absent");
        } else {
            let state = &body["working_state"]["value"];
            assert_eq!(state["bytes"].as_u64(), Some(self.working.len() as u64));
            assert!(
                state["text"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && self.working.starts_with(s)),
                "lost saved work: {body}"
            );
        }
        let turns = body["recent_turns"].as_array().ok_or("turns")?;
        let omitted_turns: u64 = body["omissions"]
            .as_array()
            .ok_or("omissions")?
            .iter()
            .filter(|o| o["section"] == "recent_turns")
            .map(|o| o["count"].as_u64().ok_or("turn count"))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .sum();
        assert_eq!(
            turns.len() as u64 + omitted_turns,
            if since.is_some() { 0 } else { 8 }
        );
        let rows = body["unread"]["items"].as_array().ok_or("unread rows")?;
        assert!(!rows.is_empty(), "lost first unread: {body}");
        for row in rows {
            assert!(
                self.messages
                    .contains(&row["id"].as_str().ok_or("mail id")?.to_owned())
            );
            assert_eq!(row["body"]["bytes"].as_u64(), Some(self.mail.len() as u64));
            let preview = row["body"]["text"].as_str().ok_or("mail text")?;
            assert!(self.mail.starts_with(preview));
            if preview.len() < self.mail.len() {
                assert_eq!(row["body"]["complete"], false);
            }
            assert!(
                body["required_reads"]
                    .as_array()
                    .ok_or("reads")?
                    .iter()
                    .any(|r| r["id"] == row["id"])
            );
        }
        assert!(
            body["omissions"]
                .as_array()
                .ok_or("omissions")?
                .iter()
                .any(|o| o["section"] == "unread")
        );
        if let Some(since) = since {
            assert_eq!(&body["since"], since);
        }
        Ok(())
    }
    fn unread(&self) -> TestResult<Vec<String>> {
        let (v, _) = self.json(
            &["--project", &self.project, "msg", "list", "--limit", "100"],
            true,
        )?;
        let mut ids: Vec<_> = v["items"]
            .as_array()
            .ok_or("mail")?
            .iter()
            .map(|r| r["id"].as_str().map(str::to_owned).ok_or("mail id"))
            .collect::<Result<_, _>>()?;
        ids.sort();
        Ok(ids)
    }
}
impl Drop for Consumer {
    fn drop(&mut self) {
        if let Ok(mut c) = self.command(false) {
            match c.arg("--json").arg("down").output() {
                Ok(out) if out.status.success() => (),
                other => eprintln!("review fixture shutdown was not witnessed: {other:?}"),
            }
        }
    }
}
fn setup(provider: Provider, saved_notes: bool) -> TestResult<Consumer> {
    let root = directory::private_directory()?;
    fs::create_dir(root.join("owner"))?;
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("runtime"))?;
    }
    fs::create_dir(root.join("repo"))?;
    let home = root.join("state home with a quoted \"segment\" and retained conversation context");
    let mut c = Consumer {
        root,
        home,
        project: String::new(),
        agent: String::new(),
        session: capture::session()?,
        messages: Vec::new(),
        working: "OWED: finish verification λ \" \\ \n".repeat(80),
        mail: "READ NEXT: retained obligation λ \" \\ \n".repeat(80),
        calls: 0,
        provider,
    };
    if !saved_notes {
        c.working.clear();
    }
    let name = if provider == Provider::Claude {
        "claude"
    } else {
        "codex"
    };
    let repo = c.root.join("repo");
    let (init, _) = c.json(
        &[
            "init",
            "--repo",
            repo.to_str().ok_or("repo")?,
            "--name",
            "Resume review",
            "--agent",
            "Worker",
            "--provider",
            name,
        ],
        false,
    )?;
    c.project = init["project"]["id"].as_str().ok_or("project")?.into();
    c.agent = init["agent"]["id"].as_str().ok_or("agent")?.into();
    let config = c.home.join("config.toml");
    let configured = fs::read_to_string(&config)?;
    fs::write(
        &config,
        configured
            .lines()
            .filter(|line| !line.starts_with("listen_port ="))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )?;
    let options = StoreOptions {
        state_directory: c.home.clone(),
        busy_timeout: Duration::from_secs(5),
    };
    let Read::Present { value: reader } = SqliteFactory::open_reader(&options)? else {
        return Err("store absent".into());
    };
    let store = reader.info()?.id;
    drop(reader);
    let f = Fixture {
        home: c.home.clone(),
        _root: None,
        options,
        store: store.clone(),
        owner: init["owner"]["human_id"].as_str().ok_or("owner")?.parse()?,
        project: c.project.parse()?,
        a: c.agent.parse()?,
        b: c.agent.parse()?,
    };
    let lease = Lease::acquire(&c.home, LeaseMode::DirectClient, Some(store))?;
    let Read::Present { value: mut direct } = SqliteFactory::open_direct(&f.options, &*lease)?
    else {
        return Err("direct store absent".into());
    };
    let source = capture::record()?;
    let credential = capture::record()?;
    let token = Secret::new(
        format!(
            "sec1.{}.{}",
            c.session,
            &se_types::hex_lower(se_proc::random_secret()?.expose())[..43]
        )
        .into_bytes(),
    )?;
    let mut prepared = capture::prepared(&f, &c.session, &f.a);
    if let EventBody::SessionPrepared { provider: p, .. } = &mut prepared {
        *p = provider;
    }
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(request("resume-review-session")?),
            vec![
                prepared,
                EventBody::CredentialIssued {
                    credential,
                    session: c.session.clone(),
                    purpose: "session".into(),
                    secret_sha256: Sha256::digest(token.expose()).into(),
                    expires_at_us: now + 900_000_000,
                    activation_deadline_us: now + 60_000_000,
                    expected: Expected::Absent,
                },
                capture::activated(&c.session)?,
                EventBody::CredentialActivated {
                    credential,
                    session: c.session.clone(),
                    expected: revision(1)?,
                    first_request: capture::record()?,
                },
                capture::source(source, &c.session, b"first", Expected::Absent),
            ],
        )?,
        &*lease,
    )?;
    fs::write(c.home.join("transcript.jsonl"), b"ten bytes!".repeat(8))?;
    for n in 0..8 {
        let mut batch = capture::capture(
            &f,
            &c.session,
            source,
            b"first",
            n * 10,
            n + 1,
            &format!("CHANGED-{n}: {}", "retained context λ \" \\ ".repeat(30)),
        )?;
        for e in &mut batch.events {
            // Public event reads require the synthetic capture producer's provenance.
            e.header.door = Door::Hook;
            if let EventBody::SessionTurn { provider: p, .. } = &mut e.body {
                *p = provider;
            }
        }
        direct.append(batch, &*lease)?;
    }
    if saved_notes {
        direct.append(
            f.working(&c.working, Expected::Absent, "resume-review-work")?,
            &*lease,
        )?;
    }
    for n in 0..24 {
        let id = message()?;
        direct.append(
            f.send(
                Actor::Human(f.owner.clone()),
                Actor::Agent(f.a.clone()),
                id.clone(),
                &c.mail,
                &format!("resume-review-mail-{n}"),
            )?,
            &*lease,
        )?;
        c.messages.push(id.to_string());
    }
    c.messages.sort();
    direct.close()?;
    drop(lease);
    se_proc::publish_session_pin(
        &se_proc::NativeStateFiles::open(&c.home)?,
        &c.session,
        &token,
    )?;
    let (up, _) = c.json(&["up"], false)?;
    assert_eq!(up["state"], "running");
    Ok(c)
}
fn exercise(provider: Provider, saved_notes: bool) -> TestResult {
    let mut c = setup(provider, saved_notes)?;
    assert_eq!(c.unread()?, c.messages);
    let mut since: Option<Value> = None;
    for phase in 0..2 {
        let mut words = vec!["resume"];
        let cursor_text;
        if let Some(cursor) = &since {
            cursor_text = cursor.as_str().ok_or("cursor")?.to_owned();
            words.extend(["--since", &cursor_text]);
        }
        let (body, bytes) = c.json(&words, true)?;
        c.record("cli", &body, bytes.len())?;
        assert!(
            bytes.len() <= 4096,
            "CLI complete response exceeds budget: {}",
            bytes.len()
        );
        assert_eq!(
            body["budget"]["used_bytes"].as_u64(),
            Some(bytes.iter().rposition(|b| *b != b'\n').ok_or("stdout")? as u64 + 1)
        );
        c.check(&body, since.as_ref())?;
        let args = since
            .as_ref()
            .map_or_else(|| json!({}), |cursor| json!({"since":cursor}));
        let (mcp, used) = c.mcp(args)?;
        c.record("mcp", &mcp, used)?;
        assert!(used <= 4096, "MCP complete response exceeds budget: {used}");
        assert_eq!(mcp["budget"]["used_bytes"].as_u64(), Some(used as u64));
        c.check(&mcp, since.as_ref())?;
        assert_eq!(c.unread()?, c.messages, "resume acknowledged mail");
        if phase == 0 {
            // Execute the actual advertised commands; recovery may be individual
            // or shared depending on how much representation fits.
            let recoveries: Vec<Vec<String>> = mcp["omissions"]
                .as_array()
                .ok_or("omissions")?
                .iter()
                .filter_map(|o| o["argv"].as_array())
                .filter(|a| !a.is_empty())
                .map(|a| {
                    a.iter()
                        .map(|v| v.as_str().map(str::to_owned).ok_or("argv word"))
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<_, _>>()?;
            assert!(
                !recoveries.is_empty(),
                "clipped reply has no executable recovery"
            );
            for argv in recoveries {
                assert!(
                    argv.contains(&c.project)
                        && argv.contains(&c.home.to_string_lossy().into_owned())
                );
                let recovered = c
                    .raw_command(true)?
                    .arg("--json")
                    .args(&argv[1..])
                    .output()?;
                assert!(
                    matches!(recovered.status.code(), Some(0 | 2)),
                    "advertised recovery refused: {}",
                    String::from_utf8_lossy(&recovered.stderr)
                );
                let full: Value = serde_json::from_slice(&recovered.stdout)?;
                assert_ne!(full["schema"], "se.error/v1");
                if argv.iter().any(|a| a == "resume") {
                    if saved_notes {
                        assert_eq!(full["working_state"]["value"]["text"], c.working);
                    } else {
                        assert_eq!(full["working_state"]["state"], "absent");
                    }
                    assert_eq!(
                        full["recent_turns"]
                            .as_array()
                            .ok_or("recovered turns")?
                            .len(),
                        8
                    );
                }
                if argv.iter().any(|a| a == "msg") {
                    assert_eq!(full["items"][0]["body"]["text"], c.mail);
                    assert_eq!(full["items"][0]["body"]["complete"], true);
                }
            }
            assert_eq!(c.unread()?, c.messages, "recovery acknowledged mail");
            since = Some(body["cursor"].clone());
        }
    }
    let (down, _) = c.json(&["down"], false)?;
    assert_eq!(down["complete"], true);
    assert!(!c.home.join("endpoint.json").exists());
    Ok(())
}
#[test]
fn claude_session_default_cli_and_mcp_retain_scoped_resume_answers() -> TestResult {
    for saved_notes in [false, true] {
        exercise(Provider::Claude, saved_notes)?;
    }
    Ok(())
}
#[test]
fn codex_session_default_cli_and_mcp_retain_scoped_resume_answers() -> TestResult {
    for saved_notes in [false, true] {
        exercise(Provider::Codex, saved_notes)?;
    }
    Ok(())
}
