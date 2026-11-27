//! A saved-agent page that outgrows its byte budget ends early with a store
//! cursor, so paging reaches every agent once instead of failing the read.
#![allow(
    dead_code,
    reason = "The native store fixture is shared with other consumers."
)]
#[path = "../../test-support/provider_home.rs"]
mod provider_home;
use se_core::{
    admission::HumanTerminal,
    commit::{Cx, OpStep},
    dispatch::{CallFacts, Kernel},
    ops::{AgentCreate, AnyOp, agent_status},
};
use se_store::*;
use se_types::{AgentId, HumanId, IdempotencyKey, OmissionReason, ProjectId};
use std::{path::Path, process::Command};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[cfg(windows)]
#[path = "../../test-support/executable.rs"]
mod executable;
#[cfg(windows)]
#[path = "support/foreground_host.rs"]
mod foreground_host;
#[cfg(windows)]
#[path = "../../test-support/home_reaper.rs"]
mod home_reaper;

const AGENTS: usize = 20;

fn command(image: &Path, home: &Path, root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(image);
    command
        .args(["--json", "--home"])
        .arg(home)
        .args(args)
        .current_dir(root);
    for name in [
        "SE_HOME",
        "SE_PROJECT",
        "SE_CONFIG",
        "SE_LOG",
        "SE_SESSION",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(name);
    }
    provider_home::for_state(&mut command, home);
    command
}

fn call(
    image: &Path,
    home: &Path,
    root: &Path,
    args: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let output = command(image, home, root, args).output()?;
    assert!(
        output.status.success(),
        "CLI refused: {}; {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// Protects: twenty saved agents whose expanded rows exceed one page's byte
/// budget are returned across byte-bounded pages, each agent exactly once and
/// in order, with every partial page naming the byte budget and a cursor.
#[test]
fn saved_agents_past_one_byte_budget_page_through_every_agent() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let root = f.home.join("repository");
    std::fs::create_dir(&root)?;
    let home = &f.options.state_directory;
    let image = Path::new(env!("CARGO_BIN_EXE_se"));
    let initialized = call(image, home, &root, &["init", "--name", "byte-pages"])?;
    let owner: HumanId = initialized["owner"]["human_id"]
        .as_str()
        .ok_or("initialized owner")?
        .parse()?;
    let project: ProjectId = initialized["project"]["id"]
        .as_str()
        .ok_or("initialized project")?
        .parse()?;
    for index in 0..AGENTS {
        let key = format!("byte-page-agent-{index}");
        let name = format!("worker-{index:02}");
        call(image, home, &root, &["--key", &key, "agent", "add", &name])?;
    }
    let admission = Admission {
        scope: Scope::Project(project),
        actor: Actor::Human(owner),
        session: None,
        generation: 1,
    };
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(ReadScope {
        admission: admission.clone(),
        visibility: Visibility::Owner,
    })?;
    let mut cx = Cx {
        read: &mut snapshot,
        admission: &admission,
    };
    let whole = agent_status::page(budget(100, 1024 * 1024, None)?, &mut cx)?;
    assert!(whole.window().complete() && whole.next().is_none());
    let expected: Vec<AgentId> = whole.items().iter().map(|row| row.id.clone()).collect();
    assert!(expected.len() >= AGENTS, "every added agent is listed");
    // Room for about six expanded rows. The smaller principal metadata lets the
    // store return more records than that, so row expansion meets the budget.
    let widest = whole
        .items()
        .iter()
        .map(|row| serde_json::to_vec(row).map(|bytes| bytes.len()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or("rows")?;
    let max_bytes = u32::try_from(widest * 6 + 8)?;
    let (mut seen, mut after, mut pages) = (Vec::new(), None, 0);
    loop {
        let page = agent_status::page(budget(100, max_bytes, after)?, &mut cx)?;
        pages += 1;
        assert!(!page.items().is_empty(), "page {pages} made no progress");
        seen.extend(page.items().iter().map(|row| row.id.clone()));
        after = page.next().cloned();
        if after.is_none() {
            assert!(page.window().complete(), "the last page is complete");
            break;
        }
        assert!(!page.window().complete(), "a partial page says so");
        assert_eq!(
            page.window().omitted().reason,
            Some(OmissionReason::Budget),
            "page {pages} names the byte budget"
        );
        assert!(pages <= expected.len(), "paging must terminate");
    }
    snapshot.close()?;
    assert!(pages > 1, "the byte budget split the list");
    assert_eq!(seen, expected, "every agent exactly once, in order");
    Ok(())
}

const OBSERVED_AGENTS: usize = 101;

/// Protects: native observation enlarges saved rows after the store page is
/// cut, so the direct CLI and the hosted runtime both cut the observed page
/// again at its final bytes and continue from the last returned agent.
#[test]
fn observed_agent_list_pages_cut_at_their_final_bytes() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let root = f.home.join("repository");
    std::fs::create_dir(&root)?;
    // Observation adds this home to each row's resume command twice, and the
    // longest names and models bring the saved rows near one page's bytes.
    let home = &f.home.join("observed-state-".repeat(8)).join("state");
    std::fs::create_dir_all(home.parent().ok_or("state parent")?)?;
    // Cargo hard-links its binary; the runtime `se up` starts requires a
    // single-link image, as an installed archive provides.
    let image = &f.home.join(format!("se{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(env!("CARGO_BIN_EXE_se"), image)?;
    let initialized = call(image, home, &root, &["init", "--name", "observed-pages"])?;
    seed_observed_agents(&f.home, home, &initialized)?;
    let direct = list_every_agent(image, home, &root)?;
    // Hosted Windows runners forbid job breakaway, so there the test owns a
    // foreground host as its child instead of starting a detached one.
    #[cfg(windows)]
    let host = foreground_host::ForegroundHost::start(command(image, home, &root, &[]), home)?;
    #[cfg(not(windows))]
    call(image, home, &root, &["up"])?;
    let hosted = list_every_agent(image, home, &root);
    call(image, home, &root, &["down"])?;
    #[cfg(windows)]
    host.wait()?;
    let hosted = hosted?;
    assert!(
        direct.len() > OBSERVED_AGENTS,
        "every added agent is listed"
    );
    assert_eq!(
        hosted, direct,
        "hosted and direct pages list the same agents"
    );
    Ok(())
}

/// Saves the observed agents through the real create operation in this
/// process: one CLI process per agent outlasts the test timeout on Windows.
fn seed_observed_agents(root: &Path, home: &Path, initialized: &serde_json::Value) -> Check {
    let mut seed = Fixture::at(root.to_owned(), home.to_owned())?;
    seed.owner = initialized["owner"]["human_id"]
        .as_str()
        .ok_or("initialized owner")?
        .parse()?;
    seed.project = initialized["project"]["id"]
        .as_str()
        .ok_or("initialized project")?
        .parse()?;
    seed.store = present(SqliteFactory::open_reader(&seed.options)?)?
        .info()?
        .id;
    let configuration: se_config::config_policy::ConfigFile =
        toml::from_str(&std::fs::read_to_string(home.join("config.toml"))?)?;
    let lease = Lease::acquire(home, LeaseMode::DirectClient, Some(seed.store.clone()))?;
    let mut direct = present(SqliteFactory::open_direct(&seed.options, &*lease)?)?;
    let admission = seed.owner_project();
    let model = "m".repeat(128);
    for index in 0..OBSERVED_AGENTS {
        let micros = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        let kernel = Kernel::new(CallFacts {
            event: event()?,
            message: message()?,
            agent: agent()?,
            profile_event: event()?,
            notification_event: event()?,
            notification_message: message()?,
            occurred_at_us: i64::try_from(micros.as_micros())?,
            door: Door::Cli,
        })?
        .with_configuration(configuration.clone())?;
        let op = AnyOp::AgentCreate(AgentCreate {
            provider_settings: Box::default(),
            harness: None,
            name: format!("observed-{index:03}-{}", "n".repeat(50)),
            provider: None,
            model: Some(model.clone()),
            profile: None,
            idempotency_key: IdempotencyKey::new(format!("observed-page-agent-{index}"))?,
            external: false,
        });
        let mut snapshot = direct.snapshot(seed.scoped(Visibility::Owner))?;
        let mut cx = Cx {
            read: &mut snapshot,
            admission: &admission,
        };
        let step = kernel.plan(op, &mut cx, &HumanTerminal::OutsideAgentTree)?;
        snapshot.close()?;
        let OpStep::Commit { batch, .. } = step else {
            return Err("agent creation must plan a commit".into());
        };
        direct.append(batch, &*lease)?;
    }
    direct.close()?;
    Ok(())
}

/// Pages `agent list --limit 100` to its end; each agent appears exactly once.
fn list_every_agent(
    image: &Path,
    home: &Path,
    root: &Path,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let (mut seen, mut cursor, mut pages) = (Vec::new(), None::<String>, 0);
    loop {
        let mut args = vec!["agent", "list", "--limit", "100"];
        if let Some(cursor) = &cursor {
            args.extend(["--cursor", cursor]);
        }
        let page = call(image, home, root, &args)?;
        let items = page["items"].as_array().ok_or("agent page items")?;
        pages += 1;
        assert!(!items.is_empty(), "page {pages} made no progress: {page}");
        for item in items {
            seen.push(item["id"].as_str().ok_or("agent id")?.to_owned());
        }
        match page["next"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
        assert!(pages <= OBSERVED_AGENTS + 1, "paging must terminate");
    }
    assert!(pages > 1, "the byte budget split the observed list");
    let unique: std::collections::BTreeSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), seen.len(), "no agent is listed twice");
    Ok(seen)
}
