//! A saved-agent page that outgrows its byte budget ends early with a store
//! cursor, so paging reaches every agent once instead of failing the read.
#![allow(
    dead_code,
    reason = "The native store fixture is shared with other consumers."
)]
#[path = "../../test-support/provider_home.rs"]
mod provider_home;
use se_core::{commit::Cx, ops::agent_status};
use se_store::*;
use se_types::{AgentId, HumanId, OmissionReason, ProjectId};
use std::{path::Path, process::Command};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

const AGENTS: usize = 20;

fn call(
    home: &Path,
    root: &Path,
    args: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
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
    let output = command.output()?;
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
    let initialized = call(home, &root, &["init", "--name", "byte-pages"])?;
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
        call(home, &root, &["--key", &key, "agent", "add", &name])?;
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
