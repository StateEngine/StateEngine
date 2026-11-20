//! Public init and status consumers prove paged observations cannot receipt a complete bundle.
#[path = "../../test-support/directory.rs"]
mod directory;
#[path = "../../test-support/provider_home.rs"]
mod provider_home;

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[path = "../../se-store/tests/support/store_fixture.rs"]
mod store_fixture;

use se_store::{
    Actor, CommitState, DirectStore, EventBody, Expected, LeaseMode, ReadStore, Root, Scope,
    SqliteFactory, StoreFactory,
};
use se_types::{NativePath, ProjectId};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    root: PathBuf,
    _root: directory::PrivateDirectory,
    user_home: PathBuf,
    home: PathBuf,
    repos: PathBuf,
    temp: PathBuf,
}

impl Fixture {
    fn new() -> Check<Self> {
        se_proc::initialize_file_creation_owner()?;
        let root = directory::private_directory()?;
        let fixture = Self {
            user_home: root.join("user"),
            home: root.join("state"),
            repos: root.join("repos"),
            temp: root.join("exports"),
            root: root.to_path_buf(),
            _root: root,
        };
        for path in [&fixture.user_home, &fixture.repos, &fixture.temp] {
            private_dir(path)?;
        }
        // State roots require a protected native DACL on Windows; mkdir's
        // inherited permissions do not satisfy that contract.
        drop(se_proc::NativeStateFiles::create(&fixture.home)?);
        Ok(fixture)
    }

    fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(program);
        // Neither provider markers nor credentials/configuration from the real
        // account enter git, init, status, or the diagnostic child processes.
        command.env_clear();
        for key in [
            "PATH",
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "SYSTEMDRIVE",
            "PATHEXT",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .env("XDG_CONFIG_HOME", self.user_home.join(".config"))
            .env("XDG_STATE_HOME", self.user_home.join(".local/state"))
            .env("XDG_CACHE_HOME", self.user_home.join(".cache"))
            .env("APPDATA", self.user_home.join("AppData/Roaming"))
            .env("LOCALAPPDATA", self.user_home.join("AppData/Local"))
            .env("TMPDIR", &self.temp)
            .env("TEMP", &self.temp)
            .env("TMP", &self.temp)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.user_home.join(".gitconfig"))
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("NO_COLOR", "1")
            .current_dir(&self.root);
        provider_home::isolate_at(
            &mut command,
            &self.root,
            &self.user_home,
            &self.user_home.join(".codex"),
            &self.user_home.join(".claude"),
        );
        command
    }

    fn se(&self) -> Command {
        let mut command = self.command(env!("CARGO_BIN_EXE_se"));
        command.args(["--json", "--home"]).arg(&self.home);
        command
    }
}

fn private_dir(path: &Path) -> Check {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder.create(path)?;
    Ok(())
}

fn printed(output: &Output) -> String {
    format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn json(output: Output, exit_code: i32, label: &str) -> Check<Value> {
    assert_eq!(
        output.status.code(),
        Some(exit_code),
        "{label}: {}",
        printed(&output)
    );
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!("{label} did not return JSON: {error}: {}", printed(&output)).into()
    })
}

fn first_project_page(status: &Value) -> Check<BTreeSet<String>> {
    assert_eq!(
        status["scope"], "all",
        "must observe the whole home, not one repository"
    );
    let projects = &status["projects"];
    let rows = projects["items"]
        .as_array()
        .ok_or("project page rows missing")?;
    assert_eq!(rows.len(), 100, "must retain the measured first page");
    assert_eq!(projects["window"]["limit"], 100);
    assert_eq!(projects["window"]["complete"], false);
    assert!(
        projects["next"]
            .as_str()
            .is_some_and(|cursor| !cursor.is_empty()),
        "a partial project page must retain its continuation"
    );
    let names = rows
        .iter()
        .map(|row| {
            row["name"]
                .as_str()
                .map(str::to_owned)
                .ok_or("project name missing")
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(names.len(), 100, "first page repeated a registered project");
    Ok(names)
}

fn register_projects(fixture: &Fixture) -> Check<BTreeSet<String>> {
    let name = "paging-000";
    let repo = fixture.repos.join(name);
    private_dir(&repo)?;
    let initialized = json(
        fixture
            .se()
            .args(["init", "--repo"])
            .arg(&repo)
            .args([
                "--name",
                name,
                "--agent",
                "synthetic-agent",
                "--provider",
                "codex",
            ])
            .current_dir(&repo)
            .output()?,
        0,
        "public init",
    )?;
    assert_eq!(initialized["project"]["name"], name);
    let first: ProjectId = initialized["project"]["id"]
        .as_str()
        .ok_or("initialized project ID missing")?
        .parse()?;

    // Keep real home initialization and seed the remaining projects through
    // the store. The status page needs 101 registrations under the same owner.
    let mut seed = store_fixture::Fixture::at(fixture.root.clone(), fixture.home.clone())?;
    seed.owner = initialized["owner"]["human_id"]
        .as_str()
        .ok_or("initialized owner missing")?
        .parse()?;
    let info = store_fixture::present(SqliteFactory::open_reader(&seed.options)?)?.info()?;
    seed.store = info.id;
    let lease = store_fixture::Lease::acquire(
        &seed.options.state_directory,
        LeaseMode::DirectClient,
        Some(seed.store.clone()),
    )?;
    let mut direct = store_fixture::present(SqliteFactory::open_direct(&seed.options, &*lease)?)?;
    let admission = seed.admission(Scope::Registry, Actor::Human(seed.owner.clone()));
    let mut names = BTreeSet::from([name.to_owned()]);
    let mut registered = BTreeSet::from([first]);
    for range in [1..=50, 51..=100] {
        let key = format!("paging-projects-from-{}", range.start());
        let mut projects = Vec::new();
        for index in range {
            let name = format!("paging-{index:03}");
            let root = fixture.repos.join(&name);
            private_dir(&root)?;
            let path = NativePath::from_local(se_proc::canonicalize_path(&root)?)?;
            let canonical_key = serde_json::to_vec(&path)?;
            let project = ProjectId::from_parts(1_700_000_000_000 + index, [11; 10])?;
            assert!(registered.insert(project.clone()), "project ID collision");
            names.insert(name.clone());
            projects.push(EventBody::ProjectRegistered {
                project,
                name,
                roots: vec![Root {
                    path,
                    canonical_key,
                }],
                owner: seed.owner.clone(),
                history_from: None,
                expected: Expected::Absent,
            });
        }
        let count = projects.len();
        let receipt = direct.append(
            seed.batch(
                admission.clone(),
                Some(store_fixture::request(&key)?),
                projects,
            )?,
            &*lease,
        )?;
        assert_eq!(receipt.state, CommitState::Committed);
        assert_eq!(receipt.events.len(), count);
    }
    direct.close()?;
    assert_eq!(registered.len(), 101);
    Ok(names)
}

fn read_bundle(fixture: &Fixture, receipt: &Value) -> Check<Value> {
    let path = PathBuf::from(
        receipt["path"]
            .as_str()
            .ok_or("bundle receipt path missing")?,
    );
    assert!(path.is_absolute());
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some("bundle.json")
    );
    let parent = path.parent().ok_or("bundle directory missing")?;
    assert_ne!(parent, fixture.temp);
    assert_eq!(
        fs::canonicalize(parent.parent().ok_or("bundle temp parent missing")?)?,
        fs::canonicalize(&fixture.temp)?
    );
    assert!(fs::symlink_metadata(&path)?.is_file());
    let bytes = fs::read(&path)?;
    assert_eq!(receipt["bytes"].as_u64(), Some(bytes.len() as u64));
    let digest = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(receipt["sha256"].as_str(), Some(digest.as_str()));
    Ok(serde_json::from_slice(&bytes)?)
}

#[test]
fn a_paged_home_status_remains_observed_but_makes_the_export_incomplete() -> Check {
    let fixture = Fixture::new()?;
    let expected_names = register_projects(&fixture)?;

    // A successful public page is still a partial collection. Witness its
    // source exit and page bounds before judging the export's completeness.
    let source = json(
        fixture.se().args(["status", "--all"]).output()?,
        0,
        "home-wide status",
    )?;
    let source_names = first_project_page(&source)?;
    assert!(source_names.is_subset(&expected_names));

    let receipt = json(
        fixture.se().arg("diagnostic-bundle").output()?,
        2,
        "diagnostic bundle",
    )?;
    assert_eq!(receipt["schema"], "se.diagnostic-bundle/v1");
    assert_eq!(
        receipt["complete"], false,
        "a source continuation is not complete collection"
    );
    let bundle = read_bundle(&fixture, &receipt)?;
    assert_eq!(bundle["schema"], "se.diagnostic-bundle-file/v1");
    assert_eq!(bundle["complete"], false);
    assert_eq!(
        bundle["status"]["state"], "observed",
        "paging must not discard measured data"
    );
    assert_eq!(bundle["status"]["exit_code"], 0);
    assert_eq!(bundle["status"]["complete"], false);
    assert_eq!(first_project_page(&bundle["status"]["data"])?, source_names);
    assert_eq!(bundle["version"]["state"], "observed");
    assert_eq!(bundle["version"]["complete"], true);
    assert_eq!(bundle["doctor"]["state"], "observed");
    assert_eq!(
        bundle["doctor"]["complete"], true,
        "an observed unhealthy diagnosis is still collected"
    );
    assert!(matches!(
        bundle["doctor"]["exit_code"].as_u64(),
        Some(0 | 1)
    ));
    assert!(
        bundle["doctor"]["data"]["checks"]
            .as_array()
            .is_some_and(|checks| !checks.is_empty())
    );
    assert_eq!(bundle["logs"]["state"], "absent");
    assert_eq!(bundle["logs"]["inventory_complete"], true);
    assert_eq!(bundle["logs"]["omitted"], 0);
    assert!(
        bundle["logs"]["entries"]
            .as_array()
            .is_some_and(|entries| entries.is_empty())
    );
    Ok(())
}
