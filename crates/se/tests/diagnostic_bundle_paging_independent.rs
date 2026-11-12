//! Public init and status consumers prove paged observations cannot receipt a complete bundle.
#[path = "../../test-support/directory.rs"]
mod directory;

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

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
        for path in [
            &fixture.user_home,
            &fixture.home,
            &fixture.repos,
            &fixture.temp,
        ] {
            private_dir(path)?;
        }
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
            .env("HOME", &self.user_home)
            .env("USERPROFILE", &self.user_home)
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

#[test]
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn a_paged_home_status_remains_observed_but_makes_the_export_incomplete() -> Check {
    let fixture = Fixture::new()?;
    let mut registered = BTreeSet::new();
    let mut expected_names = BTreeSet::new();
    let mut owner = None::<String>;
    for index in 0..101 {
        let name = format!("paging-{index:03}");
        let repo = fixture.repos.join(&name);
        private_dir(&repo)?;
        // Empty native repositories need neither commits, identity, hooks nor
        // provider credentials. Suppress account/global template configuration.
        let git = fixture
            .command("git")
            .args(["init", "--quiet", "--template="])
            .current_dir(&repo)
            .output()?;
        assert!(git.status.success(), "git init {index}: {}", printed(&git));
        assert!(repo.join(".git").is_dir());
        let initialized = json(
            fixture
                .se()
                .args(["init", "--repo"])
                .arg(&repo)
                .args([
                    "--name",
                    &name,
                    "--agent",
                    "synthetic-agent",
                    "--provider",
                    "codex",
                ])
                .current_dir(&repo)
                .output()?,
            0,
            &format!("public init {index}"),
        )?;
        assert_eq!(initialized["project"]["name"], name);
        let id = initialized["project"]["id"]
            .as_str()
            .ok_or("initialized project ID missing")?;
        assert!(
            registered.insert(id.to_owned()),
            "init reused an earlier project ID"
        );
        let human = initialized["owner"]["human_id"]
            .as_str()
            .ok_or("initialized owner missing")?;
        match &owner {
            Some(owner) => assert_eq!(
                human,
                owner.as_str(),
                "init changed the shared home's owner"
            ),
            None => owner = Some(human.to_owned()),
        }
        expected_names.insert(name);
    }
    assert_eq!(registered.len(), 101);

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
    let bundle: Value = serde_json::from_slice(&bytes)?;
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
