//! Reviewer-owned public setup/removal regression; no provider account is used.
#![cfg(any(target_os = "linux", windows))]

use std::{
    error::Error,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn Error>>;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("cannot remove owned settings fixture: {error}");
        }
    }
}
fn scratch() -> Result<Scratch, Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!(
        "se-adoption-settings-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&path)?;
    Ok(Scratch(path))
}
fn provider(root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    // Installation only asks --version. Any other request is a fixture error,
    // not a simulated provider session or a claim about capture/mail behavior.
    let source = root.join("version.rs");
    fs::write(
        &source,
        r#"fn main() {
        if std::env::args().nth(1).as_deref() == Some("--version") {
            println!("2.1.318 (Claude Code)");
        } else { std::process::exit(91); }
    }"#,
    )?;
    let binary = root.join(if cfg!(windows) {
        "version.exe"
    } else {
        "version"
    });
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let output = Command::new(rustc)
        .args(["--edition=2024", "-C", "debuginfo=0"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()?;
    assert!(
        output.status.success(),
        "native version fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(binary)
}
struct Fixture {
    binary: PathBuf,
    root: PathBuf,
    owner: PathBuf,
    config: PathBuf,
    home: PathBuf,
    repo: PathBuf,
}
impl Fixture {
    fn new(root: PathBuf, binary: &Path) -> Result<Self, Box<dyn Error>> {
        let owner = root.join("owner");
        let config = owner.join("claude");
        let home = root.join("state");
        let repo = root.join("repo");
        fs::create_dir_all(&config)?;
        fs::create_dir(&repo)?;
        Ok(Self {
            binary: binary.to_owned(),
            root,
            owner,
            config,
            home,
            repo,
        })
    }
    fn call(&self, args: &[&str]) -> Result<Output, Box<dyn Error>> {
        let mut command = Command::new(&self.binary);
        command.env_clear();
        for key in ["PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let output = command
            .env("HOME", &self.owner)
            .env("USERPROFILE", &self.owner)
            .env("CLAUDE_CONFIG_DIR", &self.config)
            .env("XDG_CONFIG_HOME", self.owner.join("config"))
            .args(["--json", "--home"])
            .arg(&self.home)
            .args(args)
            .current_dir(&self.repo)
            .output()?;
        assert!(
            output.status.success(),
            "{args:?}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    }
    fn install(&self, provider: &Path, before: &str) -> Check {
        fs::write(self.config.join("settings.json"), before)?;
        self.call(&[
            "init",
            "--provider",
            "claude",
            "--key",
            "synthetic-plain-init",
        ])?;
        assert_eq!(
            fs::read(self.config.join("settings.json"))?,
            before.as_bytes()
        );
        let path = self.home.join("config.toml");
        let config = fs::read_to_string(&path)?;
        let selected = format!(
            "[providers.claude]\ncommand = {:?}",
            provider.to_str().ok_or("non-UTF8 fixture path")?
        );
        assert_eq!(config.matches("[providers.claude]").count(), 1);
        fs::write(path, config.replacen("[providers.claude]", &selected, 1))?;
        self.call(&[
            "init",
            "--adopt",
            "--provider",
            "claude",
            "--key",
            "synthetic-adopt-init",
        ])?;
        Ok(())
    }
    fn roundtrip(&self, provider: &Path, before: &str, later_edit: bool) -> Check {
        self.install(provider, before)?;
        let path = self.config.join("settings.json");
        let installed = fs::read(&path)?;
        self.call(&[
            "init",
            "--adopt",
            "--provider",
            "claude",
            "--key",
            "synthetic-adopt-retry",
        ])?;
        assert_eq!(fs::read(&path)?, installed, "retry rewrote settings");
        let expected = if later_edit {
            let installed = String::from_utf8(installed)?;
            let edited = installed.replace("\"before\"", "\"after-user-edit\"");
            assert_ne!(installed, edited);
            fs::write(&path, edited)?;
            before.replace("\"before\"", "\"after-user-edit\"")
        } else {
            before.to_owned()
        };
        self.call(&["uninstall", "--yes", "--key", "synthetic-adopt-remove"])?;
        assert_eq!(
            fs::read(&path)?,
            expected.as_bytes(),
            "unrelated settings bytes changed in {}",
            self.root.display()
        );
        assert!(!self.home.join("claude-adoption.json").exists());
        Ok(())
    }
}

#[test]
fn public_adoption_preserves_settings_bytes_and_later_user_edits() -> Check {
    let root = scratch()?;
    let provider = provider(&root.0)?;
    let binary = std::env::var_os("SE_ADOPTION_REVIEW_BINARY")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_se").map(PathBuf::from))
        .ok_or("provide the CLI binary through Cargo or SE_ADOPTION_REVIEW_BINARY")?;
    let cases = [
        "{ \"model\" : \"synthetic-model\",\n \"permissions\": { \"allow\" : [\"Read\"], \"deny\": [\"Bash(*)\"] }, \"hooks\" : {\"SessionStart\":[ { \"hooks\": [{\"type\":\"command\",\"command\":\"user-command\",\"args\":[]} ] } ]}, \"env\":{\"SYNTHETIC_SETTING\":\"\\u006b\\u0065pt\"} }\n",
        "{}",
        "{ \r\n \"model\" : \"synthetic-model\" \r\n}\r\n",
        "{\"model\":\"synthetic-model\",\"hooks\":{   }}\n",
        "{ \"hooks\": { \"SessionStart\": [   ] }, \"permissions\":{\"allow\":[\"Read\"]}}",
        "{\"h\\u006foks\":{\"Sessi\\u006fnStart\":[ ],\"Stop\": [ ]},\"env\":{\"unicode\":\"caf\\u00e9\"}}\n",
        "{\"hooks\":{\"SessionStart\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"user-command\",\"args\":[\"brace } [ \\\"\",\"\\u0061\"]}]}]}}",
        "{\"model\":\"synthetic-model\",\"env\":{\"SYNTHETIC\":\"before\"}}\n",
    ];
    for (index, before) in cases.iter().enumerate() {
        let fixture = Fixture::new(root.0.join(index.to_string()), &binary)?;
        fixture.roundtrip(&provider, before, index == cases.len() - 1)?;
    }
    Ok(())
}
