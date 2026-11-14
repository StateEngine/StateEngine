//! Independent public CLI coverage: private, bounded, redacted diagnostic exports.
#[path = "../../test-support/directory.rs"]
mod directory;

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, FileTimes, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, SystemTime},
};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    root: PathBuf,
    _root: directory::PrivateDirectory,
    user_home: PathBuf,
    home: PathBuf,
    temp: PathBuf,
}

impl Fixture {
    fn new() -> Check<Self> {
        se_proc::initialize_file_creation_owner()?;
        let root = directory::private_directory()?;
        let user_home = root.join("synthetic-user-home");
        let home = user_home.join("stateengine");
        let temp = root.join("exports");
        for path in [&user_home, &home, &temp] {
            private_dir(path)?;
        }
        Ok(Self {
            root: root.to_path_buf(),
            _root: root,
            user_home,
            home,
            temp,
        })
    }

    fn command(&self, home: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
        // No provider/session markers or real account credentials enter this child.
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
            .args(["diagnostic-bundle", "--home"])
            .arg(home)
            .arg("--json")
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
            .env("NO_COLOR", "1")
            .current_dir(&self.root);
        command
    }

    fn collect(&self, complete: bool) -> Check<Bundle> {
        self.collect_from(&self.home, complete)
    }

    fn collect_from(&self, home: &Path, complete: bool) -> Check<Bundle> {
        self.read_bundle(self.command(home).output()?, complete)
    }

    #[expect(
        clippy::cognitive_complexity,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    fn read_bundle(&self, output: Output, complete: bool) -> Check<Bundle> {
        if let Ok(receipt) = serde_json::from_slice::<Value>(&output.stdout)
            && let Some(path) = receipt["path"].as_str()
            && let Ok(bytes) = fs::read(path)
            && let Ok(document) = serde_json::from_slice::<Value>(&bytes)
        {
            for section in ["version", "status", "doctor", "logs"] {
                eprintln!(
                    "diagnostic section {section}: state={}, code={}, reason={}",
                    document[section]["state"],
                    document[section]["code"],
                    document[section]["reason"]
                );
            }
        }
        assert_eq!(
            output.status.code(),
            Some(if complete { 0 } else { 2 }),
            "unexpected diagnostic exit: {}",
            printed(&output)
        );
        let receipt: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(receipt["schema"], "se.diagnostic-bundle/v1");
        assert_eq!(receipt["complete"], complete);
        let path = PathBuf::from(receipt["path"].as_str().ok_or("receipt path missing")?);
        assert!(path.is_absolute(), "receipt path must be absolute");
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("bundle.json")
        );
        let parent = path.parent().ok_or("export directory missing")?;
        assert_ne!(parent, self.temp, "export must have its own new directory");
        assert_eq!(
            fs::canonicalize(parent.parent().ok_or("temp parent missing")?)?,
            fs::canonicalize(&self.temp)?,
            "export must be directly inside the selected OS temp directory"
        );
        assert!(fs::symlink_metadata(parent)?.is_dir());
        assert!(fs::symlink_metadata(&path)?.is_file());
        assert_private(parent, 0o700)?;
        assert_private(&path, 0o600)?;
        assert_eq!(
            directory_names(parent)?,
            BTreeSet::from(["bundle.json".into()])
        );
        let bytes = fs::read(&path)?;
        assert_eq!(receipt["bytes"].as_u64(), Some(bytes.len() as u64));
        let actual_digest = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(receipt["sha256"].as_str(), Some(actual_digest.as_str()));
        let document: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(document["schema"], "se.diagnostic-bundle-file/v1");
        for section in ["version", "status", "doctor"] {
            assert!(
                matches!(
                    document[section]["state"].as_str(),
                    Some("observed" | "unreadable" | "oversized")
                ),
                "unknown section state for {section}"
            );
            if document[section]["state"] == "observed" {
                assert!(
                    document[section]["data"].is_object(),
                    "missing {section} data"
                );
            } else {
                assert!(
                    document[section].get("data").is_none(),
                    "unobserved data must not be exported"
                );
            }
        }
        assert!(matches!(
            document["logs"]["state"].as_str(),
            Some("observed" | "absent" | "unreadable")
        ));
        assert!(document["logs"]["entries"].is_array());
        let inventory_complete = document["logs"]["inventory_complete"]
            .as_bool()
            .ok_or("inventory completeness missing")?;
        let omitted = document["logs"]
            .get("omitted")
            .ok_or("omitted metadata missing")?;
        if inventory_complete {
            assert!(
                omitted.as_u64().is_some(),
                "complete inventory needs a known omitted count"
            );
        } else {
            assert!(
                omitted.is_null(),
                "an unknown omitted count must not become a false zero"
            );
        }
        for entry in entries(&document)? {
            assert!(entry["name"].is_string());
            assert!(entry["truncated"].is_boolean());
            match entry["state"].as_str() {
                Some("observed") => {
                    assert!(entry["content"].is_string());
                    assert_eq!(entry["truncated"], false);
                }
                Some("unreadable" | "oversized") => {
                    assert!(
                        entry.get("content").is_none(),
                        "non-observed log leaked content"
                    );
                }
                _ => panic!("unknown log state"),
            }
        }
        Ok(Bundle {
            path,
            bytes,
            document,
        })
    }

    fn log(&self, index: usize, content: &[u8], age_rank: u64) -> Check<String> {
        let name = log_name(index);
        let path = self.home.join(&name);
        private_file(&path, content)?;
        File::options()
            .write(true)
            .open(path)?
            .set_times(FileTimes::new().set_modified(
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + age_rank * 60),
            ))?;
        Ok(name)
    }
}

struct Bundle {
    path: PathBuf,
    bytes: Vec<u8>,
    document: Value,
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

fn private_file(path: &Path, bytes: &[u8]) -> Check {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)?;
    Ok(())
}

fn assert_private(path: &Path, expected: u32) -> Check {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::symlink_metadata(path)?.permissions().mode() & 0o777,
            expected
        );
    }
    #[cfg(not(unix))]
    let _ = (path, expected);
    Ok(())
}

fn directory_names(path: &Path) -> Check<BTreeSet<String>> {
    fs::read_dir(path)?
        .map(|entry| {
            Ok(entry?
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF-8 fixture entry")?)
        })
        .collect()
}

fn printed(output: &Output) -> String {
    format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn log_name(index: usize) -> String {
    format!("runtime-startup-{index:032x}.log")
}

fn entries(document: &Value) -> Check<&Vec<Value>> {
    document["logs"]["entries"]
        .as_array()
        .ok_or_else(|| "log entries missing".into())
}

fn entry<'a>(document: &'a Value, name: &str) -> Check<&'a Value> {
    entries(document)?
        .iter()
        .find(|entry| entry["name"] == name)
        .ok_or_else(|| format!("log entry missing: {name}").into())
}

fn assert_uninitialized_observations(document: &Value) -> Check {
    for section in ["version", "status", "doctor"] {
        assert_eq!(
            document[section]["state"], "observed",
            "{section} must really be collected"
        );
    }
    assert_eq!(
        document["version"]["data"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(document["status"]["data"]["setup"]["state"], "not-set-up");
    let checks = document["doctor"]["data"]["checks"]
        .as_array()
        .ok_or("doctor checks missing")?;
    assert!(
        checks
            .iter()
            .any(|check| check["id"] == "store.open" && check["code"] == "setup-required")
    );
    Ok(())
}

fn assert_no_leaks(bundle: &Bundle, forbidden: &[String]) -> Check {
    let raw = std::str::from_utf8(&bundle.bytes)?;
    let mut decoded = Vec::new();
    strings(&bundle.document, &mut decoded);
    for secret in forbidden {
        assert!(!secret.is_empty());
        assert!(
            !raw.contains(secret),
            "sensitive fixture bytes survived in bundle.json"
        );
        assert!(
            decoded.iter().all(|value| !value.contains(secret)),
            "sensitive fixture bytes survived in decoded JSON"
        );
    }
    Ok(())
}

fn strings<'a>(value: &'a Value, output: &mut Vec<&'a str>) {
    match value {
        Value::String(text) => output.push(text),
        Value::Array(values) => values.iter().for_each(|value| strings(value, output)),
        Value::Object(fields) => {
            for (key, value) in fields {
                output.push(key);
                strings(value, output);
            }
        }
        _ => (),
    }
}

#[test]
fn uninitialized_home_exports_real_observations_with_verified_private_unique_receipts() -> Check {
    let fixture = Fixture::new()?;
    let first = fixture.collect(true)?;
    assert_uninitialized_observations(&first.document)?;
    assert_eq!(first.document["logs"]["state"], "absent");
    assert!(entries(&first.document)?.is_empty());
    assert_eq!(first.document["logs"]["omitted"], 0);
    assert_eq!(first.document["logs"]["inventory_complete"], true);
    assert_no_leaks(
        &first,
        &[
            fixture.home.to_string_lossy().into_owned(),
            fixture.user_home.to_string_lossy().into_owned(),
        ],
    )?;
    let original = fs::read(&first.path)?;
    let second = fixture.collect(true)?;
    assert_uninitialized_observations(&second.document)?;
    assert_ne!(
        first.path.parent(),
        second.path.parent(),
        "each export needs a new directory"
    );
    assert_eq!(
        fs::read(&first.path)?,
        original,
        "later export overwrote prior bundle"
    );
    assert!(
        directory_names(&fixture.home)?.is_empty(),
        "diagnosis initialized or mutated the home"
    );
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn actual_allowlisted_log_redacts_credentials_and_homes_but_preserves_benign_text() -> Check {
    let fixture = Fixture::new()?;
    // Every value below is synthetic and deliberately useless as a credential.
    let mut text = String::from(concat!(
        "benign startup marker: synthetic diagnostics remain useful\n",
        "api_key=synthetic-unquoted-assignment\n",
        "api_key = \"synthetic quoted assignment with spaces\"\n",
        "token='synthetic single quoted assignment'\n",
        "password = \"synthetic-multiline-first\nsynthetic-multiline-second\"\n",
        "\"client_secret\": \"synthetic-json-client-secret\"\n",
        "Set-Cookie: session=synthetic-cookie; HttpOnly\n",
        "Cookie: session=synthetic-in-cookie\n",
        "passphrase=synthetic-phrase\n",
        "\"passphrase\": \"synthetic-field-phrase\"\n",
        "launch --passphrase synthetic-flag-phrase --mode benign\n",
        "Authorization: Bearer synthetic-bearer-credential\n",
        "Authorization: ApiKey synthetic-short-secret\n",
        "launch --token synthetic-flag-secret --mode benign\n",
        "Authorization: Basic c3ludGhldGljLWZha2U6bm90LWEtY3JlZGVudGlhbA==\n",
        "url=https://synthetic-url-user:synthetic-url-password@example.invalid/path?api_key=synthetic-query-key&access_token=synthetic-query-access&token=synthetic-query-token&password=synthetic-query-password&safe=benign-query-marker\n",
        "encoded=https://synthetic%2Dencoded%2Duser:synthetic%2Dencoded%2Dpassword@example.invalid/path\n",
        "userinfo URL https://synthetic-user-token@example.invalid/path\n",
        "custom query https://example.invalid/path?widget=synthetic-query-a&%61%75%74%68=synthetic-query-b\n",
        "prefix sk-synthetic-fake-token-not-a-real-key-000000000000000000000000\n",
        "prefix sk-ant-api03-synthetic-fake-token-not-a-real-key-000000000000\n",
        "prefix ghp_syntheticFakeTokenNotReal000000000000000000000000\n",
        "prefix github_pat_syntheticFakeTokenNotReal000000000000000000000000\n",
        "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-FAKE-PRIVATE-KEY-NOT-VALID-BASE64\n-----END PRIVATE KEY-----\n",
        "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC-FAKE-RSA-KEY-NOT-VALID-BASE64\n-----END RSA PRIVATE KEY-----\n",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nshort-fake-key\n-----END PGP PRIVATE KEY BLOCK-----\n",
        "linux path /home/synthetic-linux-home/project/file.rs\n",
        "mac path /Users/synthetic-macos-home/project/file.rs\n",
        "windows path C:\\Users\\synthetic-windows-home\\project\\file.rs\n",
        "windows forward path C:/Users/synthetic-forward-home/project/file.rs\n",
        "windows spaced path C:\\Users\\synthetic wide home\\project\\file.rs\n",
        "windows doubled path C:\\\\Users\\\\synthetic-doubled-home\\\\project\\\\file.rs\n",
        "windows doubled spaced path C:\\\\Users\\\\synthetic doubled spaced home\\\\project\\\\file.rs\n",
        "benign final marker: collection finished\n",
    ));
    text.push_str(&format!(
        "selected state path {}\nselected user path {}\n",
        fixture.home.display(),
        fixture.user_home.display()
    ));
    let forbidden = [
        "synthetic-unquoted-assignment",
        "synthetic quoted assignment with spaces",
        "synthetic single quoted assignment",
        "synthetic-multiline-first",
        "synthetic-multiline-second",
        "synthetic-json-client-secret",
        "synthetic-cookie",
        "synthetic-in-cookie",
        "synthetic-phrase",
        "synthetic-field-phrase",
        "synthetic-flag-phrase",
        "short-fake-key",
        "synthetic-bearer-credential",
        "synthetic-short-secret",
        "synthetic-flag-secret",
        "synthetic-user-token",
        "synthetic-query-a",
        "synthetic-query-b",
        "benign-query-marker",
        "c3ludGhldGljLWZha2U6bm90LWEtY3JlZGVudGlhbA==",
        "synthetic-url-user",
        "synthetic-url-password",
        "synthetic-query-key",
        "synthetic-query-access",
        "synthetic-query-token",
        "synthetic-query-password",
        "synthetic%2Dencoded%2Duser",
        "synthetic%2Dencoded%2Dpassword",
        "synthetic-encoded-user",
        "synthetic-encoded-password",
        "synthetic-fake-token-not-a-real-key-",
        "syntheticFakeTokenNotReal000000000000000000000000",
        "sk-synthetic-fake-token-not-a-real-key-000000000000000000000000",
        "sk-ant-api03-synthetic-fake-token-not-a-real-key-000000000000",
        "ghp_syntheticFakeTokenNotReal000000000000000000000000",
        "github_pat_syntheticFakeTokenNotReal000000000000000000000000",
        "SYNTHETIC-FAKE-PRIVATE-KEY-NOT-VALID-BASE64",
        "SYNTHETIC-FAKE-RSA-KEY-NOT-VALID-BASE64",
        "synthetic-linux-home",
        "synthetic-macos-home",
        "synthetic-windows-home",
        "synthetic-forward-home",
        "synthetic wide home",
        "wide home",
        "synthetic-doubled-home",
        "synthetic doubled spaced home",
        "doubled spaced home",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([
        fixture.home.to_string_lossy().into_owned(),
        fixture.user_home.to_string_lossy().into_owned(),
    ])
    .collect::<Vec<_>>();
    let name = fixture.log(11, text.as_bytes(), 1)?;
    let bundle = fixture.collect(true)?;
    assert_uninitialized_observations(&bundle.document)?;
    assert_no_leaks(&bundle, &forbidden)?;
    assert_eq!(bundle.document["logs"]["state"], "observed");
    assert_eq!(bundle.document["logs"]["omitted"], 0);
    assert_eq!(bundle.document["logs"]["inventory_complete"], true);
    assert_eq!(entries(&bundle.document)?.len(), 1);
    let observed = entry(&bundle.document, &name)?;
    assert_eq!(observed["state"], "observed");
    let content = observed["content"]
        .as_str()
        .ok_or("observed log content missing")?;
    assert!(content.contains("benign startup marker: synthetic diagnostics remain useful"));
    assert!(content.contains("benign final marker: collection finished"));
    assert_eq!(
        fs::read(fixture.home.join(name))?,
        text.as_bytes(),
        "redaction modified the source log"
    );
    Ok(())
}

#[test]
fn nine_logs_select_eight_by_mtime_and_ignore_non_allowlisted_or_nested_files() -> Check {
    let fixture = Fixture::new()?;
    // Name order and creation order deliberately disagree with modification order.
    let ranks = [3, 8, 1, 6, 0, 4, 7, 2, 5];
    for (index, rank) in ranks
        .into_iter()
        .enumerate()
        .filter(|(index, _)| *index != 4)
    {
        fixture.log(
            index,
            format!("benign retained log {index}\n").as_bytes(),
            rank,
        )?;
    }
    let exactly_eight = fixture.collect(true)?;
    assert_eq!(entries(&exactly_eight.document)?.len(), 8);
    assert_eq!(exactly_eight.document["logs"]["omitted"], 0);
    fixture.log(4, b"benign retained log 4\n", 0)?;
    let excluded_marker = "synthetic-excluded-file-content-not-for-export";
    for name in [
        "runtime-startup-user.log".to_owned(),
        format!("runtime-startup-{}.log", "A".repeat(32)),
        format!("runtime-startup-{}.log", "a".repeat(31)),
        format!("runtime-startup-{}.log", "a".repeat(33)),
        format!("{}.old", log_name(90)),
        "unrelated.log".to_owned(),
        "credentials.json".to_owned(),
    ] {
        private_file(&fixture.home.join(name), excluded_marker.as_bytes())?;
    }
    let nested = fixture.home.join("nested");
    private_dir(&nested)?;
    private_file(&nested.join(log_name(91)), excluded_marker.as_bytes())?;
    let before = directory_names(&fixture.home)?;
    let bundle = fixture.collect(false)?;
    assert_uninitialized_observations(&bundle.document)?;
    assert_eq!(bundle.document["logs"]["state"], "observed");
    assert_eq!(bundle.document["logs"]["omitted"], 1);
    assert_eq!(bundle.document["logs"]["inventory_complete"], true);
    let actual = entries(&bundle.document)?
        .iter()
        .map(|entry| {
            entry["name"]
                .as_str()
                .ok_or("entry name missing")
                .map(str::to_owned)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = (0..9)
        .filter(|index| *index != 4)
        .map(log_name)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "newest eight must use mtime, not lexical or directory order"
    );
    assert_eq!(entries(&bundle.document)?.len(), 8);
    for index in (0..9).filter(|index| *index != 4) {
        let observed = entry(&bundle.document, &log_name(index))?;
        assert_eq!(observed["state"], "observed");
        assert_eq!(
            observed["content"],
            format!("benign retained log {index}\n")
        );
    }
    assert_no_leaks(
        &bundle,
        &[excluded_marker.into(), "benign retained log 4\n".into()],
    )?;
    assert_eq!(
        directory_names(&fixture.home)?,
        before,
        "export pruned or created source files"
    );
    Ok(())
}

#[test]
fn sixty_four_kibibyte_boundary_is_observed_but_larger_log_is_wholly_omitted() -> Check {
    let fixture = Fixture::new()?;
    // Short prose isolates the byte limit from conservative opaque-token redaction.
    let line = "benign log line\n";
    let exact = line.repeat(64 * 1024 / line.len());
    assert_eq!(exact.len(), 64 * 1024);
    let exact_name = fixture.log(21, exact.as_bytes(), 1)?;
    let oversized_marker = "synthetic oversized log must be wholly omitted";
    let mut oversized = oversized_marker.to_owned();
    oversized.push_str(&exact);
    oversized.truncate(64 * 1024 + 1);
    assert_eq!(oversized.len(), 64 * 1024 + 1);
    let oversized_name = fixture.log(22, oversized.as_bytes(), 2)?;
    let bundle = fixture.collect(false)?;
    assert_uninitialized_observations(&bundle.document)?;
    assert_eq!(bundle.document["logs"]["state"], "observed");
    assert_eq!(bundle.document["logs"]["inventory_complete"], true);
    assert_eq!(entries(&bundle.document)?.len(), 2);
    let bounded = entry(&bundle.document, &exact_name)?;
    assert_eq!(bounded["state"], "observed");
    assert_eq!(bounded["content"], exact);
    let over = entry(&bundle.document, &oversized_name)?;
    assert_eq!(over["state"], "oversized");
    assert_eq!(over["truncated"], true);
    assert!(over.get("content").is_none());
    assert_no_leaks(&bundle, &[oversized_marker.into()])?;
    assert_eq!(
        fs::read(fixture.home.join(oversized_name))?,
        oversized.as_bytes()
    );
    Ok(())
}

#[test]
fn directory_inventory_overflow_is_unreadable_not_false_absence_or_complete_success() -> Check {
    let fixture = Fixture::new()?;
    // Even irrelevant files count against the scan bound, not just accepted logs.
    for index in 0..4096 {
        private_file(&fixture.home.join(format!("irrelevant-{index:04}")), b"")?;
    }
    let at_limit = fixture.collect(true)?;
    assert_uninitialized_observations(&at_limit.document)?;
    assert_eq!(at_limit.document["logs"]["state"], "absent");
    assert_eq!(at_limit.document["logs"]["inventory_complete"], true);
    assert_eq!(at_limit.document["logs"]["omitted"], 0);
    assert!(entries(&at_limit.document)?.is_empty());
    private_file(&fixture.home.join("irrelevant-4096"), b"")?;
    let bundle = fixture.collect(false)?;
    assert_eq!(bundle.document["version"]["state"], "observed");
    assert_eq!(
        bundle.document["version"]["data"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    // Ordinary status and doctor also refuse an unknown staging inventory.
    for section in ["status", "doctor"] {
        assert_eq!(bundle.document[section]["state"], "unreadable");
        assert!(bundle.document[section].get("data").is_none());
    }
    assert_eq!(bundle.document["logs"]["state"], "unreadable");
    assert_eq!(bundle.document["logs"]["inventory_complete"], false);
    assert!(
        entries(&bundle.document)?.is_empty(),
        "incomplete inventory must not present a selected newest set"
    );
    assert_eq!(directory_names(&fixture.home)?.len(), 4097);
    Ok(())
}

#[test]
fn owner_can_export_an_incomplete_bundle_for_a_file_valued_home_without_mutating_it() -> Check {
    let fixture = Fixture::new()?;
    let damaged_home = fixture.user_home.join("file-valued-state");
    let canary = "synthetic file valued home bytes must remain untouched";
    private_file(&damaged_home, canary.as_bytes())?;
    let bundle = fixture.collect_from(&damaged_home, false)?;
    assert_eq!(bundle.document["version"]["state"], "observed");
    assert_eq!(
        bundle.document["version"]["data"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(bundle.document["status"]["state"], "unreadable");
    assert_eq!(bundle.document["logs"]["state"], "unreadable");
    assert_eq!(bundle.document["logs"]["inventory_complete"], false);
    assert!(entries(&bundle.document)?.is_empty());
    assert_no_leaks(
        &bundle,
        &[
            canary.into(),
            damaged_home.to_string_lossy().into_owned(),
            fixture.user_home.to_string_lossy().into_owned(),
        ],
    )?;
    assert!(fs::symlink_metadata(&damaged_home)?.is_file());
    assert_eq!(fs::read(&damaged_home)?, canary.as_bytes());
    assert!(directory_names(&fixture.home)?.is_empty());
    Ok(())
}

#[test]
fn malformed_session_refuses_as_owner_only_before_home_inspection_or_export_creation() -> Check {
    let fixture = Fixture::new()?;
    let poison_home = fixture.root.join("not-a-directory");
    let canary = b"synthetic-home-canary-must-not-be-read-or-overwritten";
    private_file(&poison_home, canary)?;
    let config = fixture.home.join("config.toml");
    private_file(&config, b"synthetic malformed configuration = [")?;
    let missing_home = fixture.root.join("must-remain-absent");
    for home in [&poison_home, &fixture.home, &missing_home] {
        for marker in ["synthetic-invalid-session-handle", ""] {
            let output = fixture.command(home).env("SE_SESSION", marker).output()?;
            assert!(
                !output.status.success(),
                "session marker granted owner authority"
            );
            let refusal: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
                format!(
                    "missing structured owner refusal: {error}: {}",
                    printed(&output)
                )
            })?;
            assert_eq!(refusal["code"], "owner-required", "{}", printed(&output));
            assert!(!printed(&output).contains(std::str::from_utf8(canary)?));
            assert!(
                directory_names(&fixture.temp)?.is_empty(),
                "refusal created an export"
            );
            assert!(!missing_home.exists(), "refusal created the selected home");
            assert_eq!(fs::read(&poison_home)?, canary);
            assert_eq!(fs::read(&config)?, b"synthetic malformed configuration = [");
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn allowlisted_symlink_log_is_unreadable_and_its_target_is_never_exported() -> Check {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new()?;
    let target = fixture.root.join("outside-private-target");
    let canary = "synthetic-symlink-target-must-never-enter-export";
    private_file(&target, canary.as_bytes())?;
    let name = log_name(31);
    let link = fixture.home.join(&name);
    symlink(&target, &link)?;
    let regular = fixture.log(32, b"benign regular sibling survives\n", 1)?;
    let bundle = fixture.collect(false)?;
    assert_uninitialized_observations(&bundle.document)?;
    assert_eq!(bundle.document["logs"]["state"], "observed");
    assert_eq!(bundle.document["logs"]["inventory_complete"], true);
    assert_eq!(entries(&bundle.document)?.len(), 2);
    let refused = entry(&bundle.document, &name)?;
    assert_eq!(refused["state"], "unreadable");
    assert!(refused.get("content").is_none());
    assert_eq!(
        entry(&bundle.document, &regular)?["content"],
        "benign regular sibling survives\n"
    );
    assert_no_leaks(&bundle, &[canary.into()])?;
    assert_eq!(fs::read(&target)?, canary.as_bytes());
    assert_eq!(fs::read_link(link)?, target);
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_utf8_temp_parent_refuses_before_creating_any_export_artifacts() -> Check {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let fixture = Fixture::new()?;
    let bad_temp = fixture
        .root
        .join(OsString::from_vec(b"synthetic-temp-\xff".to_vec()));
    private_dir(&bad_temp)?;
    assert!(bad_temp.to_str().is_none());
    let output = fixture
        .command(&fixture.home)
        .env("TMPDIR", &bad_temp)
        .output()?;
    assert!(
        !output.status.success(),
        "an unrepresentable receipt path must be refused"
    );
    let refusal: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("missing structured refusal: {error}: {}", printed(&output)))?;
    assert!(
        refusal["code"]
            .as_str()
            .is_some_and(|code| !code.is_empty())
    );
    assert_ne!(refusal["schema"], "se.diagnostic-bundle/v1");
    assert!(
        refusal.get("path").is_none(),
        "refusal returned an export receipt"
    );
    assert!(
        directory_names(&bad_temp)?.is_empty(),
        "refusal left private export artifacts"
    );
    assert!(
        directory_names(&fixture.temp)?.is_empty(),
        "refusal silently selected another temp parent"
    );
    assert!(
        directory_names(&fixture.home)?.is_empty(),
        "refusal changed the state home"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_utf8_user_home_display_and_private_log_suffix_are_redacted() -> Check {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let fixture = Fixture::new()?;
    let user_home = fixture
        .root
        .join(OsString::from_vec(b"synthetic-home-\xff".to_vec()));
    private_dir(&user_home)?;
    assert!(user_home.to_str().is_none());
    let displayed_home = user_home.display().to_string();
    let suffix = "synthetic-private-suffix.txt";
    let displayed_file = format!("{displayed_home}/{suffix}");
    let content = format!(
        "displayed home file {displayed_file}\nbenign displayed home diagnostic survives\n"
    );
    let name = fixture.log(41, content.as_bytes(), 1)?;
    let output = fixture
        .command(&fixture.home)
        .env("HOME", &user_home)
        // Keep cwd outside this HOME so cwd masking cannot cover a missing
        // comparison against the lossy display spelling of the native HOME.
        .current_dir(&fixture.temp)
        .output()?;
    let bundle = fixture.read_bundle(output, true)?;
    assert_uninitialized_observations(&bundle.document)?;
    assert_no_leaks(&bundle, &[displayed_home, displayed_file, suffix.into()])?;
    assert_eq!(entries(&bundle.document)?.len(), 1);
    let observed = entry(&bundle.document, &name)?;
    assert_eq!(observed["state"], "observed");
    assert!(
        observed["content"]
            .as_str()
            .is_some_and(|text| text.contains("benign displayed home diagnostic survives"))
    );
    assert_eq!(fs::read(fixture.home.join(name))?, content.as_bytes());
    assert!(
        directory_names(&user_home)?.is_empty(),
        "diagnosis wrote to the user home"
    );
    Ok(())
}
