use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) struct Fixture {
    pub root: PathBuf,
    pub adapter: Arc<Discord>,
    pub token: se_types::Secret,
    _process: Process,
}
struct Process {
    root: PathBuf,
    child: Child,
    helper: PathBuf,
}

impl Fixture {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub fn new(mode: &str) -> Check<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "channel-wire-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let openssl = |args: &[&str]| -> Check<()> {
            let output = Command::new("openssl")
                .args(args)
                .current_dir(&root)
                .output()?;
            require(
                output.status.success(),
                "synthetic TLS certificate generation failed",
            )
        };
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=synthetic-local-test-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ])?;
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "key.pem",
            "-out",
            "request.csr",
            "-subj",
            "/CN=gateway.discord.gg",
        ])?;
        fs::write(
            root.join("leaf.conf"),
            "subjectAltName=DNS:discord.com,DNS:gateway.discord.gg\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
        )?;
        openssl(&[
            "x509",
            "-req",
            "-in",
            "request.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "certificate.pem",
            "-days",
            "1",
            "-extfile",
            "leaf.conf",
        ])?;
        let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/judges/discord_gateway_review.py");
        let child = Command::new("python3")
            .arg("-B")
            .arg(&helper)
            .arg("--root")
            .arg(&root)
            .arg("--mode")
            .arg(mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(root.join("provider.stderr"))?)
            .spawn()?;
        let process = Process {
            root: root.clone(),
            child,
            helper,
        };
        let started = std::time::Instant::now();
        while !root.join("ready.json").exists() {
            if started.elapsed() > Duration::from_secs(5) {
                return Err("local provider did not publish its listener".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let ready: Value = serde_json::from_slice(&fs::read(root.join("ready.json"))?)?;
        let port = u16::try_from(ready["port"].as_u64().ok_or("listener port absent")?)?;
        let address = ([127, 0, 0, 1], port).into();
        let client = Discord::client_builder()
            .resolve("discord.com", address)
            .resolve("gateway.discord.gg", address)
            .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(
                root.join("ca.pem"),
            )?)?)
            .build()?;
        Ok(Self {
            root,
            _process: process,
            adapter: Arc::new(Discord {
                client,
                invalid_sessions: Mutex::default(),
                identify_fire: Mutex::default(),
            }),
            token: se_types::Secret::new(b"synthetic-discord-token-for-local-tests-only".to_vec())?,
        })
    }
    pub fn events(&self) -> Check<Vec<Value>> {
        let path = self.root.join("events.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }
    /// Print every event the provider recorded, so a failed assertion names the
    /// step that refused instead of only the client-visible error.
    pub fn report(&self, test: &str) {
        match self.events() {
            Ok(events) => match serde_json::to_string(&events) {
                Ok(text) => eprintln!("{test}: provider events ({}): {text}", events.len()),
                Err(error) => eprintln!("{test}: provider events unprintable: {error}"),
            },
            Err(error) => eprintln!("{test}: provider events unreadable: {error}"),
        }
    }
    pub fn no_fixture_errors(&self) -> Check<()> {
        require(
            !self.events()?.iter().any(|e| e["kind"] == "fixture_error"),
            "provider fixture assertion failed",
        )
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = fs::write(self.root.join("stop"), "stop");
        let started = std::time::Instant::now();
        while self.child.try_wait().ok().flatten().is_none()
            && started.elapsed() < Duration::from_secs(5)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let cmdline =
                fs::read(format!("/proc/{}/cmdline", self.child.id())).unwrap_or_default();
            if cmdline
                .windows(self.helper.as_os_str().as_encoded_bytes().len())
                .any(|part| part == self.helper.as_os_str().as_encoded_bytes())
            {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
        if let Some(output) = std::env::var_os("CHANNEL_REVIEW_EVIDENCE") {
            let destination = PathBuf::from(output).join(self.root.file_name().unwrap_or_default());
            if fs::create_dir_all(&destination).is_ok() {
                for name in ["events.json", "provider.stderr"] {
                    let _ = fs::copy(self.root.join(name), destination.join(name));
                }
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
