"""Native CLI/ACP and Codex app-server launch judges with no provider account."""
import contextlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


def until(get, reason, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if value := get():
            return value
        time.sleep(0.05)
    raise AssertionError(reason)


def try_json(file):
    with contextlib.suppress(FileNotFoundError, json.JSONDecodeError):
        return json.loads(file.read_bytes())


def safe_issue(result):
    try:
        value = json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError):
        value = {}
    if not isinstance(value, dict):
        value = {}
    diagnostic = value.get("message", "")
    diagnostic = re.sub(r"(?:sec1\.|sels[-_.])[^\s\x22\x27]+", "<redacted>", diagnostic)
    return f"exit={result.returncode}, code={value.get('code')}, diagnostic={diagnostic[:360]}"


def config_section(text, section, lines):
    expression = rf"(?m)^\[{re.escape(section)}\]\n(?:(?!^\[)[^\n]*\n)*"
    block = f"[{section}]\n" + "\n".join(lines) + "\n\n"
    if re.search(expression, text):
        return re.sub(expression, lambda _: block, text, count=1)
    return text.rstrip() + "\n\n" + block


def build_codex(root, se, home):
    helper = Path(__file__).with_name("session_environment_provider.py").resolve(strict=True)
    source = root / "codex.rs"
    image = root / ("codex-fixture.exe" if os.name == "nt" else "codex-fixture")
    tokens = [sys.executable, str(helper), "codex", str(root), str(se), str(home)]
    literals = ", ".join(json.dumps(token, ensure_ascii=False) for token in tokens)
    source.write_text(
        r'''
        fn main() {
            let argv: Vec<_> = std::env::args_os().skip(1).collect();
            if argv.iter().any(|arg| arg == "--version") {
                println!("codex-cli 0.152.0");
                return;
            }
            let [python, script, mode, root, se, home] = BINDS;
            let status = std::process::Command::new(python)
                .args([script, mode, root, se, home]).args(argv)
                .status().expect("fixture process");
            std::process::exit(status.code().unwrap_or(1));
        }
        '''.replace("BINDS", f"[{literals}]"),
        encoding="utf-8",
    )
    result = subprocess.run(
        ["rustc", "--edition=2024", str(source), "-o", str(image)],
        capture_output=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"could not compile the native version/transport fixture: {result.stderr.decode(errors='replace')[:500]}"
    )
    return image


class Case:
    def __init__(self, root, image):
        self.root, self.se = root, image.resolve(strict=True)
        for name in ("owner", "repo", "codex", "config", "data", "cache", "local"):
            (root / name).mkdir()
        self.home, self.repo = root / "state", root / "repo"
        self.runtime = Path(tempfile.mkdtemp(prefix="se-rpc-"))
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.upper().startswith(("SE_", "STATEENGINE_", "SECODE_", "CODEX_", "CLAUDE", "OPENAI"))
        }
        self.env.update(
            HOME=str(root / "owner"), USERPROFILE=str(root / "owner"),
            CODEX_HOME=str(root / "codex"), XDG_RUNTIME_DIR=str(self.runtime),
            XDG_CONFIG_HOME=str(root / "config"), XDG_DATA_HOME=str(root / "data"),
            XDG_CACHE_HOME=str(root / "cache"), XDG_STATE_HOME=str(root / "local"),
            SE_PROVIDER_STOP_GRACE_MS="500",
        )
        self.command = [str(self.se), "--json", "--home", str(self.home)]
        self.host = None

    def run(self, *args):
        return subprocess.run(
            [*self.command, *args], cwd=self.repo, env=self.env,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=80,
        )

    def ok(self, *args):
        result = self.run(*args)
        assert result.returncode == 0, f"{args[0]}: {safe_issue(result)}"
        return json.loads(result.stdout)

    def prepare(self, case):
        args = ("--key", str(uuid.uuid4()), "init", "--repo", str(self.repo),
                "--name", "Session environment judge", "--agent", "CodexFixture", "--provider", "codex",
                "--model", "gpt-5.3-codex")
        def bootstrap():
            result = self.run(*args)
            if b"installation record is busy" in result.stderr:
                return None
            assert result.returncode == 0, f"init: {safe_issue(result)}"
            return json.loads(result.stdout)
        initial = until(bootstrap, "installation admission remained busy", 45)
        self.project = initial["project"]["id"]
        self.agent = initial["agent"]["id"]
        path = self.home / "config.toml"
        config = path.read_text(encoding="utf-8")
        config = re.sub(r"(?m)^listen_port\s*=\s*\d+\s*\n", "", config)
        if case == "codex":
            image = build_codex(self.root, self.se, self.home)
            config = config_section(config, "providers.codex", [
                f"command = {json.dumps(str(image))}", 'model = "gpt-5.3-codex"',
            ])
            config = config_section(config, "atlas", ["enabled = true", "hooks = true"])
        else:
            helper = Path(__file__).with_name("session_environment_provider.py").resolve(strict=True)
            config = config_section(config, "providers.acp", [
                f"command = {json.dumps(sys.executable)}", 'profile = "acp-judge"',
            ])
            config = config_section(config, "profiles.acp-judge", [
                "bypass = true", "network = true", 'approval = "never"',
            ])
            arguments = [str(helper), "acp", str(self.root), str(self.se), str(self.home)]
            config = config_section(config, "acp", [f"arguments = {json.dumps(arguments)}"])
        path.write_text(config, encoding="utf-8")
        if case != "codex":
            self.agent = self.ok("--project", self.project, "agent", "add", "AcpFixture",
                                 "--provider", "acp")["agent"]["id"]

    def start(self):
        out = self.root / "host.stdout"
        with out.open("wb") as stdout, (self.root / "host.stderr").open("wb") as stderr:
            self.host = subprocess.Popen(
                [*self.command, "up", "--foreground"], cwd=self.repo, env=self.env,
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            )
        def ready():
            assert self.host.poll() is None, "owned foreground host exited before readiness"
            return try_json(out)
        record = until(ready, "foreground host readiness missing")
        assert record["state"] == "running" and record["process"]["pid"] == self.host.pid

    def launch(self):
        return self.run("--project", self.project, "launch", self.agent,
                        "--detach", "--task", "Read the fixture state.")

    @staticmethod
    def launched_session(result):
        if result.returncode != 0:
            raise AssertionError(f"native launch: {safe_issue(result)}")
        receipt = json.loads(result.stdout)
        assert receipt["state"] == "running", "native provider did not reach running"
        assert receipt["session_id"].startswith("ses_"), "launch receipt lacks public session"
        return receipt["session_id"]

    def close(self):
        if self.host is not None:
            receipt = self.ok("down")
            assert receipt["complete"] and receipt["witness"]["state"] == "witnessed"
            assert self.host.wait(timeout=30) == 0, "exact foreground owner did not exit cleanly"
        shutil.rmtree(self.runtime)
        shutil.rmtree(self.root)


def judge(case, image):
    root = Path(tempfile.mkdtemp(prefix="se-env-judge-"))
    harness = Case(root, image)
    try:
        harness.prepare(case)
        harness.start()
        launch = harness.launch()
        if case == "codex":
            session = harness.launched_session(launch)
        values = until(lambda: try_json(root / "environment.json"), "child environment receipt absent")
        assert not values["has_credential_argv"], "provider argv contains credential bytes"
        if case != "codex":
            pipe = until(lambda: try_json(root / "acp-pipe.json"), "ACP protocol receipt absent")
            assert pipe["session_proof_seen"] and pipe["http"], "ACP protocol HTTP proof missing"
            if case == "acp-environment":
                assert not values["has_credential_bytes"], "ACP child inherited credential bytes"
            else:
                assert pipe["ipc"], "ACP child's se discovery rejected the inherited session input"
            session = harness.launched_session(launch)
        if case == "acp-consumer":
            (root / "call-se").touch()
            result = until(lambda: try_json(root / "consumer.json"), "ACP se-call receipt absent")
            assert result.get("session") == session and result.get("agent") == harness.agent, (
                f"ACP child could not use se with its inherited session (exit={result['exit']})"
            )
        else:
            assert values["sessions"] == [session] and not values["has_credential_bytes"], (
                "ACP child inherited credential bytes or the wrong public session"
                if case == "acp-environment" else "Codex did not receive exactly one public SE_SESSION"
            )
            if case == "codex":
                hooks = until(lambda: try_json(root / "hooks.json"), "Atlas hook witness absent")
                assert hooks["configured"], "this Codex launch did not carry the requested Atlas hooks"
        print(f"witnessed {case} through the native CLI")
    finally:
        harness.close()


if __name__ == "__main__":
    try:
        judge(sys.argv[1], Path(sys.argv[2]))
    except Exception as error:
        print(f"{type(error).__name__}: {error}")
        raise SystemExit(1) from None
