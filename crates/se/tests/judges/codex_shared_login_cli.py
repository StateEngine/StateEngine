"""Public-CLI verification for shared Codex app-server per login and login relink."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid
from judge_records import wait_json
from provider_home import isolate, run_provider_command


def observe(pid):
    try:
        proc = Path(f"/proc/{pid}")
        argv = [v.decode(errors="replace") for v in (proc / "cmdline").read_bytes().split(b"\0") if v]
        stat = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
        return {"pid": pid, "birth": stat[19], "state": stat[0], "argv": argv}
    except (FileNotFoundError, ProcessLookupError):
        return None


def live(identity):
    row = observe(identity["pid"])
    return bool(row and row["birth"] == identity["birth"] and row["state"] != "Z")


def owned_rows(root):
    rows = []
    marker = str(root).encode()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            argv = (proc / "cmdline").read_bytes()
            environ = (proc / "environ").read_bytes()
            if marker not in argv and marker not in environ:
                continue
            row = observe(int(proc.name))
            if row and row["argv"]:
                rows.append(row)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return rows


def write_auth(codex_home, account_id, token):
    auth = codex_home / "auth.json"
    staged = codex_home / f".auth.{uuid.uuid4().hex}.tmp"
    payload = {
        "tokens": {
            "account_id": account_id,
            "access_token": token,
            "refresh_token": f"refresh-{token}",
        }
    }
    staged.write_text(json.dumps(payload))
    staged.chmod(0o600)
    staged.replace(auth)


def wait_exit(identity, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not live(identity):
            return
        time.sleep(0.05)
    raise AssertionError(f"process did not exit in time: {identity}")


class Judge:
    def __init__(self, args):
        self.args = args
        self.root = args.output.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        for name in ("owner", "repo", "runtime", "tmp", "codex"):
            (self.root / name).mkdir(mode=0o700)
        self.home = self.root / "state"
        self.codex_home = self.root / "codex"
        self.env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("SE_", "STATEENGINE_", "CODEX_", "CLAUDE", "OPENAI"))
        }
        isolate(self.env, self.root, self.root / "owner", codex=self.codex_home)
        self.env.update(
            XDG_RUNTIME_DIR=str(self.root / "runtime"),
            TMPDIR=str(self.root / "tmp"),
            SE_PROVIDER_STOP_GRACE_MS="500",
        )
        helper_source = Path(__file__).with_name("codex_recovery_provider.py").resolve(strict=True)
        helper = self.root / "provider.py"
        shutil.copyfile(helper_source, helper)
        source = self.root / "provider.rs"
        source.write_text(
            'fn main(){let a:Vec<String>=std::env::args().collect();'
            'if a.iter().any(|v|v=="--version"){println!("codex-cli 0.152.0");return;}'
            'let root=std::path::Path::new(HELPER).parent().unwrap();'
            'let log=std::fs::File::create(root.join("provider-stderr.txt")).unwrap();'
            'let s=std::process::Command::new(PYTHON).arg(HELPER).args(&a[1..])'
            '.stderr(log).status().unwrap();'
            'std::process::exit(s.code().unwrap_or(1));}'
            .replace("PYTHON", json.dumps(os.sys.executable))
            .replace("HELPER", json.dumps(str(helper)))
        )
        self.provider_bin = self.root / "provider"
        compiled = subprocess.run(
            ["rustc", "--edition=2024", str(source), "-o", str(self.provider_bin)],
            capture_output=True,
            timeout=40,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr.decode())

    def call(self, *args, timeout=100):
        return run_provider_command(
            subprocess.run,
            [str(self.args.se.resolve()), "--home", str(self.home), "--json", *args],
            environment=self.env,
            fixture=self.root,
            cwd=self.root / "repo",
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
        )

    def ok(self, *args):
        r = self.call(*args)
        if r.returncode:
            raise AssertionError((args, r.returncode, r.stdout.decode(), r.stderr.decode()))
        return json.loads(r.stdout), r.stdout.decode()

    def run(self):
        token_a = "synthetic-not-a-real-token-alpha"
        token_b = "synthetic-not-a-real-token-beta"
        write_auth(self.codex_home, "acct-alpha-original", token_a)

        init_data, _ = self.ok(
            "--key", str(uuid.uuid4()), "init",
            "--repo", str(self.root / "repo"),
            "--name", "Shared Login Judge",
            "--agent", "Alpha",
            "--provider", "codex",
            "--model", "gpt-5.3-codex",
        )
        project = init_data["project"]["id"]
        alpha = init_data["agent"]["id"]

        config = self.home / "config.toml"
        text = config.read_text()
        text = text.replace(f'listen_port = {init_data["profile"]["native_server_port"]}', "", 1)
        text = text.replace(
            "[providers.codex]",
            "[providers.codex]\ncommand = " + json.dumps(str(self.provider_bin.resolve())),
            1,
        )
        config.write_text(text)

        beta_data, _ = self.ok(
            "--project", project, "--key", str(uuid.uuid4()),
            "agent", "add", "Beta",
            "--provider", "codex", "--model", "gpt-5.3-codex",
        )
        beta = beta_data["agent"]["id"]

        launch_a, _ = self.ok("--project", project, "launch", alpha, "--detach", "--force")
        launch_b, _ = self.ok("--project", project, "launch", beta, "--detach", "--force")
        assert launch_a["state"] == "running" and launch_b["state"] == "running"
        assert launch_a["session_id"] != launch_b["session_id"]
        assert launch_a["conversation_id"] != launch_b["conversation_id"]
        assert launch_a["process"]["pid"] != launch_b["process"]["pid"]

        ready_a = wait_json(self.codex_home / f'ready-{launch_a["session_id"]}.json', 20)
        ready_b = wait_json(self.codex_home / f'ready-{launch_b["session_id"]}.json', 20)
        assert ready_a["helper_pid"] == ready_b["helper_pid"], (
            f"agents did not share one app-server helper: {ready_a} vs {ready_b}"
        )
        assert ready_a["native_pid"] == ready_b["native_pid"], (
            f"agents did not share one app-server scope: {ready_a} vs {ready_b}"
        )
        shared_server = observe(ready_a["native_pid"])
        assert shared_server is not None and live(shared_server)

        wait_json(self.codex_home / f'turn-{launch_a["conversation_id"]}.json', 20)
        wait_json(self.codex_home / f'turn-{launch_b["conversation_id"]}.json', 20)

        status_before, raw_before = self.ok("--project", project, "status")
        assert token_a not in raw_before, "raw token leaked into status output"
        rows_before = {row["id"]: row for row in status_before["agents"]["items"]}
        for agent_id in (alpha, beta):
            login = rows_before[agent_id]["codex_login"]
            assert login["state"] == "present", login
            assert login["value"]["account"] == "acct-alpha-original", login

        # Deliberate relink: replace auth.json while both agents are running.
        write_auth(self.codex_home, "acct-beta-relinked", token_b)

        status_after, raw_after = self.ok("--project", project, "status")
        assert token_a not in raw_after and token_b not in raw_after, "token leaked after relink"
        rows_after = {row["id"]: row for row in status_after["agents"]["items"]}
        for agent_id in (alpha, beta):
            login = rows_after[agent_id]["codex_login"]
            assert login["state"] == "present", login
            assert login["value"]["account"] == "acct-beta-relinked", login
            show_data, show_raw = self.ok("--project", project, "agent", "show", agent_id)
            assert token_b not in show_raw
            assert show_data["agent"]["value"]["codex_login"]["value"]["account"] == "acct-beta-relinked"
        assert live(shared_server), "shared app-server died during relink"

        # Stop Alpha: shared app-server must stay alive while Beta is running.
        self.ok("--project", project, "stop", alpha)
        time.sleep(0.3)
        assert live(shared_server), "shared app-server stopped while second agent was still running"

        # Stop Beta: shared app-server must retire cleanly.
        self.ok("--project", project, "stop", beta)
        wait_exit(shared_server, timeout=20.0)
        self.ok("down")
        leftover = owned_rows(self.root)
        assert not leftover, f"lingering processes after shutdown: {leftover}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--se", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    judge = Judge(parser.parse_args())
    try:
        judge.run()
    finally:
        try:
            judge.call("down", timeout=15)
        except Exception:
            pass


if __name__ == "__main__":
    main()
