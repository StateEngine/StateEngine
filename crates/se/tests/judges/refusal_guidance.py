"""Protects: refusal advice leads to real recovery through an installed public CLI.
No provider, account, private store write, or test-only production hook is used.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile


class Judge:
    def __init__(self, image, root):
        self.image, self.root = image.resolve(), root.resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        self.home = self.root / "selected state's directory"
        self.repo = self.root / "repository"
        self.repo.mkdir()
        self.runtime = Path(tempfile.mkdtemp(prefix="se-rg-"))
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("SE_", "STATEENGINE_", "CODEX", "CLAUDE",
                                         "OPENAI", "ANTHROPIC"))}
        for name in ["HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
                     "XDG_CACHE_HOME", "XDG_STATE_HOME"]:
            path = self.root / name.lower()
            path.mkdir()
            self.env[name] = str(path)
        self.env["XDG_RUNTIME_DIR"] = str(self.runtime)
        self.project = None
        self.calls, self.results, self.births = [], [], []
        subprocess.run(["git", "init", str(self.repo)], env=self.env,
                       capture_output=True, check=True, timeout=10)
        initial = self.ok("init", "--repo", str(self.repo), "--name", "Refusal project",
                          "--agent", "Local Writer", "--provider", "claude")
        self.project, self.agent = initial["project"]["id"], initial["agent"]["id"]
        config = self.home / "config.toml"
        text = config.read_text()
        for provider in ["claude", "codex"]:
            text = text.replace("[providers." + provider + "]",
                                "[providers." + provider + "]\ncommand = " +
                                json.dumps(str(self.root / ("absent-" + provider))), 1)
        for port in range(20000 + os.getpid() % 9000, 30000):
            with socket.socket() as listener:
                try:
                    listener.bind(("127.0.0.1", port))
                    break
                except OSError:
                    continue
        else:
            raise AssertionError("no available supported fixture port")
        config.write_text(text.replace(
            "listen_port = " + str(initial["profile"]["native_server_port"]),
            "listen_port = " + str(port), 1))

    def raw(self, argv, extra=None):
        result = subprocess.run([str(self.image), *argv], cwd=self.repo,
                                env={**self.env, **(extra or {})}, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=45)
        row = dict(argv=argv, exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
        self.calls.append(row)
        (self.root / f"call-{len(self.calls):03}.json").write_text(json.dumps(row, indent=2))
        return row

    def call(self, *args, json_mode=True, home=None, extra=None):
        argv = (["--json"] if json_mode else []) + ["--home", str(home or self.home)]
        if self.project and (home is None or home == self.home) and args[0] not in ("init", "up", "down"):
            argv += ["--project", self.project]
        return self.raw([*argv, *args], extra)

    def ok(self, *args, **kwargs):
        row = self.call(*args, **kwargs)
        assert row["exit"] == 0, row
        return json.loads(row["stdout"])

    def refuse(self, *args, json_mode=True, **kwargs):
        row = self.call(*args, json_mode=json_mode, **kwargs)
        assert row["exit"] != 0, row
        if json_mode:
            assert json.loads(row["stdout"]).get("code"), row
        return row

    def birth(self):
        endpoint = self.home / "endpoint.json"
        assert endpoint.exists(), "positive control never started a real runtime"
        status = self.ok("status")
        pid = status["runtime"]["process"]["pid"]
        start = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
        value = (pid, start)
        if value not in self.births:
            self.births.append(value)
        return value

    def bare_stop(self):
        """Protects: bare stop names agent scopes and both stop forms preserve the host."""
        missing = self.root / "absent home"
        for json_mode in [False, True]:
            row = self.refuse("stop", json_mode=json_mode, home=missing)
            assert "se stop AGENT" in row["stderr"] and "se stop --all" in row["stderr"], row
            assert "renamed" not in row["stderr"], row
        assert not missing.exists(), "usage error opened state"
        self.ok("up")
        before = self.birth()
        for args in [("stop", self.agent), ("stop", "--all")]:
            stopped = self.ok(*args)
            assert stopped["complete"], stopped
            assert self.birth() == before, "agent-stop advice shut down the background runtime"
        help_row = self.call("stop", "--help", json_mode=False)
        assert help_row["exit"] == 0 and "--all" in help_row["stdout"], help_row

    def floor_advice(self):
        """Protects: invalid floor sends save nothing and documented flags recover the exact message."""
        before = self.ok("msg", "list", "--to", self.agent, "--full")
        for json_mode in [False, True]:
            for options in [(), ("--work-action", "notify"),
                            ("--work-action", "notify", "--addressee", "Local Writer")]:
                row = self.refuse("msg", "send", "floor", "must not be saved", *options,
                                  json_mode=json_mode)
                for token in ["--work-action", "--addressee", "msg send --help", "agent list"]:
                    assert token in row["stderr"], (token, row)
        assert self.ok("msg", "list", "--to", self.agent, "--full") == before
        help_row = self.call("msg", "send", "--help", json_mode=False)
        assert help_row["exit"] == 0 and "notify" in help_row["stdout"], help_row
        agents = self.ok("agent", "list")
        assert self.agent in json.dumps(agents)
        sent = self.ok("msg", "send", "floor", "recovered floor message",
                       "--work-action", "notify", "--addressee", self.agent)
        assert sent["state"] == "committed", sent
        inbox = self.ok("msg", "list", "--to", self.agent, "--full")
        matches = [m for m in inbox["items"] if m["id"] == sent["message_id"]]
        assert len(matches) == 1 and matches[0]["body"]["text"] == "recovered floor message", inbox
        assert matches[0]["body"]["complete"], inbox

    def unknown_agent(self):
        """Protects: lookup remedies execute with the exact quoted home and project."""
        for args in [("launch", "missing-agent", "--detach"),
                     ("config", "get", "agent.missing-agent.model"),
                     ("msg", "inbox", "missing-agent")]:
            for json_mode in [False, True]:
                row = self.refuse(*args, json_mode=json_mode)
                assert "agent list" in row["stderr"], row
                if json_mode:
                    error = json.loads(row["stdout"])
                    assert error["code"] == "target-unknown", error
                    argv = error["remedy"]["command"]["argv"]
                else:
                    # Execute the rendered command too: spaces/apostrophes in
                    # the selected home must survive shell quoting.
                    candidates = [line.split("Run: ", 1)[1] for line in row["stderr"].splitlines()
                                  if "Run: se " in line and "agent list" in line]
                    assert len(candidates) == 1, row
                    argv = shlex.split(candidates[0])
                assert argv[0] == "se" and argv[-2:] == ["agent", "list"], argv
                assert argv[argv.index("--home") + 1] == str(self.home), argv
                assert argv[argv.index("--project") + 1] == self.project, argv
                recovery = self.raw(["--json", *argv[1:]])
                assert recovery["exit"] == 0 and self.agent in recovery["stdout"], recovery

    def file_home(self):
        """Protects: directory/init advice recovers from a file-valued home without changing its bytes."""
        path = self.root / "ordinary-file"
        original = b"retain this existing file\n"
        path.write_bytes(original)
        for extra in [None, {"SE_CONFIG": str(self.home / "config.toml")}]:
            for json_mode in [False, True]:
                row = self.refuse("status", home=path, extra=extra, json_mode=json_mode)
                text = row["stderr"].lower()
                assert "--home" in text and "directory" in text and "init" in text, row
                assert path.read_bytes() == original
        replacement = self.root / "new directory"
        self.ok("init", "--repo", str(self.repo), home=replacement)
        self.ok("status", home=replacement)
        assert path.read_bytes() == original

    def close(self):
        if (self.home / "endpoint.json").exists():
            self.birth()
        stopped = self.ok("down")
        assert stopped["complete"], stopped
        assert not (self.home / "endpoint.json").exists()
        with (self.home / "runtime.lock").open("rb") as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for pid, start in self.births:
            record = Path(f"/proc/{pid}/stat")
            if record.exists():
                fields = record.read_text().rsplit(") ", 1)[1].split()
                assert fields[19] != start or fields[0] in ("Z", "X"), (pid, start)
        import shutil
        shutil.rmtree(self.runtime)


def main():
    """Protects: all four refusal paths are checked through native CLI effects and closure."""
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    judge = Judge(args.se, args.output)
    try:
        # Read/write failures must reach target selection rather than being
        # confused with an unrelated cold-start refusal.
        judge.ok("up")
        judge.birth()
        for name in ["bare_stop", "floor_advice", "unknown_agent", "file_home"]:
            try:
                getattr(judge, name)()
                row = dict(name=name, passed=True)
            except Exception as error:
                row = dict(name=name, passed=False, error=str(error))
            judge.results.append(row)
            print(("ok" if row["passed"] else "not ok") + " - " + name, flush=True)
    finally:
        judge.close()
        result = dict(image_sha256=hashlib.sha256(args.se.read_bytes()).hexdigest(),
                      checks=judge.results, calls=len(judge.calls), births=judge.births,
                      endpoint_absent=True, lease_free=True)
        (judge.root / "result.json").write_text(json.dumps(result, indent=2))
    assert all(row["passed"] for row in judge.results), judge.results


if __name__ == "__main__":
    main()
