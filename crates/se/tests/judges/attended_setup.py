"""Protects: attended expiry preserves windows and prior holds with ordinary retry.

Uses the real ten-minute clock, xterm/Xvfb and a native protocol double. No
provider account, store edits, injected clock or production process is used.
Run with --se EXACT_IMAGE --output NEW_SHORT_DIRECTORY.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
import urllib.request
import uuid

from mail_cli import Fixture


def provider():
    se, home, *args = sys.argv[2:]
    selectors = [flag for flag in ["--session-id", "--resume"] if flag in args]
    assert len(selectors) == 1, "one native conversation selector is required"
    conversation = args[args.index(selectors[0]) + 1]
    cwd = Path.cwd()
    # This judge uses short ASCII paths; refuse rather than approximate another slug.
    assert len(str(cwd)) < 180 and str(cwd).isascii()
    slug = "".join(c if c.isalnum() else "-" for c in str(cwd))
    path = Path(os.environ["HOME"]) / ".claude/projects" / slug / (conversation + ".jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    # A resumed provider retains its existing transcript instead of truncating it.
    with path.open("a") as transcript:
        transcript.write(json.dumps({"type": "user", "sessionId": conversation,
                                     "uuid": str(uuid.uuid4()), "message": {
                                         "role": "user", "content": "Native attended fixture"}}) + "\n")
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    ipc = subprocess.run([se, "--home", home, "mcp"], input=request + b"\n",
                         capture_output=True, timeout=20)
    assert ipc.returncode == 0, ipc.stderr
    config = json.loads(Path(args[args.index("--mcp-config") + 1]).read_text())
    server = config["mcpServers"]["stateengine"]
    call = urllib.request.Request(server["url"], data=request,
                                  headers={**server["headers"], "Content-Type": "application/json"})
    with urllib.request.urlopen(call, timeout=20) as response:
        assert response.status == 200
    (cwd / ("connected-" + conversation)).write_text("both discovery transports verified")


def identity(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    return fields[0], fields[19]


class Window(Fixture):
    def __init__(self, se, root):
        super().__init__(se, root)
        self.started = time.monotonic()
        self.env["TMPDIR"] = str(self.root / "tmp")
        (self.root / "tmp").mkdir()
        helper = Path(__file__).resolve()
        source = self.root / "provider.rs"
        source.write_text('''use std::{fs,thread,time::Duration,process::Command};
fn main(){let a:Vec<String>=std::env::args().collect();
if a.get(1).map(String::as_str)==Some("--version"){println!("2.1.318 (Claude Code)");return;}
if a.get(1).map(String::as_str)==Some("auth"){println!("{}",r#"{"loggedIn":true}"#);return;}
if a.get(1).map(String::as_str)==Some("plugin"){return;}
let i=a.iter().position(|x|x=="--session-id"||x=="--resume").unwrap();let c=&a[i+1];
fs::write(format!(".native-{c}"),std::process::id().to_string()).unwrap();
fs::rename(format!(".native-{c}"),format!("native-{c}")).unwrap();
while !std::path::Path::new(&format!("ready-{c}")).exists(){thread::sleep(Duration::from_millis(50));}
let s=Command::new(PYTHON).args([HELPER,"--provider",SE,HOME]).args(&a[1..]).status().unwrap();
assert!(s.success());loop{thread::sleep(Duration::from_secs(1));}}
'''.replace("PYTHON", json.dumps(sys.executable)).replace(
            "HELPER", json.dumps(str(helper))).replace("SE,HOME", ",".join(
                json.dumps(str(x)) for x in [self.se, self.home])))
        compiled = subprocess.run(["rustc", "--edition=2024", str(source), "-o", str(self.root / "provider")],
                                  capture_output=True, timeout=60)
        (self.root / "compile.stderr").write_bytes(compiled.stderr)
        assert compiled.returncode == 0, compiled.stderr
        self.display = subprocess.Popen(
            ["Xvfb", "-displayfd", "1", "-screen", "0", "640x480x24", "-nolisten", "tcp"],
            stdout=subprocess.PIPE, stderr=(self.root / "display.log").open("wb"), env=self.env)
        number = self.display.stdout.readline().decode().strip()
        assert number.isdigit(), "private display did not start"
        self.display_birth = identity(self.display.pid)[1]
        (self.root / "display.json").write_text(json.dumps({"pid": self.display.pid, "birth": self.display_birth}))
        self.env["DISPLAY"] = ":" + number

    def call(self, *args, recipient=False):
        if "launch" not in args or "--detach" in args:
            return super().call(*args, recipient=recipient)
        self.calls += 1
        argv = [str(self.se), "--json", "--home", str(self.home), *args]
        result = subprocess.run(["script", "-q", "-e", "-c", shlex.join(argv), "/dev/null"],
                                env=self.env, capture_output=True, timeout=65)
        base = self.log_root / f"call-{self.calls:02}"
        base.with_suffix(".stdout").write_bytes(result.stdout)
        base.with_suffix(".stderr").write_bytes(result.stderr)
        return result

    def row(self):
        rows = self.ok("--project", self.project, "status")["agents"]["items"]
        return next(row for row in rows if row["id"] == self.agent)

    def hold(self):
        return json.loads((self.home / "claude-mail/data" /
                           f"{self.project}-{self.agent}-hold.json").read_text())

    def launch_window(self, fresh=False, release=False):
        previous = {path: path.read_text() for path in self.repo.glob("native-*")}
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.call, "--project", self.project, "launch", self.agent,
                                  *(["--new"] if fresh else []))
            end = time.monotonic() + 40
            while time.monotonic() < end:
                new = [path for path in self.repo.glob("native-*")
                       if path.read_text() != previous.get(path)]
                if new:
                    record, = new
                    conversation = record.name.removeprefix("native-")
                    self.conversation = conversation
                    pid = int(record.read_text())
                    self.processes.append((pid, identity(pid)[1]))
                    if release:
                        (self.repo / ("ready-" + conversation)).touch()
                    break
                if pending.done():
                    result = pending.result()
                    raise AssertionError(("no native provider", result.stdout, result.stderr))
                time.sleep(.1)
            else:
                raise AssertionError("native provider was not observed")
            result = pending.result()
        if release:
            assert result.returncode == 0, (result.stdout, result.stderr)
        else:
            assert result.returncode == 0, (result.stdout, result.stderr)
            reply = json.loads(result.stdout)
            assert reply["state"] in ("starting", "setup-needed"), reply
            assert reply["session_id"] and reply["lifecycle_id"], reply
            for field in ("event_id", "conversation_id", "process", "containment"):
                assert field not in reply, ("pending is not activation proof", field, reply)
        row = self.row()
        self.session = row["session"]["session_id"]
        return row

    def mod(self, action):
        config = self.home / "launch" / ("lch_" + self.session[4:]) / "claude-mail.json"
        run = subprocess.run(["node", str(Path(__file__).with_name("attended_setup_mod.mjs")),
                              str(config), action], env=self.env, capture_output=True, timeout=45)
        (self.root / f"mod-{self.calls}-{action}.stdout").write_bytes(run.stdout)
        (self.root / f"mod-{self.calls}-{action}.stderr").write_bytes(run.stderr)
        assert run.returncode == 0, (run.stdout, run.stderr)
        return json.loads(run.stdout)

    def signal_display(self, signum):
        assert identity(self.display.pid)[1] == self.display_birth
        assert b"Xvfb\0-displayfd\0" in Path(f"/proc/{self.display.pid}/cmdline").read_bytes()
        os.kill(self.display.pid, signum)

    def close(self):
        self.signal_display(signal.SIGCONT)
        try:
            super().close()
        finally:
            self.signal_display(signal.SIGTERM)
            self.display.wait(timeout=10)


def main():
    """Protects: real expiry, mail wake/hold separation and failed-replacement retry."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    fixtures = []
    results = []
    def check(name, condition):
        assert condition, name
        results.append({"name": name, "passed": True})
        print(f"ok {len(results)} - {name}", flush=True)
    try:
        fresh = Window(args.se, args.output / "fresh")
        fixtures.append(fresh)
        held = Window(args.se, args.output / "held")
        fixtures.append(held)
        # Startup latency is a separate contract. Retain every failed setup;
        # use the supported explicit startup before judging welcome custody.
        for f in fixtures:
            f.ok("up")
        held.launch_window(release=True)
        original_held_conversation = held.conversation
        check("production hook retains session.start result and persists human stop", held.mod("human")["retained"] and held.hold()["held"])
        held.ok("--project", held.project, "stop", held.agent)
        for f, new in [(fresh, False), (held, True)]:
            row = f.launch_window(fresh=new)
            check("live welcome remains starting after caller returns", row["session"]["state"] == "starting")
        prior = held.hold()
        expired_fresh_conversation = fresh.conversation
        print("# waiting for the real ten-minute credential expiry; no clock/store edits", flush=True)
        end = time.monotonic() + 650
        while time.monotonic() < end:
            rows = [f.row() for f in fixtures]
            if all(row["session"]["state"] == "setup-expired" for row in rows):
                break
            time.sleep(5)
        else:
            raise AssertionError("setup did not expire with retained native window")
        for f, row in zip(fixtures, rows):
            check("expiry retains exact native process and gives ordinary scoped relaunch",
                  row["session"]["liveness"] == {"state": "present", "value": "live"}
                  and "--new" not in row["resume"]["argv"]
                  and "10 minutes" in row["resume"]["reason"])
            f.mod("expired-end")
        check("expiry and final mod closure create no fresh durable hold", fresh.hold()["held"] is False)
        check("expiry preserves all prior human hold fields", all(held.hold().get(k) == v for k, v in prior.items()))
        held.signal_display(signal.SIGSTOP)
        try:
            failed = held.call("--project", held.project, "launch", held.agent)
            check("replacement display failure is reported", failed.returncode != 0)
            # The caller may return pending before native setup's deadline.
            # Keep the actual display unavailable until that retained attempt ends.
            time.sleep(30)
        finally:
            held.signal_display(signal.SIGCONT)
        row = held.row()
        check("failed replacement keeps ordinary retry without claiming another expiry",
              "replacement setup failed" in row["resume"]["reason"] and "--new" not in row["resume"]["argv"])
        for f in fixtures:
            row = f.launch_window(release=True)
            check("ordinary reconnect activates its selected conversation", row["session"]["recorded_state"] == "activated")
        check("an unactivated fresh setup gets a new conversation",
              fresh.conversation != expired_fresh_conversation)
        check("prior verified conversation remains resumable after failed setup",
              held.conversation == original_held_conversation)
        sent = fresh.mail("send", fresh.agent, "Attended expiry judge")
        wake = fresh.mod("wake")
        check("unheld successor offers real unread mail through production mod", sent["message_id"] in " ".join(wake["prompts"]))
        check("prior held successor schedules no automatic wait", held.mod("held")["scheduled"] == 0 and held.hold()["held"])
    finally:
        cleanup = []
        for f in fixtures:
            try:
                f.close()
                cleanup.append({"home": str(f.home), "births": f.processes, "closed": True})
            except Exception as error:
                cleanup.append({"home": str(f.home), "closed": False, "error": repr(error)})
        (args.output / "result.json").write_text(json.dumps({"image_sha256": hashlib.sha256(args.se.read_bytes()).hexdigest(), "checks": results, "outside": cleanup}, indent=2))
        assert all(x["closed"] for x in cleanup), cleanup
    print(f"1..{len(results)}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--provider":
        provider()
    else:
        main()
