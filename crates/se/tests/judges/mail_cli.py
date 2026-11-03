"""Independent public CLI mail judge. Uses an isolated owner home and a native
Claude protocol double; no paid provider account or database edits are required.
Run: python3 mail_cli.py --se RELEASE_SE --output NEW_OWNED_DIRECTORY
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid


class Fixture:
    def __init__(self, se, root):
        self.se, self.root = se.resolve(), root.resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        self.home = self.root / "state"
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.root / "owner").mkdir()
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("SE_", "STATEENGINE_", "CODEX_", "CLAUDE"))}
        self.env.update(HOME=str(self.root / "owner"), USERPROFILE=str(self.root / "owner"))
        self.calls, self.session, self.processes = 0, None, []
        init = self.ok("--key", str(uuid.uuid4()), "init", "--repo", str(self.repo),
                       "--name", "Mail Judge", "--agent", "Recipient", "--provider", "claude",
                       "--model", "claude-sonnet-5-5")
        self.project, self.agent = init["project"]["id"], init["agent"]["id"]
        config = self.home / "config.toml"
        start = uuid.uuid4().int % 10000
        for offset in range(10000):
            port = 20000 + (start + offset) % 10000
            with socket.socket() as listener:
                try:
                    listener.bind(("127.0.0.1", port))
                    break
                except OSError:
                    continue
        else:
            raise RuntimeError("no available listener port")
        text = config.read_text().replace(f'listen_port = {init["profile"]["native_server_port"]}',
                                         f"listen_port = {port}", 1)
        helper = Path(__file__).with_name("mail_provider.py").resolve()
        source = self.root / "provider.rs"
        source.write_text('''fn main(){let a:Vec<String>=std::env::args().collect();
if a.get(1).map(String::as_str)==Some("--version"){println!("2.1.287 (Claude Code)");return;}
let s=std::process::Command::new(PYTHON).args([HELPER,SE,HOME]).args(&a[1..]).status().unwrap();
std::process::exit(s.code().unwrap_or(1));}'''.replace("PYTHON", json.dumps(sys.executable))
            .replace("HELPER,SE,HOME", ",".join(json.dumps(str(p)) for p in [helper, self.se, self.home])))
        executable = self.root / ("provider.exe" if os.name == "nt" else "provider")
        subprocess.run(["rustc", "--edition=2024", str(source), "-o", str(executable)],
                       capture_output=True, check=True, timeout=60)
        config.write_text(text.replace("[providers.claude]", "[providers.claude]\ncommand = " +
                                       json.dumps(str(executable)), 1))

    def call(self, *args, recipient=False):
        self.calls += 1
        environment = dict(self.env)
        if recipient:
            assert self.session
            environment["SE_SESSION"] = self.session
        result = subprocess.run([str(self.se), "--json", "--home", str(self.home), *args],
                                env=environment, capture_output=True, timeout=90)
        base = self.root / f"call-{self.calls:02}"
        base.with_suffix(".stdout").write_bytes(result.stdout)
        base.with_suffix(".stderr").write_bytes(result.stderr)
        return result

    def ok(self, *args, recipient=False):
        result = self.call(*args, recipient=recipient)
        end = time.monotonic() + 40
        while result.returncode and "init" in args and b"installation record is busy" in result.stderr and time.monotonic() < end:
            time.sleep(1)
            result = self.call(*args, recipient=recipient)
        assert result.returncode == 0, (args, result.stdout.decode(), result.stderr.decode())
        return json.loads(result.stdout)

    def mail(self, *args, recipient=False):
        return self.ok("--project", self.project, "msg", *args, recipient=recipient)

    def rpc(self, name, arguments):
        self.calls += 1
        environment = {**self.env, "SE_SESSION": self.session}
        request = {"jsonrpc": "2.0", "id": self.calls, "method": "tools/call",
                   "params": {"name": name, "arguments": arguments}}
        result = subprocess.run([str(self.se), "--home", str(self.home), "mcp"],
                                input=(json.dumps(request) + "\n").encode(), env=environment,
                                capture_output=True, timeout=30)
        base = self.root / f"call-{self.calls:02}"
        base.with_suffix(".stdout").write_bytes(result.stdout)
        base.with_suffix(".stderr").write_bytes(result.stderr)
        assert result.returncode == 0, (result.stdout, result.stderr)
        reply = json.loads(result.stdout)
        assert "result" in reply, reply
        return reply["result"]

    def launch(self):
        result = self.ok("--project", self.project, "launch", self.agent, "--detach", "--task", "Mail judge")
        assert result["state"] == "running", result
        self.session = result["session_id"]
        ready = json.loads((self.repo / "provider-ready.json").read_text())
        assert ready["session_discovery"] and ready["http_discovery"]
        if sys.platform == "linux":
            for pid in [ready["native_root_pid"], ready["helper_pid"]]:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
                self.processes.append((pid, fields[19]))

    def close(self):
        result = self.ok("down")
        assert result["complete"] and result["witness"]["state"] == "witnessed", result
        assert not (self.home / "endpoint.json").exists()
        for pid, birth in self.processes:
            try:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
                assert fields[19] != birth or fields[0] == "Z", "owned provider still live"
            except FileNotFoundError:
                pass


def run(f):
    f.launch()
    print("ok 1 - real launch, session pin and both discovery transports", flush=True)
    sent = f.mail("send", f.agent, "complete body " + "x" * 4096)
    (f.root / "sent.json").write_text(json.dumps(sent, indent=2))
    msg = sent["message_id"]
    inspection = f.mail("read", msg)
    assert inspection["inspection"] and not inspection["marked_read"], inspection
    print("ok 2 - owner inspection preserves recipient unread state", flush=True)
    small = f.call("--project", f.project, "msg", "read", msg, "--budget", "512", recipient=True)
    assert small.returncode != 0 and b"too-large" in small.stderr, (small.stdout, small.stderr)
    inbox = f.mail("list", "--full", recipient=True)
    (f.root / "inbox.json").write_text(json.dumps(inbox, indent=2))
    assert any(row["id"] == msg for row in inbox["items"]), inbox
    print("ok 3 - reply budget refusal leaves original message unread", flush=True)
    read = f.mail("read", msg, recipient=True)
    assert read["marked_read"] and read["marker"] == "new" and read["event_id"], read
    assert "x" * 4096 in json.dumps(read), "full body truncated"
    again = f.mail("ack", msg, recipient=True)
    assert again["marker"] == "already" and again["event_id"] == read["event_id"], (read, again)
    print("ok 4 - complete read and ack replay preserve original event", flush=True)
    unread = f.mail("list", recipient=True)
    assert all(row["id"] != msg for row in unread["items"]), unread
    print("ok 5 - finite unread list reflects the committed read marker", flush=True)
    sent2 = f.mail("send", f.agent, "dismiss without read")
    dismissed = f.mail("dismiss", sent2["message_id"], recipient=True)
    replay = f.mail("dismiss", sent2["message_id"], recipient=True)
    assert dismissed["marker"] == "new" and replay["marker"] == "already", (dismissed, replay)
    assert dismissed["event_id"] == replay["event_id"]
    print("ok 6 - dismiss retry preserves its natural receipt", flush=True)
    other = f.ok("--project", f.project, "agent", "add", "Other", "--provider", "claude", "--model", "claude-sonnet-5-5")
    (f.root / "other.json").write_text(json.dumps(other, indent=2))
    foreign = f.mail("send", other["agent"]["id"], "recipient-private-body")
    for verb in ["read", "ack", "dismiss"]:
        refused = f.call("--project", f.project, "msg", verb, foreign["message_id"], recipient=True)
        assert refused.returncode != 0 and b"recipient-private-body" not in refused.stdout, (verb, refused.stdout, refused.stderr)
    print("ok 7 - foreign read, ack and dismiss refuse without body disclosure", flush=True)
    large = f.mail("send", f.agent, "mcp budget body " + "z" * 30000)["message_id"]
    refused = f.rpc("stateengine_msg_read", {"msg_id": large})
    assert refused["isError"] and "too-large" in json.dumps(refused), refused
    assert any(row["id"] == large for row in f.mail("list", recipient=True)["items"])
    print("ok 8 - actual MCP envelope budget refuses before a read marker", flush=True)
    ack = f.rpc("stateengine_msg_ack", {"msg_id": large})
    assert not ack.get("isError", False), ack
    replay = f.mail("ack", large, recipient=True)
    assert replay["marker"] == "already" and replay["event_id"] == ack["structuredContent"]["event_id"], (ack, replay)
    print("ok 9 - MCP ack and CLI replay share the original natural receipt", flush=True)
    small = f.mail("send", f.agent, "MCP complete body")["message_id"]
    received = f.rpc("stateengine_msg_read", {"msg_id": small})
    assert not received.get("isError", False), received
    content = received["structuredContent"]
    assert content["message"]["body"]["complete"] and content["message"]["body"]["text"] == "MCP complete body", content
    replay = f.mail("read", small, recipient=True)
    assert replay["marker"] == "already" and replay["event_id"] == content["event_id"], (content, replay)
    print("ok 10 - complete MCP read and CLI replay share the original receipt", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    f = Fixture(args.se, args.output)
    print("1..11", flush=True)
    try:
        run(f)
    finally:
        f.close()
    print("ok 11 - witnessed shutdown and outside provider exit", flush=True)


if __name__ == "__main__":
    main()
