"""Protects: `se agent wake` and its MCP twin arm one running agent's mail
delivery pass and report the committed offer, staying honest when nothing can
be offered. Quiet mail is never pushed; the agent picks it up at its next
inbox read. Wake never launches a process and never claims the mail was read
or acted on.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from mail_cli import Fixture


def wait(check, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("public effect did not arrive before the bounded deadline")


def inputs(f):
    try:
        return [json.loads(line) for line in (f.repo / "provider-inputs.jsonl").read_text().splitlines()]
    except FileNotFoundError:
        return []


def idle_seq(f):
    try:
        return json.loads((f.repo / "provider-idle.json").read_text())["sequence"]
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def release_gate(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
    try:
        os.write(descriptor, b"!")
    finally:
        os.close(descriptor)


def rpc_raw(f, name, arguments):
    f.calls += 1
    environment = {**f.env, "SE_SESSION": f.session}
    request = {"jsonrpc": "2.0", "id": f.calls, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
    result = subprocess.run([str(f.se), "--home", str(f.home), "mcp"],
                            input=(json.dumps(request) + "\n").encode(), env=environment,
                            capture_output=True, timeout=30)
    base = f.log_root / f"call-{f.calls:02}"
    base.with_suffix(".stdout").write_bytes(result.stdout)
    base.with_suffix(".stderr").write_bytes(result.stderr)
    assert result.returncode == 0, (result.stdout, result.stderr)
    reply = json.loads(result.stdout)
    assert "result" in reply, reply
    return reply["result"]


def assert_no_counts(receipt):
    assert not any("count" in key.lower() or "unread" in key.lower() for key in receipt), receipt


def reply(f, receipt, marker):
    def read():
        page = f.mail("list", "--full")
        return next((row for row in page["items"] if row["reply_to"] == receipt["message_id"]), None)
    row = wait(read)
    assert row["from"]["id"] == f.agent and row["body"]["complete"] and row["body"]["text"] == marker, row
    return row


def run(f):
    gate = f.repo / "busy-gate"
    os.mkfifo(gate, 0o600)
    absent = f.ok("--project", f.project, "agent", "add", "Absent", "--provider", "claude",
                  "--model", "claude-sonnet-5-5")["agent"]["id"]
    other = f.ok("--project", f.project, "agent", "add", "Other", "--provider", "claude",
                 "--model", "claude-sonnet-5-5")["agent"]["id"]
    f.launch()
    wait(lambda: idle_seq(f) == 1)
    baseline = len(inputs(f))
    assert baseline == 1, baseline
    print("ok 1 - the real launch brings up the runtime the wake coordinator needs", flush=True)
    # The runtime is running but the target has no process: honest refusal, no spawn.
    refused = f.call("--project", f.project, "agent", "wake", "Absent")
    assert refused.returncode == 1, (refused.stdout, refused.stderr)
    receipt = json.loads(refused.stdout)
    assert receipt["schema"] == "se.wake/v1" and receipt["outcome"] == "refused", receipt
    assert receipt["lifecycle"]["state"] == "not_running" and receipt["offer"] is None, receipt
    assert "no running process" in receipt["detail"] and "Launch" in receipt["remedy"], receipt
    assert_no_counts(receipt)
    assert len(inputs(f)) == baseline, "wake of an absent agent wrote provider frames"
    print("ok 2 - wake of an absent agent refuses honestly without spawning", flush=True)
    seed = f.mail("send", absent, "owner identity seed", "--kind", "task")
    assert seed["delivery"]["state"] == "pending", seed
    owner = seed["from"]["id"]
    assert owner.startswith("hu_"), owner
    # This task is delivered to the idle provider, which blocks on the gate
    # mid-turn until the judge releases it: a real, held busy turn.
    busy_marker = "wake-" + str(uuid.uuid4())
    busy = f.mail("send", f.agent,
                  (f"HOLD_BUSY. Reply to owner {owner} with a done message containing exactly "
                   f"{busy_marker}; finish this turn after replying."),
                  "--kind", "task")
    def held():
        try:
            (f.repo / "provider-busy.json").read_text()
            return True
        except FileNotFoundError:
            return None
    wait(held, seconds=40)
    marker = "wake-" + str(uuid.uuid4())
    sent = f.mail("send", f.agent,
                  (f"Reply to owner {owner} with a done message containing exactly {marker}; "
                   "this is a new post-launch task. Finish this turn after replying."),
                  "--kind", "task")
    assert sent["delivery"]["state"] == "pending", sent
    assert len(inputs(f)) == baseline + 1, "the busy provider consumed the queued mail early"
    quiet_marker = "wake-" + str(uuid.uuid4())
    quiet = f.mail("send", f.agent,
                   (f"Reply to owner {owner} with a done message containing exactly {quiet_marker}; "
                    "this is a new post-launch task. Finish this turn after replying."),
                   "--kind", "task", "--no-wake")
    assert quiet["delivery"]["state"] == "pending", quiet
    assert len(inputs(f)) == baseline + 1, "--no-wake notified the provider"
    # Arm the delivery pass in a separate process, then release the held turn
    # inside the wait window: the boundary offer must commit while it is open.
    started = time.monotonic()
    process = subprocess.Popen([str(f.se), "--json", "--home", str(f.home),
                                "--project", f.project, "agent", "wake", f.agent],
                               env=dict(f.env), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL)
    time.sleep(0.2)
    release_gate(gate)
    stdout, stderr = process.communicate(timeout=60)
    finished = time.monotonic()
    assert process.returncode == 0, (stdout, stderr, finished - started)
    offered = json.loads(stdout)
    assert offered["schema"] == "se.wake/v1" and offered["outcome"] == "offered", offered
    assert offered["agent"]["id"] == f.agent, offered
    assert offered["lifecycle"]["state"] == "running", offered
    assert offered["lifecycle"]["session"] == f.session, offered
    assert offered["offer"]["kind"] == "transport-written", offered
    assert offered["offer"]["transport"] == "stdio", offered
    assert offered["offer"]["bytes"] > 0, offered
    assert_no_counts(offered)
    print("ok 3 - wake armed the pass, the released turn offered the queued mail exactly once",
          flush=True)
    reply(f, busy, busy_marker)
    reply(f, sent, marker)
    def delivered():
        original = f.mail("read", sent["message_id"])
        message = original["message"]
        return original if (message["delivery"]["state"] == "delivered"
                            and message["disposition"]["state"] == "read") else None
    wait(delivered)
    assert len(inputs(f)) == baseline + 2, inputs(f)
    print("ok 4 - the held turn finished, the boundary offer reached the same provider", flush=True)
    assert not any(quiet_marker in json.dumps(frame) for frame in inputs(f)), \
        "quiet mail was pushed to the provider"
    quiet_read = f.mail("read", quiet["message_id"])
    message = quiet_read["message"]
    assert message["delivery"]["state"] == "pending" and message["disposition"]["state"] == "read", \
        message
    print("ok 5 - quiet mail was never pushed and was picked up at the next inbox read",
          flush=True)
    again = f.call("--project", f.project, "agent", "wake", f.agent)
    assert again.returncode == 2, (again.stdout, again.stderr)
    pending = json.loads(again.stdout)
    assert pending["outcome"] == "pending" and pending["offer"] is None, pending
    assert pending["lifecycle"]["state"] == "running" and pending["detail"], pending
    assert_no_counts(pending)
    print("ok 6 - a second wake without pending mail reports pending without leaking counts",
          flush=True)
    twin = rpc_raw(f, "stateengine_agent_wake", {"target_agent_id": f.agent})
    assert not twin.get("isError", False), twin
    content = twin["structuredContent"]
    assert content["outcome"] == "pending" and content["agent"]["id"] == f.agent, content
    assert_no_counts(content)
    print("ok 7 - the MCP twin carries the same honest pending verdict", flush=True)
    foreign = rpc_raw(f, "stateengine_agent_wake", {"target_agent_id": other})
    assert foreign.get("isError", False), "a non-creator may control a foreign agent: " + json.dumps(foreign)
    error = json.dumps(foreign).lower()
    assert "control" in error or "choose" in error or "wake target" in error, foreign
    assert_no_counts(foreign["structuredContent"])
    print("ok 8 - a foreign target is refused by the store control port", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    f = Fixture(args.se, args.output, Path(__file__).with_name("live_mail_provider.py"), log_directory="calls")
    failure = cleanup = None
    try:
        run(f)
    except Exception as caught:
        failure = repr(caught)
    finally:
        try:
            release_gate(f.repo / "busy-gate")
        except OSError:
            pass
        try:
            f.close()
        except Exception as caught:
            cleanup = repr(caught)
    result = {"failure": failure, "cleanup_failure": cleanup}
    (f.root / "results.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result), flush=True)
    return int(bool(failure or cleanup))


if __name__ == "__main__":
    sys.exit(main())
