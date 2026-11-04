"""Protects: post-launch mail reaches idle/busy native Claude input, while absent/stopped stays pending.
The provider waits for input and performs one finite inbox read per input, never polling.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid
from mail_cli import Fixture


def wait(check, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("public effect did not arrive before the bounded deadline")


def loaded(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def inputs(f):
    try:
        return [json.loads(line) for line in (f.repo / "provider-inputs.jsonl").read_text().splitlines()]
    except FileNotFoundError:
        return []


def send(f, owner, hold=False):
    marker = "wake-" + str(uuid.uuid4())
    # The command/body pattern is the audit's post-launch-wake-send case,
    # with only the private owner, agent, project, home and unique token changed.
    body = (f"Reply to owner {owner} with a done message containing exactly {marker}; "
            "this is a new post-launch task. Do not poll inbox or start a timer. "
            "Finish this turn after replying." + (" HOLD_BUSY" if hold else ""))
    key = str(uuid.uuid4())
    receipt = f.ok("--key", key, "--project", f.project, "msg", "send", f.agent, body, "--kind", "task")
    return receipt, marker, body, key


def reply(f, receipt, marker):
    def read():
        page = f.mail("list", "--full")
        return next((row for row in page["items"] if row["reply_to"] == receipt["message_id"]), None)
    row = wait(read)
    assert row["from"]["id"] == f.agent and row["body"]["complete"] and row["body"]["text"] == marker, row
    original = f.mail("read", receipt["message_id"])
    assert original["inspection"] and original["message"]["delivery"]["state"] == "delivered", original
    return row


def run(f):
    other = f.ok("--project", f.project, "agent", "add", "Absent", "--provider", "claude", "--model", "claude-sonnet-5-5")
    absent = f.mail("send", other["agent"]["id"], "Absent pending witness", "--kind", "task")
    assert absent["delivery"]["state"] == "pending", absent
    owner = absent["from"]["id"]
    os.mkfifo(f.repo / "busy-gate", 0o600)
    f.launch()
    ready = loaded(f.repo / "provider-ready.json")
    original_root = ready["native_root_pid"]
    wait(lambda: loaded(f.repo / "provider-idle.json"))
    assert len(inputs(f)) == 1
    first, token, body, key = send(f, owner)
    reply(f, first, token)
    wait(lambda: (loaded(f.repo / "provider-idle.json") or {}).get("sequence") == 2)
    replay = f.ok("--key", key, "--project", f.project, "msg", "send", f.agent, body, "--kind", "task")
    assert replay["event_id"] == first["event_id"] and replay["message_id"] == first["message_id"], replay
    time.sleep(0.3)  # Outside observer only: the provider has no timer or polling.
    assert len(inputs(f)) == 2, "keyed send retry delivered duplicate provider input"
    print("ok 1 - idle recipient woke on its existing native input and keyed retry stayed single", flush=True)
    busy, busy_token, _, _ = send(f, owner, hold=True)
    wait(lambda: loaded(f.repo / "provider-busy.json"))
    before = len(inputs(f))
    queued, queued_token, _, _ = send(f, owner)
    try:
        assert queued["delivery"]["state"] == "pending", queued
        time.sleep(0.5)
        assert len(inputs(f)) == before, "busy provider received mail before its turn boundary"
    finally:
        descriptor = os.open(f.repo / "busy-gate", os.O_WRONLY | os.O_NONBLOCK)
        os.write(descriptor, b"!")
        os.close(descriptor)
    reply(f, busy, busy_token)
    reply(f, queued, queued_token)
    wait(lambda: (loaded(f.repo / "provider-idle.json") or {}).get("sequence") == before + 1)
    assert loaded(f.repo / "provider-ready.json")["native_root_pid"] == original_root, "mail replaced the live provider"
    assert len(inputs(f)) == before + 1
    print("ok 2 - busy mail queued until the real result boundary, then reached the same provider", flush=True)
    stopped = f.ok("--project", f.project, "stop", f.agent)
    assert stopped["complete"], stopped
    pending = f.mail("send", f.agent, "Stopped pending witness", "--kind", "task")
    assert pending["delivery"]["state"] == "pending", pending
    assert f.mail("read", absent["message_id"])["message"]["delivery"]["state"] == "pending"
    assert f.mail("read", pending["message_id"])["message"]["delivery"]["state"] == "pending"
    print("ok 3 - absent and stopped recipients remain honestly pending", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    f = Fixture(args.se, args.output, Path(__file__).with_name("live_mail_provider.py"))
    failure = cleanup = None
    try:
        run(f)
    except Exception as caught:
        failure = repr(caught)
    finally:
        # Release a blocked fixture even when the behavior assertion fails.
        try:
            descriptor = os.open(f.repo / "busy-gate", os.O_WRONLY | os.O_NONBLOCK)
            os.write(descriptor, b"!")
            os.close(descriptor)
        except OSError:
            pass
        try:
            f.close()
        except Exception as caught:
            cleanup = repr(caught)
    result = {"failure":failure,"cleanup_failure":cleanup}
    (f.root / "results.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result), flush=True)
    return int(bool(failure or cleanup))


if __name__ == "__main__":
    sys.exit(main())
