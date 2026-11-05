"""Public CLI/MCP create-grant regression; uses mail_cli's native Claude double.
Run: python3 agent_create_cli.py --se RELEASE_SE --output NEW_OWNED_DIRECTORY
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import termios
import time
import uuid

from mail_cli import Fixture


def owner_grant(f, active):
    master, slave = pty.openpty()

    def terminal():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    command = [str(f.se), "--json", "--home", str(f.home), "--project", f.project,
               "config", "set", "agent." + f.agent + ".can-create", str(active).lower()]
    process = subprocess.Popen(command, cwd=f.repo, env=f.env, stdin=slave,
                               stdout=slave, stderr=slave, preexec_fn=terminal)
    os.close(slave)
    output = bytearray()
    try:
        until = time.monotonic() + 40
        while time.monotonic() < until:
            if select.select([master], [], [], .1)[0]:
                try:
                    block = os.read(master, 65536)
                except OSError:
                    break
                if not block:
                    break
                output.extend(block)
            elif process.poll() is not None:
                break
        process.wait(timeout=1)
    finally:
        os.close(master)
    (f.root / ("grant-" + str(active).lower() + ".stdout")).write_bytes(output)
    assert process.returncode == 0, output.decode()
    value = f.ok("--project", f.project, "config", "get",
                 "agent." + f.agent + ".can-create")
    assert value["value"] == {"state": "present", "value": active}, value


def create(f, door, name, key):
    if door == "cli":
        response = f.call("--project", f.project, "--key", key, "agent", "add",
                          name, "--provider", "claude", recipient=True)
        return response.returncode == 0, json.loads(response.stdout)
    response = f.rpc("stateengine_agent_create", {
        "name": name, "provider": "claude", "idempotency_key": key})
    return not response.get("isError", False), response["structuredContent"]


def agents(f):
    return {row["id"] for row in f.ok("--project", f.project, "agent", "list")["items"]}


def launch(f, door, agent, key, task):
    if door == "cli":
        return f.ok("--project", f.project, "--key", key, "launch", agent,
                    "--task", task, "--detach", recipient=True)
    response = f.rpc("stateengine_agent_launch", {
        "target_agent_id": agent, "task": task, "detach": True, "idempotency_key": key})
    assert not response.get("isError", False), response
    return response["structuredContent"]


def observe_child(f, receipt):
    until = time.monotonic() + 20
    while time.monotonic() < until:
        ready = json.loads((f.repo / "provider-ready.json").read_text())
        if ready["conversation"] == receipt["conversation_id"]:
            assert ready["session_discovery"] and ready["http_discovery"], ready
            assert ready["native_root_pid"] == receipt["process"]["pid"], (ready, receipt)
            for pid in [ready["native_root_pid"], ready["helper_pid"]]:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
                f.processes.append((pid, fields[19]))
            return
        time.sleep(.02)
    raise AssertionError("child never verified discovery under its own session")


def run(f):
    f.launch()
    attempts = [(door, door.upper() + " Child", str(uuid.uuid4())) for door in ["cli", "mcp"]]
    for door, name, key in attempts:
        ok, refused = create(f, door, name, key)
        assert not ok and refused["code"] == "owner-required", refused
    assert agents(f) == {f.agent}
    print("ok 1 - ungranted parent refused through both doors without child commits", flush=True)
    owner_grant(f, True)
    print("ok 2 - current owner grant committed through public terminal config and read back", flush=True)
    created = [(door, name, key, *create(f, door, name, key)) for door, name, key in attempts]
    (f.root / "granted-create.json").write_text(json.dumps(created, indent=2))
    assert all(row[3] for row in created), ("granted child creation refused", created)
    print("ok 3 - existing parent session creates CLI and MCP children under current grant", flush=True)
    children = set()
    for door, name, key, _, receipt in created:
        opposite = "mcp" if door == "cli" else "cli"
        ok, replay = create(f, opposite, name, key)
        assert ok and replay["event_id"] == receipt["event_id"], (receipt, replay)
        assert replay["agent"] == receipt["agent"], (receipt, replay)
        children.add(receipt["agent"]["id"])
    assert agents(f) == {f.agent, *children}
    print("ok 4 - opposite-door create retries retain each original child identity", flush=True)
    for index, (door, _, _, _, child) in enumerate(created, 5):
        key, task = str(uuid.uuid4()), "Launch the directly created " + door + " child"
        first = launch(f, door, child["agent"]["id"], key, task)
        assert first["state"] == "running", first
        observe_child(f, first)
        print(f"ok {index} - {door} child launched with native session and HTTP discovery", flush=True)
    owner_grant(f, False)
    for door in ["cli", "mcp"]:
        ok, refused = create(f, door, "Revoked " + door, str(uuid.uuid4()))
        assert not ok and refused["code"] == "owner-required", refused
    assert agents(f) == {f.agent, *children}
    print("ok 7 - revocation takes effect for both doors without child commits", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    f = Fixture(args.se, args.output)
    print("1..8", flush=True)
    try:
        run(f)
    finally:
        f.close()
    print("ok 8 - witnessed shutdown and independent exact provider exits", flush=True)


if __name__ == "__main__":
    main()
