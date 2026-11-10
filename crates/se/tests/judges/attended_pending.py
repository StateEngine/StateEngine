"""Retained attended launch replies through the public CLI and MCP doors.

Uses the existing native protocol/window fixture. Readiness is released by a
file barrier, not a clock or store edit. No provider account is used. Linux
execution requires Xvfb, xterm and rustc; Windows qualification is separate.
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
import traceback
import uuid

from agent_create_cli import create, owner_grant
from attended_setup import Window, identity


class PendingWindow(Window):
    def call(self, *args, recipient=False, plain=False):
        if "launch" not in args or "--detach" in args:
            return super().call(*args, recipient=recipient)
        self.calls += 1
        environment = dict(self.env)
        if recipient:
            assert self.session
            environment["SE_SESSION"] = self.session
        command = [str(self.se), *([] if plain else ["--json"]),
                   "--home", str(self.home), *args]
        response = subprocess.run(
            ["script", "-q", "-e", "-c", shlex.join(command), "/dev/null"],
            env=environment, capture_output=True, timeout=65)
        base = self.log_root / f"call-{self.calls:02}"
        base.with_suffix(".stdout").write_bytes(response.stdout)
        base.with_suffix(".stderr").write_bytes(response.stderr)
        return response

    def request(self, door, agent, key, task, override=False):
        if door == "cli":
            response = self.call("--project", self.project, "--key", key,
                                 "launch", agent, "--task", task,
                                 *(["--override-live"] if override else []), recipient=True)
            return response.returncode == 0, json.loads(response.stdout)
        response = self.rpc("stateengine_agent_launch", {
            "target_agent_id": agent, "idempotency_key": key,
            "detach": False, "task": task, "override_live": override})
        return not response.get("isError", False), response["structuredContent"]


def state(value):
    return str(value.get("state", "")).lower().replace("_", "-")


def pending(value, project, agent, key, task, override=False):
    assert state(value) in ("starting", "setup-needed"), value
    assert value["idempotency_key"] == key, value
    assert value["project"]["id"] == project and value["agent"]["id"] == agent, value
    assert value["session_id"] and value["lifecycle_id"], value
    assert value["provider"] == "claude", value
    retry = value["retry"]
    assert retry["target_agent_id"] == agent and retry["idempotency_key"] == key, value
    assert retry["task"] == task and retry["detach"] is False, value
    assert retry.get("force", False) == override, value
    # These are activation/native facts, not required metadata for a pending job.
    for name in ("event_id", "conversation_id", "process", "containment"):
        assert name not in value, ("pending invented an unproved fact", name, value)


def native_markers(f):
    return {path.name: path.read_text() for path in f.repo.glob("native-*")}


def delayed(f, door, agent, key, task, override=False):
    before = native_markers(f)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        response = pool.submit(f.request, door, agent, key, task, override)
        until = time.monotonic() + 40
        observed = None
        while time.monotonic() < until:
            new = {name: text for name, text in native_markers(f).items()
                   if before.get(name) != text}
            if new:
                assert len(new) == 1, new
                name, text = next(iter(new.items()))
                observed = (name.removeprefix("native-"), int(text))
                f.processes.append((observed[1], identity(observed[1])[1]))
                break
            if response.done():
                ok, reply = response.result()
                assert ok, (door, reply)
            time.sleep(.05)
        ok, reply = response.result()
    assert ok, (door, reply)
    assert observed is not None, "retained launch never reached its native barrier"
    return reply, observed


def disconnect(f, agent, key, task):
    """Drop only our original MCP waiter after observing its native child."""
    before = native_markers(f)
    f.calls += 1
    base = f.log_root / f"call-{f.calls:02}"
    command = [str(f.se), "--home", str(f.home), "mcp"]
    request = {"jsonrpc": "2.0", "id": f.calls, "method": "tools/call", "params": {
        "name": "stateengine_agent_launch", "arguments": {
            "target_agent_id": agent, "idempotency_key": key, "detach": False, "task": task}}}
    with base.with_suffix(".stdout").open("xb") as out, base.with_suffix(".stderr").open("xb") as err:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err,
                                 env={**f.env, "SE_SESSION": f.session})
        birth = identity(child.pid)[1]
        observed = None
        try:
            child.stdin.write((json.dumps(request) + "\n").encode())
            child.stdin.flush()
            until = time.monotonic() + 40
            while time.monotonic() < until:
                assert child.poll() is None, "MCP waiter ended before native startup"
                new = {name: text for name, text in native_markers(f).items()
                       if before.get(name) != text}
                if new:
                    assert len(new) == 1, new
                    name, text = next(iter(new.items()))
                    observed = (name.removeprefix("native-"), int(text))
                    f.processes.append((observed[1], identity(observed[1])[1]))
                    break
                time.sleep(.02)
            assert observed is not None, "MCP request never reached native startup"
        finally:
            if child.poll() is None:
                proc = Path("/proc") / str(child.pid)
                assert identity(child.pid)[1] == birth
                assert (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0") == [
                    os.fsencode(part) for part in command], "owned waiter command changed"
                os.kill(child.pid, signal.SIGTERM)
            child.wait(timeout=10)
            child.stdin.close()
    assert identity(observed[1])[0] not in ("Z", "X"), "disconnect stopped the retained provider"
    return observed


def run(options):
    assert sys.platform == "linux", "this journey uses the qualified Linux terminal adapter"
    os.umask(0o077)
    options.output.mkdir(parents=True, exist_ok=False)
    f, error, closed = None, None, False
    checks = []

    def check(name):
        checks.append(name)
        print(f"ok {len(checks)} - {name}", flush=True)

    try:
        f = PendingWindow(options.se, options.output / "fixture")
        f.ok("up")
        parent = f.launch_window(release=True)
        assert parent["session"]["recorded_state"] == "activated", parent
        parent_session = f.session
        check("already-ready attended launch still reaches actual activation")
        owner_grant(f, True)
        for door in ("cli", "mcp"):
            ok, child = create(f, door, "Pending " + door.upper(), str(uuid.uuid4()))
            assert ok, child
            agent, key, task = child["agent"]["id"], str(uuid.uuid4()), "Retain this launch request"
            started = time.monotonic()
            first, (conversation, pid) = delayed(f, door, agent, key, task)
            pending(first, f.project, agent, key, task)
            assert time.monotonic() - started < 35, "pending response exhausted its bounded waiter"
            assert first["session_id"] != parent_session, "pending substituted the caller's old session"
            assert identity(pid)[0] not in ("Z", "X"), "pending reply abandoned the live provider"
            check(door + " returns typed retained pending without activation/native placeholders")
            opposite = "mcp" if door == "cli" else "cli"
            before = native_markers(f)
            ok, again = f.request(opposite, agent, key, task)
            assert ok, again
            pending(again, f.project, agent, key, task)
            for field in ("idempotency_key", "session_id", "lifecycle_id", "project", "agent"):
                assert again[field] == first[field], (field, first, again)
            assert native_markers(f) == before, "opposite-door retry spawned another provider"
            check(door + " pending retries through the other door with the original job identity")
            ok, refused = f.request(opposite, agent, key, "Different intent")
            assert not ok and "launch request key" in json.dumps(refused), refused
            assert native_markers(f) == before
            check(door + " changed intent refuses without replacing the retained provider")
            # Release exactly this conversation. Original readiness owners prove
            # both session and HTTP discovery, then authenticate activation.
            (f.repo / ("ready-" + conversation)).touch()
            until = time.monotonic() + 30
            while True:
                ok, active = f.request(opposite, agent, key, task)
                assert ok, active
                if state(active) == "running":
                    break
                assert time.monotonic() < until, active
                pending(active, f.project, agent, key, task)
            assert active["session_id"] == first["session_id"]
            assert active["lifecycle_id"] == first["lifecycle_id"]
            assert active["idempotency_key"] == key and active["conversation_id"] == conversation
            assert active["process"]["pid"] == pid and active["event_id"], active
            assert native_markers(f) == before
            check(door + " same retained job activates only after actual readiness")
            ok, replay = f.request(door, agent, key, task)
            assert ok and replay == active, (active, replay)
            check(door + " completed retry preserves the original full Running result")
            if door == "cli":
                before = native_markers(f)
                ok, refused = f.request("mcp", agent, str(uuid.uuid4()), task)
                assert not ok and native_markers(f) == before, refused
                check("ordinary live launch still refuses without takeover consent")
                predecessor_birth = identity(pid)[1]
                (f.repo / ("ready-" + conversation)).unlink()
                replacement_key = str(uuid.uuid4())
                replacement, (_, replacement_pid) = delayed(
                    f, "cli", agent, replacement_key, task, override=True)
                pending(replacement, f.project, agent, replacement_key, task, override=True)
                assert replacement["session_id"] != active["session_id"], replacement
                assert replacement["lifecycle_id"] != active["lifecycle_id"], replacement
                report = replacement["takeover"]
                assert report["previous_session"] == active["session_id"], report
                assert "witnessed" in report["witness"], report
                try:
                    old_state, observed_birth = identity(pid)
                    assert observed_birth != predecessor_birth or old_state in ("Z", "X"), \
                        "takeover left its predecessor executing"
                except FileNotFoundError:
                    pass
                assert (replacement_pid, identity(replacement_pid)[1]) != (pid, predecessor_birth)
                check("pending takeover keeps witnessed predecessor custody without stale Running facts")
                stopped = f.ok("--project", f.project, "stop", agent)
                assert stopped["complete"] and stopped["witness"]["state"] == "witnessed", stopped
                check("explicit stop joins the pending takeover lifecycle")
        ok, child = create(f, "mcp", "Disconnected pending", str(uuid.uuid4()))
        assert ok, child
        agent, key, task = child["agent"]["id"], str(uuid.uuid4()), "Keep custody after disconnect"
        conversation, pid = disconnect(f, agent, key, task)
        before = native_markers(f)
        ok, retained = f.request("cli", agent, key, task)
        assert ok, retained
        pending(retained, f.project, agent, key, task)
        assert native_markers(f) == before
        check("disconnected MCP waiter retains its one provider for original-key CLI retry")
        (f.repo / ("ready-" + conversation)).touch()
        ok, active = f.request("mcp", agent, key, task)
        assert ok and state(active) == "running", active
        assert active["session_id"] == retained["session_id"]
        assert active["lifecycle_id"] == retained["lifecycle_id"]
        assert active["process"]["pid"] == pid and active["conversation_id"] == conversation
        assert native_markers(f) == before
        check("disconnected launch activates the original lifecycle after real readiness")
        ok, child = create(f, "cli", "Failed pending", str(uuid.uuid4()))
        assert ok, child
        agent, key, task = child["agent"]["id"], str(uuid.uuid4()), "Keep startup failure truthful"
        first, (conversation, pid) = delayed(f, "cli", agent, key, task)
        pending(first, f.project, agent, key, task)
        birth, before = identity(pid)[1], native_markers(f)
        (f.repo / ("fail-" + conversation)).touch()
        until = time.monotonic() + 30
        while True:
            ok, failure = f.request("mcp", agent, key, task)
            if not ok:
                break
            assert time.monotonic() < until, "exited provider kept returning healthy pending"
            pending(failure, f.project, agent, key, task)
        assert "launch" in json.dumps(failure).lower(), failure
        try:
            observed_state, observed_birth = identity(pid)
            assert observed_birth != birth or observed_state in ("Z", "X"), failure
        except FileNotFoundError:
            pass
        ok, repeated = f.request("cli", agent, key, task)
        assert not ok and repeated["code"] == failure["code"], (failure, repeated)
        assert native_markers(f) == before
        check("known native startup failure stays failed across original-key CLI/MCP retries")
        # Exercise the human renderer on a separate retained request; JSON/MCP
        # cannot prove the plain output avoids invented process/event lines.
        ok, child = create(f, "cli", "Plain pending", str(uuid.uuid4()))
        assert ok, child
        before = native_markers(f)
        key = str(uuid.uuid4())
        response = f.call("--project", f.project, "--key", key, "launch",
                          child["agent"]["id"], recipient=True, plain=True)
        text = response.stdout.decode()
        assert response.returncode == 0 and key in text, (text, response.stderr)
        assert "starting" in text.lower() or "setup" in text.lower(), text
        for absent in ("Process: PID", "Event:", "Conversation:"):
            assert absent not in text, (absent, text)
        for name, value in native_markers(f).items():
            if before.get(name) != value:
                pid = int(value)
                f.processes.append((pid, identity(pid)[1]))
        check("plain attended pending output is useful without invented Running facts")
        stopped = f.ok("--project", f.project, "stop", child["agent"]["id"])
        assert stopped["complete"] and stopped["witness"]["state"] == "witnessed", stopped
        check("explicit stop closes the still-pending lifecycle with a real witness")
    except BaseException as failure:
        error = failure
        (options.output / "failure.txt").write_text(traceback.format_exc())
    finally:
        if f is not None:
            try:
                f.close()
                closed = True
                check("public shutdown witnesses exact providers and private display joined")
            except BaseException as failure:
                (options.output / "cleanup-failure.txt").write_text(traceback.format_exc())
                if error is None:
                    error = failure
        report = {"image_sha256": hashlib.sha256(options.se.read_bytes()).hexdigest(),
                  "checks": checks, "passed": len(checks), "failed": int(error is not None),
                  "closed": closed, "births": f.processes if f else [],
                  "windows": "UNRUN: separate native turn required", "macos": "UNQUALIFIED"}
        (options.output / "result.json").write_text(json.dumps(report, indent=2))
    if error is not None:
        raise error
    print(f"1..{len(checks)}\n{len(checks)} passed; 0 failed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args())
