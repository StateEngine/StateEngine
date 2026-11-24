"""Reviewer judge for temporary agents on a real host (public CLI and MCP).

A temporary child of the saved agent stops when its parent stops, within the
parent's stop budget, and stays usable. `se down` stops it and keeps it. The
host retires a child whose time limit passed while it was down, at startup,
and one whose limit passes while it runs, on its deadline. A retired child
refuses launch, resume, force, wake, owner mail and peer mail by name.
Run: python3 ephemeral_host_review.py --se SE --helper TEST_BINARY --output NEW_DIRECTORY
"""
import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid

from judge_records import wait_json
from mail_cli import Fixture

STOP_BUDGET_SECONDS = 10
# Stopping a parent may also gracefully stop its child, one after the other.
# A cascade that waits on the parent's own lock adds a 15 s stall instead.
CASCADE_SLACK_SECONDS = 3.5


def until(predicate, seconds, what):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= end:
            raise AssertionError(f"deadline waiting for {what}")
        time.sleep(0.2)


def alive(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
    except FileNotFoundError:
        return False
    return state != "Z"


class Review:
    def __init__(self, fixture, helper):
        self.f, self.helper = fixture, helper
        init = json.loads((fixture.log_root / "call-01.stdout").read_text())
        self.owner = init["owner"]["human_id"]

    def inject(self, name, ttl):
        out = self.f.root / f"injected-{name}"
        environment = {**self.f.env, "REVIEW_STATE": str(self.f.home), "REVIEW_PROJECT": self.f.project,
                       "REVIEW_OWNER": self.owner, "REVIEW_PARENT": self.f.agent, "REVIEW_NAME": name,
                       "REVIEW_TTL": str(ttl), "REVIEW_OUT": str(out)}
        result = subprocess.run([str(self.helper), "--exact", "inject_temporary_agent", "--ignored"],
                                env=environment, capture_output=True, timeout=60)
        assert result.returncode == 0, (result.stdout.decode(), result.stderr.decode())
        return out.read_text().strip()

    def run(self, *args):
        return self.f.ok("--project", self.f.project, *args)

    def launch(self, agent):
        ready = self.f.repo / "provider-ready.json"
        ready.unlink(missing_ok=True)
        launched = self.run("launch", agent, "--detach", "--task", "Temporary agent review")
        assert launched["state"] == "running", launched
        return launched, wait_json(ready)["helper_pid"]

    def refused(self, *args):
        result = self.f.call("--project", self.f.project, *args)
        text = result.stdout.decode() + result.stderr.decode()
        assert result.returncode != 0, (args, text)
        assert "retired" in text and "handoff export" in text, (args, text)

    def listed(self, include_temp=False):
        args = ["agent", "list", "--limit", "100"] + (["--include-temp"] if include_temp else [])
        return {row["id"] for row in self.run(*args)["items"]}

    def host_pid(self):
        endpoint = json.loads((self.f.home / "endpoint.json").read_text())
        return endpoint["epoch"]["owner"]["pid"]


def retired_refusals(review, expired):
    review.refused("launch", expired, "--detach")
    review.refused("launch", expired, "--detach", "--resume")
    review.refused("launch", expired, "--detach", "--force")
    review.refused("agent", "wake", expired)
    review.refused("msg", "send", expired, "late owner mail")
    peer = review.f.rpc("stateengine_msg_send", {"to": expired, "body": "late peer mail",
                                                 "idempotency_key": str(uuid.uuid4())})
    assert peer.get("isError") is True and "retired" in json.dumps(peer), peer


def run(review):
    helper = review.inject("Helper", 3600)
    expired = review.inject("Expired", 1)
    time.sleep(2.5)
    timed = review.inject("Timed", 20)
    print("ok 1 - three temporary children recorded while the host is down", flush=True)

    parent, parent_pid = review.launch(review.f.agent)
    review.f.session = parent["session_id"]
    host = review.host_pid()
    retired_refusals(review, expired)
    assert expired not in review.listed() and expired in review.listed(include_temp=True)
    print("ok 2 - startup retires the expired child; it refuses launch, resume, force, wake and mail", flush=True)

    # The baseline is a saved agent with no temporary children.
    other = review.run("agent", "add", "Baseline", "--provider", "claude",
                       "--model", "claude-sonnet-5-5")["agent"]["id"]
    _, other_pid = review.launch(other)
    started = time.monotonic()
    review.run("stop", other)
    alone = time.monotonic() - started
    until(lambda: not alive(other_pid), STOP_BUDGET_SECONDS, "the childless agent to stop")
    _, child_pid = review.launch(helper)
    started = time.monotonic()
    review.run("stop", review.f.agent)
    elapsed = time.monotonic() - started
    budget = 2 * alone + CASCADE_SLACK_SECONDS
    assert elapsed < budget, f"stopping the parent took {elapsed:.1f}s; alone it took {alone:.1f}s"
    until(lambda: not alive(child_pid), STOP_BUDGET_SECONDS, "the temporary child to stop with its parent")
    assert not alive(parent_pid), "the parent provider survived its stop"
    assert helper in review.listed(), "the parent's end retired its temporary child"
    print(f"ok 3 - the parent stopped in {elapsed:.1f}s (alone {alone:.1f}s) and stopped, not retired, the child", flush=True)

    until(lambda: timed not in review.listed(), 60, "the running host to retire the child on its deadline")
    assert timed in review.listed(include_temp=True)
    assert review.host_pid() == host, "the host restarted instead of retiring on its deadline"
    print("ok 4 - the running host retires a child when its time limit passes", flush=True)

    _, parent_pid = review.launch(review.f.agent)
    _, child_pid = review.launch(helper)
    down = review.f.ok("down")
    assert down["complete"] and down["witness"]["state"] == "witnessed", down
    assert not alive(child_pid) and not alive(parent_pid), "a provider survived se down"
    assert helper in review.listed(), "se down retired a live temporary child"
    _, child_pid = review.launch(helper)
    print("ok 5 - se down stops a live child and keeps it usable", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Fixture(args.se, args.output)
    print("1..6", flush=True)
    try:
        run(Review(fixture, args.helper.resolve()))
    finally:
        fixture.close()
    print("ok 6 - witnessed shutdown", flush=True)


if __name__ == "__main__":
    main()
