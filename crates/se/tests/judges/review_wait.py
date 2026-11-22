"""Independent judge for the "review" state (#522).

An idle agent whose last outgoing message is a floor work handoff (admit) to a
named agent reads state "review", naming that agent, the handoff's first line
and when it was handed. A direct reply from the addressee clears it, and so
does an addressee's floor message that names the agent.
Run: python3 review_wait.py --se SE --output NEW_DIRECTORY
"""
import argparse
from pathlib import Path
import time
import uuid

from background_status import script_provider
from judge_records import wait_json
from mail_cli import Fixture


def key():
    return str(uuid.uuid4())


def state(fixture):
    status = fixture.ok("--project", fixture.project, "status")
    rows = [row for row in status["agents"]["items"] if row["id"] == fixture.agent]
    assert len(rows) == 1, status
    return rows[0]["state"]


def until(predicate, seconds, what):
    end = time.monotonic() + seconds
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= end:
            raise AssertionError(f"deadline waiting for {what}")
        time.sleep(0.25)


def launch_reviewer(fixture):
    """Launch the second agent first, keeping its own session for its replies."""
    reviewer = fixture.ok("--key", key(), "--project", fixture.project, "agent", "add", "Reviewer",
                          "--provider", "claude", "--model", "claude-sonnet-5-5")["agent"]["id"]
    launched = fixture.ok("--project", fixture.project, "launch", reviewer, "--detach", "--task", "Review judge")
    assert launched["state"] == "running", launched
    wait_json(fixture.repo / "provider-ready.json")
    (fixture.repo / "provider-ready.json").rename(fixture.repo / "reviewer-ready.json")
    (fixture.repo / "launch-turn-complete").unlink()
    return reviewer, launched["session_id"]


def send_as(fixture, session, arguments):
    own = fixture.session
    fixture.session = session
    try:
        result = fixture.rpc("stateengine_msg_send", {"idempotency_key": key(), **arguments})
        assert not result.get("isError"), f"the send was refused: {result.get('structuredContent')}"
        return result
    finally:
        fixture.session = own


def handoff(fixture, reviewer):
    send_as(fixture, fixture.session, {"to": "floor", "kind": "handoff", "work": {"action": "admit", "addressees": [reviewer]},
                                       "body": "PR #999 is ready for review\nsecond line stays out of status"})
    return until(lambda: (lambda s: s if s["state"] == "review" else None)(state(fixture)), 30,
                 "the author to read review")


def run(fixture):
    # A script provider runs under StateEngine's own supervisor, as an npm
    # Claude Code does, so an idle agent counts no background processes.
    script_provider(fixture)
    reviewer, reviewer_session = launch_reviewer(fixture)
    fixture.launch()
    until(lambda: (fixture.repo / "launch-turn-complete").exists(), 30, "the author's launch turn")
    until(lambda: state(fixture)["state"] == "idle", 30, "the author to read idle")
    print("ok 1 - an author and a reviewer are running, the author idle", flush=True)

    waiting = handoff(fixture, reviewer)
    review = waiting["review"]
    assert review["to"] == ["Reviewer"], review
    assert review["summary"] == "PR #999 is ready for review", review
    assert waiting["since"] == review["handed_at"] and waiting["elapsed_seconds"] is not None, waiting
    print("ok 2 - a floor handoff makes the author read review, naming the reviewer and its first line", flush=True)

    send_as(fixture, reviewer_session, {"to": fixture.agent, "kind": "answer", "body": "Looks good"})
    until(lambda: state(fixture)["state"] != "review", 30, "a direct reply to clear review")
    print("ok 3 - a direct reply from the reviewer clears it", flush=True)

    handoff(fixture, reviewer)
    send_as(fixture, reviewer_session, {"to": "floor", "kind": "done", "work": {"action": "notify", "addressees": [fixture.agent]},
                                        "body": "Verdict on the floor"})
    until(lambda: state(fixture)["state"] != "review", 30, "a floor reply naming the author to clear review")
    print("ok 4 - a floor reply that names the author clears it too", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Fixture(args.se, args.output, provider_helper=Path(__file__).with_name("background_provider.py"))
    print("1..5", flush=True)
    try:
        run(fixture)
    finally:
        fixture.close()
    print("ok 5 - witnessed shutdown and outside provider exit", flush=True)


if __name__ == "__main__":
    main()
