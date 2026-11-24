"""Independent judge for the captain's quiet-crew nudge.

Under a captain, a crew agent that completes turns on an open assignment
without sending a message, saving a note or updating the assignment is nudged
exactly `captain_nudge_attempts` times, at least the idle interval apart; then
its captain gets one stuck alert and the nudges stop. While a process the agent
left running is still alive it is not nudged at all. A message from the agent
resets the streak, so nudging resumes. The provider is a script, so it runs
under StateEngine's supervisor and an idle agent has no background process.
Run: python3 captain_nudge.py --se SE --output NEW_DIRECTORY [--idle SECONDS]
"""
import argparse
import json
from pathlib import Path
import time
import uuid

from background_status import script_provider
from mail_cli import Fixture

ATTEMPTS = 2
NUDGE_TEXT = "You have an open assignment and have been idle."


def key():
    return str(uuid.uuid4())


def configure(fixture, idle):
    config = fixture.home / "config.toml"
    text = config.read_text()
    lines = f"captain_nudge_idle_seconds = {idle}\ncaptain_nudge_attempts = {ATTEMPTS}\n"
    if "[runtime]\n" in text:
        text = text.replace("[runtime]\n", "[runtime]\n" + lines, 1)
    else:
        text += "\n[runtime]\n" + lines
    config.write_text(text)


def frames(repo):
    path = repo / "captured-input.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def nudge_frames(fixture, cache):
    """Delivered notices that name a nudge, each with the nudge ids it names."""
    found = []
    for frame in frames(fixture.repo):
        named = []
        for word in frame["text"].replace('"', " ").split():
            if not word.startswith("msg_"):
                continue
            if word not in cache:
                body = fixture.mail("read", word)
                cache[word] = NUDGE_TEXT in json.dumps(body)
            if cache[word]:
                named.append(word)
        if named:
            found.append((frame, named))
    return found


def alerts(fixture, captain):
    page = fixture.mail("list", "--to", captain, "--kind", "blocker")
    return page["items"]


def wait_until(predicate, seconds, what):
    end = time.monotonic() + seconds
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= end:
            raise AssertionError(f"deadline waiting for {what}")
        time.sleep(0.2)


def run(fixture, idle):
    configure(fixture, idle)
    lead = fixture.ok("--key", key(), "--project", fixture.project, "agent", "add", "Lead",
                      "--provider", "claude", "--model", "claude-sonnet-5-5")["agent"]["id"]
    fixture.ok("--key", key(), "--project", fixture.project, "captain", "set", lead)
    fixture.ok("--key", key(), "--project", fixture.project, "assignment", "write", "--action", "open",
               "--assignee", fixture.agent, "--body", "Judge assignment that the crew never reports on")
    script_provider(fixture)
    # The agent's first turn (the assignment notice) starts a long-running job.
    (fixture.repo / "spawn-background").write_text("go")
    fixture.launch()
    wait_until(lambda: (fixture.repo / "launch-turn-complete").exists(), 30, "the launch turn")
    wait_until(lambda: (fixture.repo / "background-pid").exists(), 30, "the background job to start")
    print("ok 1 - a captain, an open assignment and a crew agent with a job still running", flush=True)

    cache = {}
    background_wait = idle * 2 + 1
    time.sleep(background_wait)
    assert not nudge_frames(fixture, cache), "an agent with a running background job was nudged"
    (fixture.repo / "stop-background").write_text("go")
    fixture.mail("send", fixture.agent, "Wrap up the job")
    wait_until(lambda: not (fixture.repo / "background-pid").exists(), 30, "the background job to stop")
    print(f"ok 2 - no nudge for {background_wait} s while the job ran", flush=True)

    nudged = wait_until(lambda: len(nudge_frames(fixture, cache)) >= ATTEMPTS and nudge_frames(fixture, cache),
                        idle * (ATTEMPTS + 3) + 30, f"{ATTEMPTS} nudges")
    alert = wait_until(lambda: alerts(fixture, lead), idle * 3 + 30, "the stuck alert")
    time.sleep(idle * 2 + 1)
    nudged = nudge_frames(fixture, cache)
    assert len(nudged) == ATTEMPTS, f"expected exactly {ATTEMPTS} nudges before the alert, saw {len(nudged)}"
    gaps = [b[0]["monotonic"] - a[0]["monotonic"] for a, b in zip(nudged, nudged[1:])]
    assert all(gap >= idle - 0.5 for gap in gaps), f"nudges came faster than the {idle}s interval: {gaps}"
    alert = alerts(fixture, lead)
    assert len(alert) == 1, f"expected one stuck alert to the captain, saw {len(alert)}"
    print(f"ok 3 - {ATTEMPTS} nudges {gaps} s apart, then one stuck alert and no further nudge", flush=True)

    fixture.rpc("stateengine_msg_send", {"to": lead, "body": "Still on it", "kind": "note",
                                         "idempotency_key": key()})
    wait_until(lambda: len(nudge_frames(fixture, cache)) > ATTEMPTS, idle * 2 + 30, "a nudge after the reset")
    print("ok 4 - a message from the agent resets the streak and nudging resumes", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--idle", type=int, default=2)
    args = parser.parse_args()
    fixture = Fixture(args.se, args.output, provider_helper=Path(__file__).with_name("background_provider.py"))
    print("1..5", flush=True)
    try:
        run(fixture, args.idle)
    finally:
        fixture.close()
    print("ok 5 - witnessed shutdown and outside provider exit", flush=True)


if __name__ == "__main__":
    main()
