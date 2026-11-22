"""Independent judge for an agent's background processes in status (#522).

An idle Claude agent that leaves a process running shows state "background" and
a count one higher than before; the count drops back once the process ends; and
the process's arguments never appear anywhere in status.
Run: python3 background_status.py --se SE --output NEW_DIRECTORY
"""
import argparse
import json
from pathlib import Path
import time

from background_provider import SECRET
from mail_cli import Fixture


def row(fixture):
    status = fixture.ok("--project", fixture.project, "status")
    rows = [item for item in status["agents"]["items"] if item["id"] == fixture.agent]
    assert len(rows) == 1, status
    return rows[0], json.dumps(status)


def readable(fixture):
    agent, _ = row(fixture)
    return (agent.get("background") or {}).get("state") == "present"


def count(fixture):
    agent, _ = row(fixture)
    background = agent.get("background") or {}
    assert background.get("state") == "present", f"background is not readable: {background}"
    return background["value"]["processes"]


def until(predicate, seconds, what):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= end:
            raise AssertionError(f"deadline waiting for {what}")
        time.sleep(0.2)


def turn(fixture, control, body):
    (fixture.repo / control).write_text("go")
    fixture.mail("send", fixture.agent, body)
    until(lambda: not (fixture.repo / control).exists(), 30, f"the provider to obey {control}")


def run(fixture):
    fixture.launch()
    until(lambda: (fixture.repo / "launch-turn-complete").exists(), 30, "the launch turn")
    # Right after launch the runtime may still hold the session for setup.
    until(lambda: readable(fixture), 30, "the agent's background to be readable")
    before = count(fixture)
    print(f"ok 1 - an idle agent reports {before} background processes (the double's own helper)", flush=True)

    turn(fixture, "spawn-background", "start a long job")
    until(lambda: count(fixture) == before + 1, 20, "the new background process to be counted")
    agent, text = row(fixture)
    assert agent["state"]["state"] == "background", f"state is {agent['state']}"
    assert agent["state"]["since"], "a background state names when its oldest process started"
    oldest = agent["background"]["value"]["oldest"]
    assert oldest and " " not in oldest["command"] and "/" not in oldest["command"], oldest
    assert SECRET not in text, "a background process argument appeared in status"
    print("ok 2 - the job is counted, the agent reads background, and no argument is shown", flush=True)

    turn(fixture, "stop-background", "the job is done")
    until(lambda: count(fixture) == before, 20, "the background count to drop back")
    print("ok 3 - the count drops back once the job ends", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Fixture(args.se, args.output, provider_helper=Path(__file__).with_name("background_provider.py"))
    print("1..4", flush=True)
    try:
        run(fixture)
    finally:
        fixture.close()
    print("ok 4 - witnessed shutdown and outside provider exit", flush=True)


if __name__ == "__main__":
    main()
