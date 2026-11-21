"""Independent judge for paced mail wakes (#522).

With runtime.mail_wake_interval_seconds set, a burst that arrives while the
agent is idle after a wake must reach it as one later wake, no sooner than the
interval, and every message must be named in some notice. With the interval
at 0 (pacing off) the same burst wakes the agent repeatedly, so this fails.
Run: python3 mail_pacing.py --se SE --output NEW_DIRECTORY [--interval SECONDS]
"""
import argparse
import json
from pathlib import Path
import time

from judge_records import wait_json
from mail_cli import Fixture

BURST = 9
SPACING = 0.5


def captured(repo):
    path = repo / "captured-input.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def wait_for(repo, count, seconds):
    end = time.monotonic() + seconds
    while True:
        frames = captured(repo)
        if len(frames) >= count:
            return frames
        if time.monotonic() >= end:
            raise AssertionError(f"expected {count} delivered notices within {seconds}s, saw {len(frames)}")
        time.sleep(0.05)


def named(frames, ids):
    return [{message for message in ids if message in frame["text"]} for frame in frames]


def configure(fixture, interval):
    config = fixture.home / "config.toml"
    text = config.read_text()
    line = f"mail_wake_interval_seconds = {interval}\n"
    if "[runtime]\n" in text:
        text = text.replace("[runtime]\n", "[runtime]\n" + line, 1)
    else:
        text += "\n[runtime]\n" + line
    config.write_text(text)


def run(fixture, interval):
    configure(fixture, interval)
    fixture.launch()
    wait_json(fixture.repo / "provider-ready.json")
    end = time.monotonic() + 30
    while not (fixture.repo / "launch-turn-complete").exists():
        assert time.monotonic() < end, "the launch turn was not completed"
        time.sleep(0.05)
    print("ok 1 - launched with a turn-completing provider", flush=True)

    first = fixture.mail("send", fixture.agent, "pacing judge first message")["message_id"]
    frames = wait_for(fixture.repo, 1, 30)
    assert first in frames[0]["text"], "the first notice does not name the first message"
    print("ok 2 - the first message woke the idle agent", flush=True)

    burst = []
    for index in range(BURST):
        burst.append(fixture.mail("send", fixture.agent, f"pacing judge burst {index}")["message_id"])
        time.sleep(SPACING)
    frames = wait_for(fixture.repo, 2, interval + 30)
    # Allow any further wake to arrive before counting them.
    time.sleep(5)
    frames = captured(fixture.repo)
    everything = [first, *burst]
    per_frame = named(frames, everything)
    assert len(frames) == 2, f"the burst woke the agent {len(frames) - 1} times, expected once: {per_frame}"
    assert per_frame[1] == set(burst), f"the paced wake did not name exactly the burst: {per_frame}"
    assert set().union(*per_frame) == set(everything), "a message was never named in any notice"
    gap = frames[1]["monotonic"] - frames[0]["monotonic"]
    assert gap >= interval, f"the paced wake came {gap:.1f}s after the first, before the {interval}s interval"
    print(f"ok 3 - {BURST} messages reached the agent as one wake {gap:.1f}s after the first", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--interval", type=int, default=20)
    args = parser.parse_args()
    fixture = Fixture(args.se, args.output, provider_helper=Path(__file__).with_name("burst_provider.py"))
    print("1..4", flush=True)
    try:
        run(fixture, args.interval)
    finally:
        fixture.close()
    print("ok 4 - witnessed shutdown and outside provider exit", flush=True)


if __name__ == "__main__":
    main()
