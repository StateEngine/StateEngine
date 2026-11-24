"""Reviewer acceptance judge for one-shot temporary agents on a real host.

Drives the public CLI and MCP with a native Claude protocol double
(delegate_provider.py); no paid provider account or database edits are needed.
Run: python3 delegate_acceptance.py --se SE --output NEW_OWNED_DIRECTORY
"""
import argparse
import concurrent.futures
import json
from pathlib import Path
import subprocess
import time
import uuid

from agent_create_cli import owner_grant
from judge_records import read_json, wait_json
from mail_cli import Fixture
from provider_home import run_provider_command

PROVIDER = Path(__file__).with_name("delegate_provider.py")
NOTICE = "[StateEngine automated notice]"


def until(probe, what, seconds=60):
    end = time.monotonic() + seconds
    while True:
        value = probe()
        if value:
            return value
        if time.monotonic() >= end:
            raise AssertionError("deadline: " + what)
        time.sleep(0.2)


def edit_config(f, old, new):
    config = f.home / "config.toml"
    text = config.read_text()
    assert old in text, (old, text)
    config.write_text(text.replace(old, new, 1))


def append_config(f, section):
    config = f.home / "config.toml"
    config.write_text(config.read_text() + "\n" + section)


def task(tag, mode):
    return f"DELEGATE-CHILD:{mode}:{tag} judge task"


def delegate(f, tag, mode, *extra, key=None, recipient=False):
    return f.call("--project", f.project, "--key", key or str(uuid.uuid4()), "delegate",
                  "--task", task(tag, mode), "--role", "judge", *extra, recipient=recipient)


def delegated(f, tag, mode, *extra, key=None, recipient=False):
    result = delegate(f, tag, mode, *extra, key=key, recipient=recipient)
    assert result.returncode == 0, (tag, result.stdout.decode(), result.stderr.decode())
    return json.loads(result.stdout)


def refused(result, code):
    assert result.returncode != 0, result.stdout.decode()
    error = json.loads(result.stdout)
    assert error["code"] == code, error
    return error


def history(f, kind):
    page = f.ok("--project", f.project, "history", "--kind", kind, "--limit", "100")
    assert page["window"]["complete"] and page["next"] is None, page["window"]
    return page["items"]


def retirement(f, agent):
    rows = [row for row in history(f, "agent.retired") if row["payload"]["agent"]["id"] == agent]
    assert len(rows) <= 1, rows
    return rows[0] if rows else None


def notices(f, agent):
    return [row for row in history(f, "message.sent")
            if row["payload"]["body"]["text"].startswith(NOTICE)
            and f"({agent})" in row["payload"]["body"]["text"]]


def temporary_names(f, *extra):
    page = f.ok("--project", f.project, "agent", "list", *extra)
    return {row["name"] for row in page["items"] if str(row.get("name", "")).startswith("tmp-")}


def child_ready(f, tag):
    return wait_json(f.repo / f"child-{tag}-ready.json", seconds=60)


def child_turns(f, tag):
    path = f.repo / f"child-{tag}-input.jsonl"
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines()
            if json.loads(line).get("type") == "user"]


def completed_with_notice(f, agent, tag, capture="Capture: verified"):
    row = until(lambda: retirement(f, agent), f"retirement of {tag}")
    assert row["payload"]["reason"] == "completed", row
    found = until(lambda: notices(f, agent), f"completion notice of {tag}")
    assert len(found) == 1, found
    text = found[0]["payload"]["body"]["text"]
    assert " finished." in text and capture in text, text
    # One atomic host batch: the notice and the retirement commit together.
    assert found[0]["recorded_at"] == row["recorded_at"], (found[0], row)
    return found[0]


def run_owner(f):
    first = delegated(f, "o1", "complete", key="owner-complete")
    agent = first["agent_id"]
    assert first["name"].startswith("tmp-judge-") and not first["handoff_included"], first
    notice = completed_with_notice(f, agent, "o1")
    assert "DELEGATE-ANSWER-o1" in notice["payload"]["body"]["text"], notice
    assert not temporary_names(f), "a retired child stays in the default roster"
    assert first["name"] in temporary_names(f, "--include-temp")
    print("ok 1 - owner one-shot child answers, retires Completed and notifies once with verified capture", flush=True)

    again = delegated(f, "o1", "complete", key="owner-complete")
    assert (again["agent_id"], again["session_id"]) == (agent, first["session_id"]), (first, again)
    print("ok 2 - same-key retry after completion returns the original child and session", flush=True)

    held = delegated(f, "o3", "hold")
    child_ready(f, "o3")
    f.mail("send", held["agent_id"], "This must not start a second turn")
    time.sleep(1.5)
    assert not child_turns(f, "o3"), child_turns(f, "o3")
    (f.repo / "release-o3").touch()
    completed_with_notice(f, held["agent_id"], "o3")
    assert not child_turns(f, "o3"), child_turns(f, "o3")
    print("ok 3 - mail queued during turn 1 never reaches the one-shot child", flush=True)

    cancelled = delegated(f, "o4", "hold")
    child_ready(f, "o4")
    result = cancel(f, cancelled["agent_id"])
    assert result["retired"] and result["stopped_lifecycle"], result
    row = until(lambda: retirement(f, cancelled["agent_id"]), "cancel retirement")
    assert row["payload"]["reason"] == "cancelled", row
    time.sleep(0.5)
    assert not notices(f, cancelled["agent_id"]), "a cancelled child was reported as finished"
    print("ok 4 - cancel stops the child and retires it Cancelled without a completion notice", flush=True)

    expiring = delegated(f, "o5", "hold", "--ttl", "2")
    assert expiring["ttl_seconds"] == 2, expiring
    child_ready(f, "o5")
    row = until(lambda: retirement(f, expiring["agent_id"]), "TTL retirement", seconds=90)
    assert row["payload"]["reason"] == "expired", row
    assert not notices(f, expiring["agent_id"]), "an expired child was reported as finished"
    print("ok 5 - a TTL child registered on a running host expires and retires Expired", flush=True)

    held = [delegated(f, tag, "hold") for tag in ("c1", "c2")]
    error = refused(delegate(f, "c0", "hold"), "state-conflict")
    assert "cap is 2" in json.dumps(error), error
    for child in held:
        cancel(f, child["agent_id"])
    before = temporary_names(f)
    assert not before, before

    def racing(tag):
        return run_provider_command(
            subprocess.run, [str(f.se), "--json", "--home", str(f.home), "--project", f.project,
                             "--key", str(uuid.uuid4()), "delegate", "--task", task(tag, "hold"),
                             "--role", "judge"],
            stdin=subprocess.DEVNULL, environment=dict(f.env), fixture=f.root,
            capture_output=True, timeout=90)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        raced = list(pool.map(racing, ["r1", "r2", "r3", "r4"]))
    (f.log_root / "raced.json").write_text(json.dumps(
        [[r.returncode, r.stdout.decode(), r.stderr.decode()] for r in raced], indent=2))
    winners = [json.loads(r.stdout) for r in raced if r.returncode == 0]
    losers = [json.loads(r.stdout) for r in raced if r.returncode != 0]
    assert len(winners) == 2 and len(temporary_names(f)) == 2, (winners, temporary_names(f))
    assert all(e["code"] == "state-conflict" and "cap is 2" in json.dumps(e) for e in losers), losers
    for child in winners:
        cancel(f, child["agent_id"])
    print("ok 6 - the active-child cap holds sequentially and under four concurrent starts", flush=True)

    known = {row["payload"]["agent"]["id"] for row in history(f, "agent.retired")}
    refused_launch = delegate(f, "o7", "fail")
    assert refused_launch.returncode != 0, refused_launch.stdout.decode()
    assert read_json(f.repo / "child-o7-failed.json"), "the provider was never started"
    assert not temporary_names(f), temporary_names(f)
    unwound = [row for row in history(f, "agent.retired")
               if row["payload"]["agent"]["id"] not in known]
    assert len(unwound) == 1 and unwound[0]["payload"]["reason"] == "cancelled", unwound
    print("ok 7 - a launch failure after create retires the child instead of leaving a counted orphan", flush=True)


def cancel(f, agent):
    # The documented form: `se delegate cancel AGENT` needs no task.
    return f.ok("--project", f.project, "--key", str(uuid.uuid4()), "delegate", "cancel", agent)


def relaunch_parent(f):
    f.ok("down")
    (f.repo / "provider-ready.json").unlink(missing_ok=True)
    f.launch()


def run_agent(f):
    f.launch()
    refused(delegate(f, "a0", "complete", recipient=True), "owner-required")
    owner_grant(f, True)
    error = refused(delegate(f, "a0", "complete", recipient=True), "configuration-invalid")
    assert error["detail"]["subject"] == "delegation.allow", error
    assert not temporary_names(f, "--include-temp"), "a refused delegation left an agent behind"
    saved = f.ok("--project", f.project, "--key", str(uuid.uuid4()), "agent", "add", "Saved Child",
                 "--provider", "claude", recipient=True)
    launched = f.ok("--project", f.project, "--key", str(uuid.uuid4()), "launch", saved["agent"]["id"],
                    "--task", "Saved child task", "--detach", recipient=True)
    assert launched["state"] == "running", launched
    print("ok 8 - without [delegation].allow an agent's delegation is refused by name, "
          "while its saved child still creates and launches", flush=True)

    append_config(f, '[[delegation.allow]]\nprovider = "claude"\nprofile = "default"\n')
    relaunch_parent(f)
    nested = delegated(f, "a9", "nest", recipient=True)
    attempt = wait_json(f.repo / "child-a9-nested.json", seconds=60)
    reply = json.dumps(attempt["reply"])
    assert attempt["reply"]["result"]["isError"] and "depth limit is 1" in reply, attempt
    notice = completed_with_notice(f, nested["agent_id"], "a9")
    assert notice["payload"]["to"]["id"] == f.agent, notice["payload"]
    print("ok 9 - an allowlisted agent delegates, its child cannot delegate again, "
          "and the parent receives the notice", flush=True)

    held = delegated(f, "a10", "hold", recipient=True)
    child_ready(f, "a10")
    f.ok("--project", f.project, "--key", str(uuid.uuid4()), "stop", f.agent)
    row = until(lambda: retirement(f, held["agent_id"]), "parent-ended retirement")
    assert row["payload"]["reason"] == "parent_ended", row
    found = until(lambda: notices(f, held["agent_id"]), "parent-ended notice")
    text = found[0]["payload"]["body"]["text"]
    assert "stopped because its parent session ended" in text and " finished." not in text, text
    print("ok 10 - a parent's end retires its running child ParentEnded with a matching notice", flush=True)


def run_capture_off(f):
    child = delegated(f, "d1", "complete")
    notice = completed_with_notice(f, child["agent_id"], "d1",
                                   capture="Capture: not captured (capture disabled)")
    assert "Final response excerpt" not in notice["payload"]["body"]["text"], notice
    print("ok 11 - with capture disabled the notice says so instead of claiming verified", flush=True)


def fixture(se, root, name, change):
    f = Fixture(se, root / name, provider_helper=PROVIDER)
    change(f)
    f.ok("down")
    return f


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--case",
        choices=("all", "owner", "agent", "capture-off"),
        default="all",
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    cases = [
        ("owner", lambda f: append_config(f, "[delegation]\nmax_active_per_parent = 2\n"), run_owner),
        ("agent", lambda f: append_config(f, "[delegation]\nmax_active_per_parent = 2\n"), run_agent),
        ("capture-off", lambda f: edit_config(f, "[capture]\nenabled = true", "[capture]\nenabled = false"),
         run_capture_off),
    ]
    if args.case != "all":
        cases = [entry for entry in cases if entry[0] == args.case]
    else:
        print("1..11", flush=True)
    for name, change, run in cases:
        f = fixture(args.se, args.output, name, change)
        try:
            run(f)
        finally:
            f.close()


if __name__ == "__main__":
    main()
