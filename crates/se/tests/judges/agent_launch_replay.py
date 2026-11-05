"""Granted parent/child launch and opposite-door request replay.
Claude uses the native protocol fixture; Codex uses a real binary and the owned
loopback model from takeover_codex.py, without an external account or service.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import tempfile
import time
import uuid

from agent_create_cli import create, launch, owner_grant
from mail_cli import Fixture
from takeover_codex import TakeoverModel


def pin(f, receipt):
    process = receipt["process"]
    path = Path("/proc") / str(process["pid"])
    fields = (path / "stat").read_text().rsplit(") ", 1)[1].split()
    assert str((path / "exe").resolve()) == process["exe"], process
    f.processes.append((process["pid"], fields[19]))
    census = {}
    for observed in Path("/proc").iterdir():
        if observed.name.isdecimal():
            try:
                row = (observed / "stat").read_text().rsplit(") ", 1)[1].split()
                census[int(observed.name)] = (int(row[1]), row[19])
            except (FileNotFoundError, ProcessLookupError):
                pass
    roots = {process["pid"]}
    while True:
        children = {pid for pid, (parent, _) in census.items() if parent in roots}
        if children <= roots:
            break
        roots.update(children)
    for pid in roots:
        f.processes.append((pid, census[pid][1]))
    return process["pid"], fields[19]


def work(f, model):
    until = time.monotonic() + 45
    while not ((f.repo / "sum.txt").exists() and model.readback):
        assert time.monotonic() < until, "native Codex work/readback incomplete"
        time.sleep(.1)
    assert (f.repo / "sum.txt").read_text() == "5\n"


def launch_count(f):
    # Lifecycle preparations are intentionally outside public history. Inspect
    # the fixture's committed projection read-only, from outside its writer.
    with sqlite3.connect((f.home / "state.db").as_uri() + "?mode=ro", uri=True) as db:
        return db.execute("SELECT count(*) FROM sessions").fetchone()[0]


def run(args):
    os.umask(0o077)
    f = Fixture(args.se, args.output, log_directory="calls")
    model, short = None, None
    rows = []
    print("1..10", flush=True)

    def check(text):
        rows.append(text)
        print(f"ok {len(rows)} - {text}", flush=True)

    try:
        if args.provider == "codex":
            assert args.codex, "--codex is required for native Codex"
            model = TakeoverModel(f.root, f.repo)
            short = Path(tempfile.mkdtemp(prefix="se5p-replay-", dir="/tmp"))
            code_home = f.root / "owned-codex-home"
            code_home.mkdir(mode=0o700)
            f.env.update(CODEX_HOME=str(code_home), OPENAI_API_KEY="sk-owned-loopback-no-account",
                         XDG_RUNTIME_DIR=str(short), TMPDIR="/tmp")
            (code_home / "config.toml").write_text('model_provider="owned-loopback"\n'
                '[model_providers.owned-loopback]\nname="Owned parent-child model"\nbase_url=' +
                json.dumps(f"http://127.0.0.1:{model.server.server_port}/v1") +
                '\nwire_api="responses"\nrequires_openai_auth=false\n')
            subprocess.run([str(args.codex), "login", "--with-api-key"],
                           input=f.env["OPENAI_API_KEY"], text=True, env=f.env,
                           capture_output=True, timeout=20, check=True)
            config = f.home / "config.toml"
            config.write_text(config.read_text().replace("[providers.codex]",
                "[providers.codex]\ncommand = " + json.dumps(str(args.codex.resolve())), 1))
            f.agent = f.ok("--project", f.project, "agent", "add", "Codex Parent",
                           "--provider", "codex", "--model", "gpt-6.1-sol")["agent"]["id"]
            parent = f.ok("--project", f.project, "launch", f.agent, "--detach", "--task",
                          "Write sum.txt containing 5, read it back and reply SUM_DONE.")
            f.session = parent["session_id"]
            pin(f, parent)
            work(f, model)
        else:
            f.launch()
        check("real parent session is active")
        owner_grant(f, True)
        check("owner grant committed through public config")
        for door in ["cli", "mcp"]:
            ok, child = create(f, door, door.upper() + " Child", str(uuid.uuid4()), args.provider)
            assert ok, child
            check(door + " creates its direct child")
            if model:
                model.sent, model.readback = False, False
                (f.repo / "sum.txt").unlink(missing_ok=True)
            key, task = str(uuid.uuid4()), "Write sum.txt containing 5, read it back and reply SUM_DONE."
            first = launch(f, door, child["agent"]["id"], key, task)
            assert first["state"] == "running" and first["provider"] == args.provider, first
            original = pin(f, first)
            if model:
                work(f, model)
            check(door + " launches its child" + (" with native Codex work/readback" if model else ""))
            before = launch_count(f)
            opposite = "mcp" if door == "cli" else "cli"
            replay = launch(f, opposite, child["agent"]["id"], key, task)
            assert replay == first, (first, replay)
            for field in ["event_id", "launch_id", "lifecycle_id", "session_id", "conversation_id", "process"]:
                assert first[field] == replay[field], (field, first, replay)
            assert pin(f, replay) == original
            assert launch_count(f) == before, "retry created another session"
            check(door + " to " + opposite + " retry returns original IDs, process birth and session count")
            if door == "cli":
                refused = f.rpc("stateengine_agent_launch", {
                    "target_agent_id": child["agent"]["id"], "task": "changed task",
                    "detach": True, "idempotency_key": key})
                assert refused.get("isError") and "launch request key" in json.dumps(refused), refused
                assert launch_count(f) == before
                check("changed request under the original key still refuses without a session")
    finally:
        try:
            f.close()
        finally:
            if model:
                model.close()
            if short:
                child_directory = short / "stateengine"
                if child_directory.exists():
                    child_directory.rmdir()
                short.rmdir()
    check("public shutdown witnesses exact roots closed and endpoint absent")
    (f.root / "result.json").write_text(json.dumps({"passed": len(rows), "checks": rows,
        "births": f.processes, "endpoint_absent": not (f.home / "endpoint.json").exists()}, indent=2))
    print(f"{len(rows)} passed; 0 failed", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--se", type=Path, required=True)
    p.add_argument("--provider", choices=["claude", "codex"], required=True)
    p.add_argument("--codex", type=Path)
    p.add_argument("--output", type=Path, required=True)
    run(p.parse_args())
