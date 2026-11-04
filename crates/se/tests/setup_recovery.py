"""Author CLI consumers for absent state and unclaimed init staging."""
import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sqlite3
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).parent / "judges"))
from history_import import Fixture


def snapshot(home):
    return {str(p.relative_to(home)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in home.rglob("*") if p.is_file() and not p.is_symlink()}


def command_block(remedy, name):
    start, end = f"BEGIN SE {name}\n", f"\nEND SE {name}"
    assert remedy.count(start) == remedy.count(end) == 1
    return remedy.split(start, 1)[1].split(end, 1)[0]


def deleted_state(f):
    f.ok("down")
    saved = f.root / "closed-copy"
    saved.mkdir(mode=0o700)
    (f.home / "state.db").rename(saved / "state.db")
    before = snapshot(f.home)
    source = snapshot(saved)
    try:
        for args in [("status",), ("resume",), ("doctor",),
                     ("init", "--repo", str(f.root / "repo"))]:
            result = f.call(*args)
            assert result.returncode != 0
            value = json.loads(result.stdout)
            assert value["code"] == "state-conflict" and "Recorded state is missing" in value["message"]
            assert snapshot(f.home) == before and not (f.home / "state.db").exists()
        remedy = value["remedy"]["text"]
        environment = dict(f.environment, PATH=str(f.se.parent) + os.pathsep + "/usr/bin:/bin")
        recovered = subprocess.run(["/bin/sh", "-c", command_block(remedy, "RESTORE COMMANDS")], env=environment,
            input=(str(saved) + "\n").encode(),
            cwd=f.root / "repo", capture_output=True, timeout=90)
        (f.root / "restore.stdout").write_bytes(recovered.stdout)
        (f.root / "restore.stderr").write_bytes(recovered.stderr)
        assert recovered.returncode == 0, recovered.stderr
        assert f.ok("status")["setup"]["state"] == "configured"
        assert snapshot(saved) == source
        # Exercise the printed no-backup command too: the original home and its
        # owner remain intact while a separate home gets fresh identities.
        argv = shlex.split(command_block(remedy, "FRESH COMMAND"))
        argv[0] = str(f.se)
        fresh = subprocess.run(argv, env=f.environment, cwd=f.root / "repo", capture_output=True, timeout=90)
        (f.root / "fresh.stdout").write_bytes(fresh.stdout)
        (f.root / "fresh.stderr").write_bytes(fresh.stderr)
        assert fresh.returncode == 0, fresh.stderr
        fresh_home = Path(argv[argv.index("--home") + 1])
        with sqlite3.connect(f"file:{f.home / 'state.db'}?mode=ro", uri=True) as old, sqlite3.connect(f"file:{fresh_home / 'state.db'}?mode=ro", uri=True) as new:
            assert new.execute("select human_id from owners").fetchall() != old.execute("select human_id from owners").fetchall()
        assert snapshot(saved) == source
    finally:
        if not (f.home / "state.db").exists():
            (saved / "state.db").rename(f.home / "state.db")


def fresh_home(f):
    home = f.root / "fresh-home"
    home.mkdir(mode=0o700)
    config = home / "config.toml"
    config.write_bytes((f.home / "config.toml").read_bytes())
    config.chmod(0o600)
    before = snapshot(home)
    initialized = f.home
    try:
        f.home = home
        result = f.call("status")
    finally:
        f.home = initialized
    assert result.returncode == 0
    assert json.loads(result.stdout)["setup"]["state"] == "not-set-up"
    assert snapshot(home) == before


def setup_required_command_keeps_curly_home(f):
    home = f.root / "fresh O’Brien's home"
    home.mkdir(mode=0o700)
    original = f.home
    try:
        f.home = home
        result = subprocess.run(f.command("resume"), env=f.environment, cwd=f.root / "repo",
                                capture_output=True, timeout=90)
        (f.root / "setup-required.stdout").write_bytes(result.stdout)
        value = json.loads(result.stdout)
        assert result.returncode != 0 and value["code"] == "setup-required"
        text = value["remedy"]["text"]
        assert text.startswith("Run se ")
        argv = shlex.split(text.removeprefix("Run "))
        assert argv[argv.index("--home") + 1] == str(home)
        assert argv[argv.index("--repo") + 1] == str(f.root / "repo")
        argv[0] = str(f.se)
        initialized = subprocess.run(argv, env=f.environment, cwd=f.root / "repo",
                                     capture_output=True, timeout=90)
        (f.root / "setup-command.stdout").write_bytes(initialized.stdout)
        (f.root / "setup-command.stderr").write_bytes(initialized.stderr)
        assert initialized.returncode == 0, initialized.stderr
        assert f.ok("status")["setup"]["state"] == "configured"
        f.close()
    finally:
        f.home = original


def unclaimed_staging(f):
    names = [".se-stage-" + "0" * 32, ".se-stage-" + "0" * 32 + "-journal"]
    unrelated = f.home / ".se-stage-user-notes"
    unrelated.write_bytes(b"Unrelated user bytes stay intact.\n")
    unrelated.chmod(0o600)
    for name in names:
        path = f.home / name
        path.write_bytes(b"Unclaimed initialization bytes.\n")
        path.chmod(0o600)
    before = snapshot(f.home)
    value = f.ok("--key", "retained-init-key", "init", "--repo", str(f.root / "repo"))
    assert value["owner"]["human_id"] == f.owner
    quarantine = list(f.home.glob("init-quarantine-*"))
    assert len(quarantine) == 1 and str(quarantine[0]) in " ".join(value["changed"])
    for name in names:
        assert not (f.home / name).exists()
        assert hashlib.sha256((quarantine[0] / name).read_bytes()).hexdigest() == before[name]
    assert unrelated.read_bytes() == b"Unrelated user bytes stay intact.\n"
    assert f.ok("--key", "retained-init-key", "init", "--repo", str(f.root / "repo"))["owner"]["human_id"] == f.owner
    assert len(list(f.home.glob("init-quarantine-*"))) == 1


def linked_stage_refuses(f):
    outside = f.root / "outside-user-file"
    outside.write_bytes(b"Outside user bytes.\n")
    link = f.home / (".se-stage-" + "1" * 32)
    link.symlink_to(outside)
    try:
        refused = f.call("init", "--repo", str(f.root / "repo"))
        assert refused.returncode != 0 and link.is_symlink()
        assert not list(f.home.glob("init-quarantine-*"))
        assert outside.read_bytes() == b"Outside user bytes.\n"
    finally:
        link.unlink()


def line_break_home_has_no_shell_command(f):
    home = f.root / "line\nbreak"
    home.mkdir(mode=0o700)
    for name in ["machine.json", "credential"]:
        path = home / name
        path.write_bytes((f.home / name).read_bytes())
        path.chmod(0o600)
    before = snapshot(home)
    original = f.home
    try:
        f.home = home
        result = f.call("status")
    finally:
        f.home = original
    value = json.loads(result.stdout)
    assert result.returncode != 0 and value["code"] == "state-conflict"
    assert "contains a line break" in value["remedy"]["text"]
    assert "BEGIN SE" not in value["remedy"]["text"]
    assert before == snapshot(home) and not (home / "state.db").exists()
    fresh = f.root / "first\nsetup"
    fresh.mkdir(mode=0o700)
    try:
        f.home = fresh
        result = f.call("resume")
    finally:
        f.home = original
    value = json.loads(result.stdout)
    assert result.returncode != 0 and value["code"] == "setup-required"
    assert "contains a line break" in value["remedy"]["text"]
    assert "Run se" not in value["remedy"]["text"]
    assert not (fresh / "state.db").exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    cases = [deleted_state, fresh_home, setup_required_command_keeps_curly_home, unclaimed_staging, linked_stage_refuses, line_break_home_has_no_shell_command]
    print(f"1..{len(cases)}", flush=True)
    for number, case in enumerate(cases, 1):
        f = Fixture(args.se.resolve(), args.output.resolve() / (case.__name__ + "-O’Brien's-" + uuid.uuid4().hex[:6]))
        try:
            case(f)
        finally:
            f.close()
        print(f"ok {number} - {case.__name__}", flush=True)


if __name__ == "__main__":
    main()
