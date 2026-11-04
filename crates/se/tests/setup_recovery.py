"""Author CLI consumers for absent state and unclaimed init staging."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).parent / "judges"))
from history_import import Fixture


def snapshot(home):
    return {str(p.relative_to(home)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in home.rglob("*") if p.is_file() and not p.is_symlink()}


def deleted_state(f):
    f.ok("down")
    saved = f.root / "retained-state.db"
    (f.home / "state.db").rename(saved)
    before = snapshot(f.home)
    try:
        for args in [("status",), ("resume",), ("doctor",),
                     ("init", "--repo", str(f.root / "repo"))]:
            result = f.call(*args)
            assert result.returncode != 0
            value = json.loads(result.stdout)
            assert value["code"] == "state-conflict" and "Recorded state is missing" in value["message"]
            assert "Restore the original database" in value["remedy"]["text"]
            assert not (f.home / "state.db").exists()
            assert snapshot(f.home) == before, "lost-state diagnosis changed surviving files"
    finally:
        saved.rename(f.home / "state.db")


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
    (f.root / "staging-before.json").write_text(json.dumps(before, indent=2))
    try:
        result = f.call("--key", "retained-init-key", "init", "--repo", str(f.root / "repo"))
        assert result.returncode != 0
        text = (result.stdout + result.stderr).decode()
        assert all(name in text for name in names) and "original --key" in text
        after = snapshot(f.home)
        (f.root / "staging-after.json").write_text(json.dumps(after, indent=2))
        # Opening the existing SQLite reader may recreate WAL/SHM sidecars.
        # Persistent database, identity and unclaimed source bytes must agree.
        persistent = lambda rows: {k: v for k, v in rows.items() if k not in ["state.db-wal", "state.db-shm"]}
        assert persistent(after) == persistent(before), "refusal changed persistent database or unclaimed files"
    finally:
        # These synthetic bytes were created by this case; retain them outside
        # the home before its ordinary public shutdown.
        for name in names:
            (f.home / name).rename(f.root / name)
    assert unrelated.read_bytes() == b"Unrelated user bytes stay intact.\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    cases = [deleted_state, fresh_home, unclaimed_staging]
    print(f"1..{len(cases)}", flush=True)
    for number, case in enumerate(cases, 1):
        f = Fixture(args.se.resolve(), args.output.resolve() / (case.__name__ + "-" + uuid.uuid4().hex[:6]))
        try:
            case(f)
        finally:
            f.close()
        print(f"ok {number} - {case.__name__}", flush=True)


if __name__ == "__main__":
    main()
