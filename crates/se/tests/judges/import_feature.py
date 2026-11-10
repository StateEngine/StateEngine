"""Public CLI feature controls; use --enabled only for an import-enabled build."""
import argparse
import json
from pathlib import Path
import subprocess
import traceback
import uuid

from history_import import Fixture


def command_surface(f, enabled):
    def metadata(name, *arguments):
        reply = subprocess.run([str(f.se), "--json", *arguments], env=f.environment,
                               capture_output=True, timeout=30)
        (f.root / (name + ".stdout")).write_bytes(reply.stdout)
        (f.root / (name + ".stderr")).write_bytes(reply.stderr)
        return reply

    help_reply = metadata("import-help", "import", "--help")
    assert (help_reply.returncode == 0) == enabled, help_reply.stdout + help_reply.stderr
    schema_reply = metadata("schema-all", "schema")
    assert schema_reply.returncode == 0, schema_reply.stdout + schema_reply.stderr
    schema = json.loads(schema_reply.stdout)
    assert any(row["name"] == "store.import_node" for row in schema["ops"]) == enabled
    selected = metadata("schema-selected", "schema", "store.import_node")
    assert (selected.returncode == 0) == enabled, selected.stdout + selected.stderr


def init_guidance(f, enabled):
    marker = f.root / "repo/.stateengine/projects.jsonl"
    marker.parent.mkdir()
    marker.write_text("{}\n")
    before = marker.read_bytes()
    reply = f.ok("init", "--repo", str(f.root / "repo"))
    hint = reply.get("import_hint") or ""
    if enabled:
        assert "se import --from-node" in hint, reply
    else:
        assert "se import" not in hint, "init recommends a command absent from this build: " + hint
    assert marker.read_bytes() == before, "init changed the retained source marker"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--enabled", action="store_true")
    args = parser.parse_args()
    failures = 0
    print("1..2", flush=True)
    for number, check in enumerate([command_surface, init_guidance], 1):
        f = None
        try:
            f = Fixture(args.se.resolve(), args.output.resolve() / (check.__name__ + "-" + uuid.uuid4().hex[:8]))
            try:
                check(f, args.enabled)
            finally:
                f.close()
            print(f"ok {number} - {check.__name__}", flush=True)
        except Exception:
            failures += 1
            print(f"not ok {number} - {check.__name__}", flush=True)
            traceback.print_exc()
    print(json.dumps({"passed": 2 - failures, "failed": failures}), flush=True)
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
