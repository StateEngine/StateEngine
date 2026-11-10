"""Protects: provider scratch never becomes authority for launch cleanup.

Run against an isolated binary with --se IMAGE --output NEW_DIRECTORY.
Uses the existing synthetic provider and exercises public launch/stop/down.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from mail_cli import Fixture


def run(image, output):
    output.mkdir(parents=True, exist_ok=False)
    helper = output / "temporary_provider.py"
    protocol = Path(__file__).with_name("mail_provider.py").resolve()
    helper.write_text('''import json, os, runpy, sys
from pathlib import Path
if '--safe-mode' in sys.argv:
    request = json.loads(sys.stdin.readline())
    print(json.dumps({'type':'control_response','response':{
        'request_id':request['request_id'],'subtype':'success',
        'response':{'effective':{},'sources':[],'errors':[]}}}), flush=True)
else:
    scratch = Path(os.environ['TMPDIR'])
    assert all(os.environ[key] == str(scratch) for key in ['TMPDIR','TMP','TEMP'])
    assert scratch.is_dir() and not scratch.is_symlink()
    (scratch / 'ordinary-temp').write_bytes(b'synthetic provider temporary bytes')
    (scratch / 'nested').mkdir()
    (scratch / 'nested' / 'keep').write_bytes(b'synthetic nested bytes')
    target = Path.cwd() / 'unrelated'
    target.mkdir(exist_ok=True)
    (target / 'keep').write_bytes(b'synthetic unrelated bytes')
    if os.name != 'nt':
        (scratch / 'outside-link').symlink_to(target, target_is_directory=True)
    with (Path.cwd() / 'scratch.jsonl').open('a') as stream:
        stream.write(json.dumps({'path':str(scratch),'mode':scratch.stat().st_mode & 0o777}) + '\\n')
    runpy.run_path(PROTOCOL, run_name='__main__')
'''.replace("PROTOCOL", repr(str(protocol))))
    fixture = Fixture(image, output / "fixture", provider_helper=helper)
    # The shared protocol fixture's native launcher must advertise the version
    # required by the current provider qualification contract.
    wrapper = fixture.root / "provider.rs"
    wrapper.write_text(wrapper.read_text().replace("2.1.287", "2.1.318"))
    executable = fixture.root / ("provider.exe" if os.name == "nt" else "provider")
    subprocess.run(["rustc", "--edition=2024", str(wrapper), "-o", str(executable)],
                   capture_output=True, check=True, timeout=60)
    results, scratch_paths = [], []

    def call(label, *args):
        result = fixture.call(*args)
        results.append({"label": label, "exit": result.returncode,
                        "stdout": result.stdout.decode(), "stderr": result.stderr.decode()})
        (output / "calls.json").write_text(json.dumps(results, indent=2))
        assert result.returncode == 0, results[-1]
        return json.loads(result.stdout)

    def retained():
        path = scratch_paths[-1]
        assert (path / "ordinary-temp").read_bytes() == b"synthetic provider temporary bytes"
        assert (path / "nested" / "keep").read_bytes() == b"synthetic nested bytes"
        assert (fixture.repo / "unrelated" / "keep").read_bytes() == b"synthetic unrelated bytes"
        if os.name != "nt":
            assert (path / "outside-link").is_symlink()

    try:
        for iteration in range(2):
            fixture.launch()
            rows = [json.loads(line) for line in (fixture.repo / "scratch.jsonl").read_text().splitlines()]
            path = Path(rows[-1]["path"])
            scratch_paths.append(path)
            assert path not in scratch_paths[:-1], "each session owns a distinct scratch directory"
            if os.name != "nt":
                assert rows[-1]["mode"] == 0o700, rows[-1]
            if iteration == 0:
                call("stop-with-provider-temp", "--project", fixture.project, "stop", fixture.agent)
            call(f"down-{iteration}", "down")
            retained()
            assert not (fixture.home / "endpoint.json").exists()
            call(f"cold-up-{iteration}", "up")
            call(f"cold-stop-{iteration}", "--project", fixture.project, "stop", fixture.agent)
            call(f"cold-down-{iteration}", "down")
            assert path.parent == fixture.home / "provider-tmp", rows[-1]
            assert not any((fixture.home / "launch").glob("*/custody.json")), "launch authority must retire despite provider scratch"
            retained()
            fixture.close()
        for path in scratch_paths:
            assert (path / "ordinary-temp").exists(), "later launches must preserve previous provider files"
        (output / "result.json").write_text(json.dumps({"state": "pass", "sessions": len(scratch_paths),
            "temporary_directories": [str(path) for path in scratch_paths],
            "checks": ["private separate scratch", "all temp environment names", "stop and down",
                       "cold recovery", "distinct session roots", "nested and unrelated data retained"]}, indent=2))
        print("PASS: separate private provider scratch survives warm and cold cleanup", flush=True)
    finally:
        result = fixture.call("down")
        (output / "final-down.stdout").write_bytes(result.stdout)
        (output / "final-down.stderr").write_bytes(result.stderr)
        if result.returncode:
            # A red baseline may leave our synthetic bytes in its authority
            # directory. Retain the refusal first, then remove only bytes this
            # fixture created, without following the unrelated-data link.
            for path in scratch_paths:
                assert path.parent in (fixture.home / "launch", fixture.home / "provider-tmp")
                for relative, content in [("ordinary-temp", b"synthetic provider temporary bytes"),
                                          ("nested/keep", b"synthetic nested bytes")]:
                    item = path / relative
                    if item.exists():
                        assert not item.is_symlink() and item.read_bytes() == content
                        item.unlink()
                link = path / "outside-link"
                if link.is_symlink():
                    assert link.readlink() == fixture.repo / "unrelated"
                    link.unlink()
                nested = path / "nested"
                if nested.exists():
                    nested.rmdir()
            retry = fixture.call("down")
            (output / "cleanup-down.stdout").write_bytes(retry.stdout)
            (output / "cleanup-down.stderr").write_bytes(retry.stderr)
            assert retry.returncode == 0, "synthetic baseline cleanup remains incomplete"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    run(args.se, args.output)
