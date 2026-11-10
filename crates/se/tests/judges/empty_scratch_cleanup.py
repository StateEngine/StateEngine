"""Protects: an unused provider scratch directory cannot block cold cleanup."""
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
    helper = output / "provider.py"
    protocol = Path(__file__).with_name("mail_provider.py").resolve()
    helper.write_text('''import json, runpy, sys
if '--safe-mode' in sys.argv:
    request = json.loads(sys.stdin.readline())
    print(json.dumps({'type':'control_response','response':{
        'request_id':request['request_id'],'subtype':'success',
        'response':{'effective':{},'sources':[],'errors':[]}}}), flush=True)
else:
    runpy.run_path(PROTOCOL, run_name='__main__')
'''.replace("PROTOCOL", repr(str(protocol))))
    fixture = Fixture(image, output / "fixture", provider_helper=helper)
    wrapper = fixture.root / "provider.rs"
    wrapper.write_text(wrapper.read_text().replace("2.1.287", "2.1.318"))
    executable = fixture.root / ("provider.exe" if os.name == "nt" else "provider")
    subprocess.run(["rustc", "--edition=2024", str(wrapper), "-o", str(executable)],
                   capture_output=True, check=True, timeout=60)
    results = []

    def call(label, *args):
        result = fixture.call(*args)
        row = {"label":label, "exit":result.returncode,
               "stdout":result.stdout.decode(), "stderr":result.stderr.decode()}
        results.append(row)
        (output / "calls.json").write_text(json.dumps(results, indent=2))
        print(label, result.returncode, flush=True)
        return row

    try:
        fixture.launch()
        before = [{"directory":str(path), "entries":sorted(p.name for p in path.iterdir())}
                  for path in (fixture.home / "launch").iterdir() if path.is_dir()]
        (output / "inventory.json").write_text(json.dumps(before, indent=2))
        assert call("warm-stop", "--project", fixture.project, "stop", fixture.agent)["exit"] == 0
        assert call("warm-down", "down")["exit"] == 0
        assert call("cold-up", "up")["exit"] == 0
        cold = call("cold-stop", "--project", fixture.project, "stop", fixture.agent)
        assert cold["exit"] == 0, "an unused scratch directory prevented cold stop"
        assert call("cold-down", "down")["exit"] == 0
        print("PASS: cold cleanup succeeds without provider temporary files", flush=True)
    finally:
        down = call("final-down", "down")
        if down["exit"]:
            # This fixture never wrote provider temp bytes. Remove only an
            # empty scratch directory after retaining the original refusal.
            for path in (fixture.home / "launch").glob("*/scratch"):
                assert not path.is_symlink() and not any(path.iterdir())
                path.rmdir()
        fixture.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    run(args.se, args.output)
