"""Pinned native consumer controls; compile failures never count as a red base."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

source, controls, output = map(lambda value: Path(value).resolve(), sys.argv[1:4])
label, expected_source = sys.argv[4:6]
output.mkdir(parents=True, exist_ok=True)
paths = ["crates/se-store/tests/review_checkpoint_deadline.rs",
         "crates/se-host/src/runtime/review_checkpoint_tests.rs"]
actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
assert actual == expected_source, (actual, expected_source)
for relative in paths:
    shutil.copyfile(controls / relative, source / relative)
module = source / "crates/se-host/src/runtime.rs"
with module.open("a", encoding="utf-8") as stream:
    stream.write('\n#[cfg(all(test, feature = "listener", any(target_os = "linux", windows)))]\nmod review_checkpoint_tests;\n')
env = dict(os.environ, CARGO_TARGET_DIR=str(output / "target"), CARGO_INCREMENTAL="0",
           CARGO_BUILD_JOBS="2", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
inputs = {"source": actual, "compiler": subprocess.check_output(["rustc", "-vV"], text=True),
          "controls": {relative: hashlib.sha256((controls / relative).read_bytes()).hexdigest()
                       for relative in paths}, "commands": []}
(output / "inputs.json").write_text(json.dumps(inputs, indent=2))
binaries = {}
for crate, kind in [("se-store", ["--test", "review_checkpoint_deadline"]), ("se-host", ["--lib"])]:
    command = ["cargo", "test", "--locked", "-p", crate, *kind, "--no-run", "--message-format=json"]
    inputs["commands"].append(command)
    with (output / (crate + "-build.jsonl")).open("w") as log, (output / (crate + "-build.stderr")).open("w") as error:
        result = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=error, timeout=1800)
    if result.returncode:
        (output / "inputs.json").write_text(json.dumps(inputs, indent=2))
        raise SystemExit("UNQUALIFIED: " + crate + " did not compile")
    found = []
    for line in (output / (crate + "-build.jsonl")).read_text().splitlines():
        value = json.loads(line)
        if value.get("reason") == "compiler-artifact" and value.get("executable") and value.get("profile", {}).get("test"):
            found.append(value["executable"])
    assert len(found) == 1, found
    binaries[crate] = found[0]
(output / "inputs.json").write_text(json.dumps(inputs, indent=2))
cases = [
    ("se-store", "review_checkpoint_hung_worker_respects_original_drain_deadline", "drain waited for the held checkpoint"),
    ("se-host", "runtime::review_checkpoint_tests::review_checkpoint_panic_reaches_native_stop_with_working_step", "last maintenance error"),
    ("se-host", "runtime::review_checkpoint_tests::review_checkpoint_missing_cause_is_still_failed", "failed maintenance with absent cause was collapsed to clean"),
    ("se-host", "runtime::review_checkpoint_tests::review_checkpoint_clean_absence_remains_clean", None),
]
rows = []
for index, (crate, name, marker) in enumerate(cases):
    listing = subprocess.check_output([binaries[crate], "--list"], cwd=source, env=env, text=True)
    assert name + ": test" in listing, "required native case absent: " + name
    command = [binaries[crate], name, "--exact", "--nocapture", "--test-threads=1"]
    result = subprocess.run(command, cwd=source, env=env, capture_output=True, text=True, timeout=40)
    text = result.stdout + result.stderr
    (output / f"case-{index}.log").write_text(text, encoding="utf-8")
    expect_red = label == "base" and marker is not None
    qualified = (result.returncode == 101 and marker in text and "1 failed" in text) if expect_red else (result.returncode == 0 and "1 passed" in text)
    rows.append({"test": name, "exit": result.returncode, "expected": "red" if expect_red else "green", "qualified": qualified})
    (output / "results.json").write_text(json.dumps(rows, indent=2))
    print(json.dumps(rows[-1]), flush=True)
if not all(row["qualified"] for row in rows):
    raise SystemExit(1)
