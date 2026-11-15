"""Build one pinned native observer and retain every result, including refusals."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib
source, controls, output = map(lambda item: Path(item).resolve(), sys.argv[1:4])
output.mkdir(parents=True, exist_ok=True)
expected = "02f60515c2cf9a02fc3e2b1c5668db5f471a82a6"
actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
assert actual == expected, actual
host = subprocess.check_output(["rustc", "--print", "host-tuple"], text=True).strip()
assert host == "aarch64-apple-darwin", host
app = output / "observer"
(app / "src").mkdir(parents=True)
files = controls / "crates/se-host/tests/review_atlas_admission"
for name in ["main.rs", "measure.rs", "parse.rs", "sql.rs"]:
    shutil.copyfile(files / name, app / "src" / name)
manifest = '[package]\nname="native-atlas-admission-observer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
for name in ["se-host", "se-atlas", "se-proc", "se-types"]:
    manifest += name + "={path=" + json.dumps(str(source / "crates" / name)) + "}\n"
manifest += 'serde_json="=1.0.154"\nlibc="=0.2.191"\nrusqlite={version="=0.41.1",features=["bundled","hooks","limits","functions"]}\ntree-sitter={version="=0.26.13",default-features=false,features=["std"]}\n'
manifest += '[patch.crates-io]\nsecode-stateengine-api={path=' + json.dumps(str(source / "vendor/secode-stateengine-api")) + '}\n'
manifest += '[profile.distribution]\ninherits="release"\nopt-level="s"\nlto="thin"\ncodegen-units=1\n[profile.distribution.package.libsqlite3-sys]\nopt-level=3\n[profile.distribution.package.sha2]\nopt-level=3\n[profile.distribution.package.hmac]\nopt-level=3\n'
(app / "Cargo.toml").write_text(manifest)
shutil.copyfile(source / "Cargo.lock", app / "Cargo.lock")
(app / ".cargo").mkdir()
shutil.copyfile(source / ".cargo/config.toml", app / ".cargo/config.toml")
env = dict(os.environ, CARGO_TARGET_DIR=str(output / "target"), CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0")
commands = []
def run(label, argv, cwd=app, timeout=1800):
    commands.append(list(map(str, argv)))
    start = time.monotonic_ns()
    with (output / (label + ".stdout")).open("w") as stdout, (output / (label + ".stderr")).open("w") as stderr:
        completed = subprocess.run(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr, timeout=timeout)
    result = {"command": list(map(str, argv)), "exit": completed.returncode, "elapsed_ns": time.monotonic_ns() - start}
    (output / (label + ".execution.json")).write_text(json.dumps(result, indent=2))
    return completed.returncode
if run("fetch", ["cargo", "fetch", "--locked", "--target", host], source):
    raise SystemExit("native observer dependencies unavailable")
if run("build", ["cargo", "build", "--manifest-path", str(app / "Cargo.toml"), "--offline", "--profile", "distribution", "--target", host]):
    raise SystemExit("native observer did not compile")
known = tomllib.loads((source / "Cargo.lock").read_text())["package"]
resolved = tomllib.loads((app / "Cargo.lock").read_text())["package"]
allowed = {(item["name"], item["version"], item.get("source")) for item in known}
names = {item["name"] for item in known}
changed = [item for item in resolved if item["name"] in names and (item["name"], item["version"], item.get("source")) not in allowed]
assert not changed, changed
image = output / "target" / host / "distribution/native-atlas-admission-observer"
inputs = {"source": actual, "compiler": subprocess.check_output(["rustc", "-vV"], text=True),
          "controls": {name: hashlib.sha256((files / name).read_bytes()).hexdigest() for name in ["main.rs", "measure.rs", "parse.rs", "sql.rs", "run.py"]},
          "manifest": manifest, "version_changes": changed, "binary_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
          "commands": commands, "allocator_reference": "https://github.com/apple-oss-distributions/libmalloc/blob/main/include/malloc/malloc.h"}
(output / "inputs.json").write_text(json.dumps(inputs, indent=2))
results = []
cases = [("sql",)] + [(grammar, pattern) for grammar in ["rust", "python", "javascript", "jsx", "typescript", "tsx"] for pattern in ["definitions", "references", "comments", "malformed", "nesting"]]
for case in cases:
    for repeat in range(3):
        label = "-".join(case) + "-" + str(repeat)
        fixture = output / ("fixture-" + label)
        exit_code = run(label, [str(image), str(fixture), *case], timeout=90)
        row = {"case": case, "repeat": repeat, "exit": exit_code}
        if exit_code == 0:
            row["observation"] = json.loads((output / (label + ".stdout")).read_text())
            assert not fixture.exists(), "successful observer retained its fixture"
        else:
            row["failure"] = (output / (label + ".stderr")).read_text()
        results.append(row)
        (output / "results.json").write_text(json.dumps(results, indent=2))
        print(json.dumps({"case": case, "repeat": repeat, "exit": exit_code}), flush=True)
if any(row["exit"] for row in results):
    raise SystemExit("one or more component measurements unqualified; all results retained")
