"""Build and run the required native status judge with private fixture inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "ci-reports/runtime-status")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("this judge requires native Linux self-accounting")
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix="observations-", dir=output))
    env = dict(os.environ)
    env.pop("CARGO_BUILD_TARGET", None)
    env.pop("SE_RUNTIME_JUDGE_SETUP_SE", None)
    env.setdefault("CARGO_BUILD_JOBS", "2")
    target = Path(env.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target.is_absolute():
        target = ROOT / target
    target = target.resolve()
    host = subprocess.check_output(["rustc", "--print", "host-tuple"], text=True).strip()
    image = target / host / "debug/se"
    env.update(SE_RUNTIME_JUDGE_SE=str(image), SE_RUNTIME_JUDGE_OUT=str(evidence))
    report = {"steps": [], "observations": str(evidence), "judge_sha256": hashlib.sha256(
        (ROOT / "crates/se-host/tests/runtime_status_independent.rs").read_bytes()).hexdigest()}
    commands = [
        ("build", ["cargo", "build", "--target", host, "-p", "se",
                   "--features", "remote,se-host/secode", "--locked"]),
        ("tests", ["cargo", "test", "--target", host, "-p", "se-host",
                   "--test", "runtime_status_independent", "--features", "remote,secode", "--locked", "--", "--test-threads", "1"]),
    ]
    try:
        for name, command in commands:
            started = time.monotonic()
            with (output / (name + ".log")).open("wb") as log:
                done = subprocess.run(command, cwd=ROOT, env=env, stdout=log,
                                      stderr=subprocess.STDOUT, timeout=1200)
            report["steps"].append({"name": name, "argv": command, "exit": done.returncode,
                                    "seconds": time.monotonic() - started})
            print(f"Required status judge {name}: exit {done.returncode}", flush=True)
            if done.returncode:
                print((output / (name + ".log")).read_text(), flush=True)
                return done.returncode
            if name == "build":
                with image.open("rb") as binary:
                    report["image_sha256"] = hashlib.file_digest(binary, "sha256").hexdigest()
        report["cases"] = {name: len(list(evidence.glob(f"se-rs-{name}-*.status.json")))
                           for name in ("daemon", "secode", "unavailable")}
        if report["cases"] != {"daemon": 1, "secode": 1, "unavailable": 1}:
            raise RuntimeError("status judge did not produce every required case observation")
    finally:
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print((output / "tests.log").read_text(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
