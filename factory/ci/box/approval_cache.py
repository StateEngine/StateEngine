#!/usr/bin/python3 -I
"""Build a dependency-only seed as the existing dedicated CI controller."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import sys

sys.path.insert(0, "/usr/local/lib/stateengine-box-ci/factory/ci/box")
from custody import Journal, idle
from dispatch import trusted
from engine import Container
from transport import execute, export


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def interrupted(*_):
    raise InterruptedError("dependency approval build canceled")


def build(request):
    report = trusted(Path(request["image_report"]))
    if report["trusted_source"] != request["source"]:
        raise ValueError("dependency source and image differ")
    output, source, seed = map(Path, (request["output"], request["archive"], request["seed"]))
    if output.stat().st_uid != os.getuid() or any(output.iterdir()):
        raise ValueError("empty controller-owned output required")
    if digest(source) != request["archive_sha256"] or digest(seed) != request["seed_sha256"]:
        raise ValueError("dependency build input differs")
    available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                         if line.startswith("MemAvailable:"))) * 1024
    if available < 34 * 1024**3:
        raise RuntimeError("less than 34 GiB available for dependency preparation")

    def checked(box, arguments, name, **kwargs):
        result = execute(box, arguments, output / (name + ".log"), **kwargs)
        (output / (name + ".json")).write_text(json.dumps(result) + "\n")
        if not result["success"]:
            raise RuntimeError("dependency preparation failed: " + name)

    with open(request["ci_lock"]) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal = Journal()
        journal.reconcile()
        box = Container(report["image"], memory=18 * 1024**3, cpus=8, deadline=1800, journal=journal)
        try:
            (output / "admission.json").write_text(json.dumps(box.proof) + "\n")
            with source.open("rb") as stream:
                checked(box, ["python3", "/opt/box/runner.py", "source"], "source", stdin=stream)
            copy = "import shutil,sys;f=open('/work/dependencies.tar.gz','xb');shutil.copyfileobj(sys.stdin.buffer,f);f.close()"
            with seed.open("rb") as stream:
                checked(box, ["python3", "-c", copy], "seed", stdin=stream)
            checked(box, ["python3", "/opt/box/runner.py", "run", "archive", "--all-features"], "archive")
            cleanup = '''
import json,os,subprocess,tarfile
from pathlib import Path
os.chdir('/work/source')
os.environ.update(CARGO_HOME='/home/ci/cargo',CARGO_NET_OFFLINE='true')
metadata=json.loads(subprocess.check_output(['cargo','metadata','--no-deps','--locked','--format-version=1']))
members=set(metadata['workspace_members'])
packages=[p['id'] for p in metadata['packages'] if p['id'] in members]
target=subprocess.check_output(['rustc','--print','host-tuple'],text=True).strip()
arguments=['cargo','clean','--target',target]
for package in packages:arguments += ['-p',package]
subprocess.run(arguments,check=True)
def dependency_entry(member):
    return None if any(member.name==p or member.name.startswith(p+'/') for p in ['target/nextest','target/cargo-timings']) else member
with tarfile.open('tests.tar.zst','w:gz',compresslevel=1) as archive:
    archive.add('target',arcname='target',filter=dependency_entry)
print(json.dumps({'workspace_packages_removed':packages,'cache_bytes':Path('tests.tar.zst').stat().st_size}))
'''
            checked(box, ["python3", "-c", cleanup], "remove-workspace")
            result = export(box, "archive", output / "dependencies.tar.gz")
            result.update(source=request["source"], image=report["image"], workspace_artifacts_removed=True)
        finally:
            box.close()
        (output / "outside-idle.json").write_text(json.dumps(idle()) + "\n")
        (output / "manifest.json").write_text(json.dumps(result) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    arguments = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    build(trusted(arguments.request))
