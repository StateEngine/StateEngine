#!/usr/bin/env python3
"""Run a bounded Linux shadow; this never updates GitHub checks or dispatches CI."""
import argparse
from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import threading

from engine import command
from custody import Journal
from workload import Cohort
from github_binding import GitHub, bind


def write(path, value):
    with path.open("x") as dest:
        json.dump(value, dest, indent=2)
        dest.write("\n")


@contextmanager
def exclusive():
    directory = Path.home() / ".local/state/stateengine-box-ci"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("private controller state directory unavailable")
    fd = os.open(directory / "one-job.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with open("/var/lib/stateengine-ci-locks/shadow.lock", "r") as shared:
            fcntl.flock(shared, fcntl.LOCK_EX | fcntl.LOCK_NB)
            live = json.loads(command("ps", "--filter=label=stateengine.shadow=true", "--format=json"))
            if live:
                raise RuntimeError("infrastructure unavailable: an earlier owned container is still running")
            yield
    finally:
        os.close(fd)


def stop(*_):
    raise InterruptedError("controller canceled")


def run(args):
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = {"scope": "Linux shadow only; hosted required check unchanged", "success": False,
              "jobs": {}, "binding": None}
    try:
        report = json.loads(args.image_report.read_text())
        api = GitHub(args.token_helper)
        binding = bind(api, args.run, args.attempt, args.pr, args.checkout, report["policy"])
        result["binding"] = asdict(binding)
        # Freeze the outside identity before candidate execution and never
        # replace it with stdout, artifacts, or files from a worker.
        write(args.output / "binding.json", result["binding"])
        source = api.get("tarball/" + binding.checkout, limit=64 * 1024**2, raw=True)
        with (args.output / "source.tar.gz").open("xb") as dest:
            dest.write(source)
        del source, api
        with exclusive():
            journal = Journal()
            journal.reconcile()
            cohort = Cohort(report, journal, args.output / "source.tar.gz", args.cache,
                            args.output, threading.Event())
            try:
                status, outcomes = cohort.run()
                result["jobs"] = outcomes
            finally:
                result["jobs"] = cohort.outcomes
                journal.reconcile()
            result["success"] = status == "passed"
    except Exception as error:
        result["error"] = type(error).__name__ + ": " + str(error)
    finally:
        write(args.output / "result.json", result)
    print(json.dumps(result))
    return 0 if result["success"] else 1


def parser():
    def positive(value):
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("use a positive integer") from None
        if number <= 0:
            raise argparse.ArgumentTypeError("use a positive integer")
        return number

    def checkout(value):
        if not re.fullmatch(r"[a-f0-9]{40}", value):
            raise argparse.ArgumentTypeError("use the complete 40-character lowercase checkout SHA")
        return value

    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--run", type=positive, required=True)
    value.add_argument("--attempt", type=positive, required=True)
    value.add_argument("--pr", type=positive, required=True)
    value.add_argument("--checkout", type=checkout, required=True)
    value.add_argument("--image-report", type=Path, required=True)
    value.add_argument("--cache", type=Path, required=True)
    value.add_argument("--token-helper", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    return value


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    raise SystemExit(run(parser().parse_args()))
