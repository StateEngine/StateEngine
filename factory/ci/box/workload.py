"""Fixed, bounded Linux cohort; only child outcomes supply authoritative stage results."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import threading

from engine import Container, capacity
from transport import execute, export, WorkloadFailure

GIB = 1024**3
LIMITS = {"fmt": (2, 2), "clippy": (6, 8), "archive": (12, 8),
          "test-1": (10, 8), "test-2": (10, 8)}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class Canceled(Exception):
    pass


def observed_failure(result):
    if result.get("reason"):
        raise WorkloadFailure(result["reason"])
    if result.get("exit_code") not in (None, 0) and result.get("exit_observed_before_cancel", True):
        raise WorkloadFailure("observed workload exit " + str(result["exit_code"]))


class Tracked(Container):
    def __init__(self, *args, **kwargs):
        self.close_lock = threading.RLock()
        super().__init__(*args, **kwargs)

    def close(self):
        with self.close_lock:
            super().close()


def counts(name, output, code):
    text = ANSI.sub("", output)
    row = dict(exit=0 if code == 0 else 1, tests=0, custom=0, docs=0, checks=0)
    if name == "fmt":
        found = re.findall(r"^Ran (\d+) tests? in .*", text, re.M)
        if len(found) == 1 and "\nOK\n" in text:
            row["checks"] = int(found[0])
    elif name == "archive":
        row["docs"] = sum(int(n) for n in re.findall(r"^test result: ok\. (\d+) passed;", text, re.M))
    elif name.startswith("test-"):
        found = re.findall(r"Summary \[.*?\] (\d+) tests run: (\d+) passed[^\n]*", text)
        if len(found) == 1 and found[0][0] == found[0][1]:
            row["tests"] = int(found[0][0])
        if name == "test-1":
            custom = re.findall(r"^Custom harnesses: (\d+) passed, 0 failed$", text, re.M)
            if len(custom) == 1:
                row["custom"] = int(custom[0])
    if ((name == "fmt" and row["checks"] <= 0) or
            (name == "archive" and row["docs"] <= 0) or
            (name.startswith("test-") and row["tests"] <= 0) or
            (name == "test-1" and row["custom"] != 9)):
        row["exit"] = 1
    return row


class Cohort:
    def __init__(self, report, journal, source, cache, output, canceled):
        self.report, self.journal, self.source = report, journal, source
        self.cache, self.output, self.canceled = cache, output, canceled
        self.containers, self.outcomes, self.active = [], {}, set()
        self.lock = threading.Lock()

    def stop(self):
        with self.lock:
            containers = list(self.containers)
        for container in containers:
            container.close()

    def stage(self, name):
        if self.canceled.is_set():
            raise Canceled("run canceled before stage")
        folder = self.output / name
        folder.mkdir()
        memory, cpus = LIMITS[name]
        box = None
        with self.lock:
            self.active.add(name)
        try:
            box = Tracked(self.report["image"], memory=memory*GIB, cpus=cpus, deadline=900,
                          journal=self.journal)
            with self.lock:
                self.containers.append(box)
            if self.canceled.is_set():
                raise Canceled("run canceled during container admission")
            if box.proof["seccomp_profile_sha256"] != self.report["seccomp_sha256"]:
                raise RuntimeError("approved seccomp identity differs")
            with self.source.open("rb") as source:
                result = execute(box, ["python3", "/opt/box/runner.py", "source"],
                                 folder / "source.log", stdin=source, canceled=self.canceled)
            observed_failure(result)
            if self.canceled.is_set():
                raise Canceled("run canceled during source transfer")
            if not result["success"]:
                row = dict(exit=1, tests=0, custom=0, docs=0, checks=0)
            else:
                if name == "archive":
                    self.transfer(box, self.cache, "/work/dependencies.tar.gz", folder / "cache.log")
                elif name.startswith("test-"):
                    self.transfer(box, self.output / "archive/tests.tar.zst",
                                  "/work/source/tests.tar.zst", folder / "archive.log")
                result = execute(box, ["python3", "/opt/box/runner.py", "run", name],
                                 folder / "job.log", canceled=self.canceled)
                observed_failure(result)
                if self.canceled.is_set():
                    raise Canceled("run canceled during workload execution")
                row = counts(name, (folder / "job.log").read_text(errors="replace"),
                             0 if result["success"] else 1)
                if row["exit"] == 0 and name == "archive":
                    export(box, "archive", folder / "tests.tar.zst")
            with self.lock:
                self.outcomes[name] = row
            return row["exit"] == 0
        except WorkloadFailure:
            with self.lock:
                self.outcomes[name] = dict(exit=1, tests=0, custom=0, docs=0, checks=0)
            raise
        finally:
            try:
                if box:
                    box.close()
            finally:
                with self.lock:
                    self.active.discard(name)

    def transfer(self, box, path, destination, log):
        # Fixed destination, controller-selected opaque source. Never unpack on the host.
        code = "import shutil,sys; f=open(" + repr(destination) + ",'xb'); shutil.copyfileobj(sys.stdin.buffer,f); f.close()"
        with path.open("rb") as source:
            result = execute(box, ["python3", "-c", code], log, stdin=source, canceled=self.canceled)
        observed_failure(result)
        if not result["success"]:
            raise RuntimeError("bounded opaque input transfer unavailable")

    def parallel(self, names):
        capacity(sum(LIMITS[n][0] for n in names)*GIB) if len(names) == 1 else self.combined(names)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.stage, n) for n in names]
            return all([f.result() for f in futures])

    @staticmethod
    def combined(names):
        # Individual admission still runs in Container; reserve the complete cohort first.
        available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                             if line.startswith("MemAvailable:"))) * 1024
        if available < (34 + sum(LIMITS[n][0] for n in names))*GIB:
            raise RuntimeError("combined CI cohort reserve unavailable")

    def run(self):
        status = "unavailable"
        try:
            if not self.stage("fmt"):
                return "failed", self.outcomes
            if not self.parallel(("clippy", "archive")):
                return "failed", self.outcomes
            status = "passed" if self.parallel(("test-1", "test-2")) else "failed"
        finally:
            self.stop()
        return status, self.outcomes
