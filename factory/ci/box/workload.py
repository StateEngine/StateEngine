"""Fixed, bounded Linux cohort; only child outcomes supply authoritative stage results."""
import re
import threading

from box_result import details
from engine import Container, capacity
from transport import execute, WorkloadFailure

GIB = 1024**3
JOBS = ("fmt", "clippy", "archive", "test-1", "test-2", "windows-clippy")
MEMORY = 18 * GIB
CPUS = 8
DEADLINE = 1800
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def resource_limits(parallel=False):
    """Use one resource profile for the real dispatcher and its qualification."""
    if type(parallel) is not bool:
        raise ValueError("runner concurrency mode must be explicit")
    return {"memory": 12 * GIB, "cpus": 4, "workers": 4} if parallel else {
        "memory": MEMORY, "cpus": CPUS, "workers": 8}


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
    elif name == "windows-clippy":
        row["checks"] = int(code == 0)
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
    def __init__(self, report, journal, source, cache, output, canceled, *, all_features=False,
                 memory=MEMORY, cpus=CPUS, workers=8):
        if type(all_features) is not bool:
            raise ValueError("feature coverage must be an explicit boolean")
        self.all_features = all_features
        if (memory, cpus, workers) not in ((MEMORY, CPUS, 8), (12 * GIB, 4, 4)):
            raise ValueError("fixed serial or paired runner limits required")
        self.memory, self.cpus, self.workers = memory, cpus, workers
        self.report, self.journal, self.source = report, journal, source
        self.cache, self.output, self.canceled = cache, output, canceled
        self.containers, self.outcomes, self.active = [], {}, set()
        self.failed = []
        self.lock = threading.Lock()
        self.box = None

    def stop(self):
        with self.lock:
            containers = list(self.containers)
        for container in containers:
            container.close()

    def stage(self, name):
        if name not in JOBS:
            raise ValueError("unknown fixed CI stage")
        if self.canceled.is_set():
            raise Canceled("run canceled before stage")
        folder = self.output / name
        folder.mkdir()
        with self.lock:
            self.active.add(name)
        try:
            if self.box is None:
                box = Tracked(self.report["image"], memory=self.memory, cpus=self.cpus,
                              deadline=DEADLINE, journal=self.journal)
                with self.lock:
                    self.containers.append(box)
                    self.box = box
                if self.canceled.is_set():
                    raise Canceled("run canceled during container admission")
                if box.proof["seccomp_profile_sha256"] != self.report["seccomp_sha256"]:
                    raise RuntimeError("approved seccomp identity differs")
                with self.source.open("rb") as source:
                    result = execute(box, ["python3", "/opt/box/runner.py", "source"],
                                     folder / "source.log", stdin=source, canceled=self.canceled)
                observed_failure(result)
                if not result["success"]:
                    raise RuntimeError("source transfer unavailable")
            box = self.box
            if self.canceled.is_set():
                raise Canceled("run canceled during stage admission")
            if name == "archive":
                self.transfer(box, self.cache, "/work/dependencies.tar.gz", folder / "cache.log")
            features = ["--all-features"] if self.all_features else []
            result = execute(box, ["python3", "/opt/box/runner.py", "--jobs", str(self.workers),
                                  *features, "run", name],
                             folder / "job.log", canceled=self.canceled)
            observed_failure(result)
            if self.canceled.is_set():
                raise Canceled("run canceled during workload execution")
            row = counts(name, (folder / "job.log").read_text(errors="replace"),
                         0 if result["success"] else 1)
            with self.lock:
                self.outcomes[name] = row
                if row["exit"] != 0:
                    # Only the failing test names and locations; the stage log
                    # itself never leaves the container boundary. A stage that
                    # failed without naming a test (a kill, a full disk, or a
                    # custom harness) says exactly that, so it cannot read as
                    # clean.
                    named = details((folder / "job.log").read_text(errors="replace"))
                    self.failed.extend(named or [f"{name}: failed; no test named"])
            return row["exit"] == 0
        except WorkloadFailure:
            with self.lock:
                self.outcomes[name] = dict(exit=1, tests=0, custom=0, docs=0, checks=0)
            raise
        finally:
            # One fresh container retains the compiled target until every stage
            # finishes. stop() remains the single outside custody join.
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

    @staticmethod
    def combined(names):
        # Retain the existing caller's admission API; stages now share one cap.
        capacity(MEMORY)

    def run(self):
        passed = {}
        try:
            for name in JOBS:
                if name != "fmt" and not passed.get("fmt"):
                    continue
                if name.startswith("test-") and not passed.get("archive"):
                    continue
                passed[name] = self.stage(name)
        finally:
            self.stop()
        return ("passed" if set(passed) == set(JOBS) and all(passed.values()) else "failed"), self.outcomes
