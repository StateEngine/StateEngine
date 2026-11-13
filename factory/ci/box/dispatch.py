#!/usr/bin/env python3
"""Trusted outbound poller. Not a runner: repository bytes execute only in fixed containers."""
import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from app import App
from custody import Journal, inventory
from dispatch_binding import Request, bind, jobs, job, live
from workload import Canceled, Cohort, resource_limits
from box_result import NAME, external_id, report, text

STOP = threading.Event()


@contextmanager
def read_budget(seconds):
    # This Linux poller admits work on its main thread, before spawning monitors.
    # A socket inactivity timeout alone does not bound a trickling HTTP response.
    def expired(*_):
        raise TimeoutError("offer observation exceeded its remaining reservation")
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise RuntimeError("offer observation cannot replace an existing deadline")
    previous = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def trusted(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("root-owned controller configuration required")
    return json.loads(path.read_text())


def save(path, value):
    with path.open("x") as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def venue(config, recover=False):
    with ExitStack() as stack:
        # These are pre-existing files with narrow ACL grants; never create a missing lock.
        for path in [*config["vm_locks"], config["ci_lock"]]:
            fd = stack.enter_context(open(path, "r"))
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = json.loads(Path(config["guest_state"]).read_text())
        if (state["schema"] != "guest-owner/v1" or state["phase"] != "idle" or
                state["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip() or
                any(state[k] is not None for k in ("guest", "owner", "launcher", "qemu", "swtpm"))):
            raise RuntimeError("guest reservation is not independently idle")
        if not recover:
            from workload import Cohort
            Cohort.combined(("test-1", "test-2"))
        yield


def config_at(path):
    config = trusted(path)
    if (set(config) != {"repository_id", "workflow_id", "app_id", "installation_id", "image_report",
                        "cache", "cache_sha256", "state", "vm_locks", "ci_lock", "guest_state"} or
            any(type(config[k]) is not int or config[k] <= 0
                for k in ("repository_id", "workflow_id", "app_id", "installation_id")) or
            not isinstance(config["vm_locks"], list) or len(config["vm_locks"]) != 2 or
            any(not isinstance(value, str) or not Path(value).is_absolute()
                for value in [*config["vm_locks"], config["guest_state"]]) or
            len(set(config["vm_locks"])) != 2):
        raise RuntimeError("controller configuration differs from the dedicated repository/venue")
    image = trusted(Path(config["image_report"]))
    required = {".github/workflows/ci.yml", ".github/actions/rust/action.yml", ".github/actions/test/action.yml",
                ".config/nextest.toml", "scripts/ci/custom.py", "scripts/ci/installation_account.py",
                "Cargo.lock", "Cargo.toml"}
    if not required.issubset(image["policy"]):
        raise RuntimeError("image policy does not cover commands, installation, routing and dependencies")
    image["policy_digest"] = hashlib.sha256(json.dumps(image["policy"], sort_keys=True).encode()).hexdigest()
    cache = Path(config["cache"])
    if cache.stat().st_size > 3*1024**3:
        raise RuntimeError("dependency snapshot exceeds bound")
    info = cache.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("root-owned dependency snapshot required")
    with cache.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != config["cache_sha256"]:
            raise RuntimeError("dependency snapshot identity differs")
    return config, image


def publish(api, value):
    payload = value["report"]
    check_id = payload["check_id"]
    observed = api.get("check-runs/" + str(check_id))
    if (observed.get("app", {}).get("id") != value["app_id"] or
            observed.get("external_id") != external_id(payload["binding"]) or
            observed.get("head_sha") != payload["binding"]["checkout"]):
        raise RuntimeError("terminal publication no longer belongs to this App/binding")
    # Never overwrite an observed failure with another disposition.
    if observed.get("conclusion") == "failure" and payload["status"] != "failed":
        raise RuntimeError("observed bound failure cannot be replaced")
    if payload["status"] == "passed":
        # Revalidate even on restart/retry, immediately before the external write.
        request = value.get("request")
        if request is None:
            raise RuntimeError("saved success has no current request provenance")
        request = Request(**request)
        if request.identity != payload["binding"]:
            raise RuntimeError("saved success request binding differs")
        if not live(api, request):
            return False
        if job(jobs(api, request.identity["run"], request.identity["attempt"]), "linux-box")["status"] != "in_progress":
            return False
        if not live(api, request):
            return False
    api.write("check-runs/" + str(check_id), {"status": "completed",
        "conclusion": {"passed": "success", "failed": "failure", "unavailable": "neutral"}[payload["status"]],
        "output": {"title": NAME + ": " + payload["status"],
                   "summary": text(payload)}}, "PATCH")
    return True


def finish(api, request, check_id, image, status, stages, folder, app_id, failed=None):
    terminal = folder / "terminal.json"
    if not terminal.exists():
        save(terminal, {"app_id": app_id, "request": asdict(request), "report": report(
            request.identity, check_id, image["image"], image["policy_digest"], status, stages,
            failed)})
    # The first durable terminal observation is immutable, even after a lost API reply.
    publish(api, json.loads(terminal.read_text()))


def retry_terminal(api, state):
    for path in state.glob("*/terminal.json"):
        value = json.loads(path.read_text())
        published = path.with_name("published")
        if not published.exists():
            accepted = publish(api, value)
            save(published, {"published": accepted, "reason": None if accepted else "run no longer live"})


def handshake(api, request, *, seconds=30, clock=time.monotonic, sleep=time.sleep):
    end = clock()+seconds
    class ReservedAPI:
        def get(self, *args, **kwargs):
            remaining = end-clock()
            if remaining <= 0 or STOP.is_set():
                raise TimeoutError("offer reservation expired")
            with read_budget(remaining):
                value = api.get(*args, **kwargs, timeout=remaining)
            if clock() >= end or STOP.is_set():
                raise TimeoutError("offer reservation expired during observation")
            return value
    reserved = ReservedAPI()
    while clock() < end and not STOP.is_set():
        try:
            active = live(reserved, request)
            if clock() >= end or STOP.is_set() or not active:
                return False
            rows = jobs(reserved, request.identity["run"], request.identity["attempt"])
        except (TimeoutError, RuntimeError):
            return False
        if clock() >= end or STOP.is_set():
            return False
        targets = [j for j in rows if j["name"] == "linux-box"]
        if len(targets) > 1:
            return False
        if targets and targets[0]["status"] == "in_progress":
            return job(rows, "linux-route")["conclusion"] == "success"
        if targets and targets[0]["status"] == "completed":
            return False
        sleep(min(2, max(0, end-clock())))
    return False


def execute(api, request, check_id, config, image, folder, journal):
    identity = request.identity
    source = folder / "source.tar.gz"
    # No candidate source is unpacked on the host.
    data = api.get("tarball/" + identity["checkout"], limit=64*1024**2, raw=True)
    with source.open("xb") as output:
        output.write(data)
    del data
    canceled, done = threading.Event(), threading.Event()
    cohort = Cohort(image, journal, source, Path(config["cache"]), folder, canceled,
                    **resource_limits(config.get("parallel", False)))
    reason, expired = [], []

    def watch():
        end = time.monotonic()+1440
        while not done.wait(2):
            try:
                deadline = time.monotonic() >= end
                active = live(api, request) and job(jobs(api, identity["run"], identity["attempt"]), "linux-box")["status"] == "in_progress"
                if not STOP.is_set() and not deadline and active:
                    continue
                reason.append("deadline" if deadline else "canceled")
                if deadline:
                    with cohort.lock:
                        expired.extend(cohort.active)
            except Exception:
                reason.append("transport unavailable")
            canceled.set()
            try:
                cohort.stop()
            except Exception:
                pass  # Persistent records retain custody; final reconciliation must still join.
            return

    monitor = threading.Thread(target=watch)
    monitor.start()
    status = "unavailable"
    try:
        status, _ = cohort.run()
    except Exception as error:
        # Diagnostics stay private; only typed bounded facts leave the host.
        save(folder / "controller-error.json", {"type": type(error).__name__, "reason": str(error)[:2000]})
        status = "unavailable"
    finally:
        done.set()
        monitor.join()
        try:
            cohort.stop()
        except Exception:
            reason.append("cleanup unavailable")
    stages = cohort.outcomes
    # Attribute a workload deadline only to stages actually running at that instant.
    for name in expired:
        stages.setdefault(name, dict(exit=1, tests=0, custom=0, docs=0, checks=0))["exit"] = 1
    if any(row["exit"] != 0 for row in stages.values()):
        status = "failed"
    elif canceled.is_set() or reason:
        status = "unavailable"
    finish(api, request, check_id, image, status, stages, folder, config["app_id"],
           getattr(cohort, "failed", []))


def consider(api, candidate, config, image, journal):
    run_id, attempt = candidate["id"], candidate["run_attempt"]
    key = str(run_id) + "-" + str(attempt)
    state = Path(config["state"])
    claim = state / (key + ".claim")
    if claim.exists():
        return
    request = bind(api, run_id, attempt, config["repository_id"], config["workflow_id"], image["policy"])
    with venue(config):
        journal.reconcile()
        if STOP.is_set():
            return
        # Tombstone before check creation: a lost API response cannot cause a second offer.
        save(claim, {"binding": request.identity})
        created = api.write("check-runs", {"name": NAME, "head_sha": request.identity["checkout"],
            "external_id": external_id(request.identity), "status": "queued"})
        if (created.get("app", {}).get("id") != config["app_id"] or
                created.get("external_id") != external_id(request.identity)):
            raise RuntimeError("created check belongs to a different App/binding")
        check_id = created["id"]
        folder = state / key
        folder.mkdir(mode=0o700)
        save(folder / "binding.json", {**asdict(request), "check_id": check_id})
        if not handshake(api, request):
            finish(api, request, check_id, image, "unavailable", {}, folder, config["app_id"])
            return
        api.write("check-runs/" + str(check_id), {"status": "in_progress"}, "PATCH")
        try:
            execute(api, request, check_id, config, image, folder, journal)
        except Exception:
            # Never clear persistent custody on a failed engine read/cleanup.
            # Do not erase a known failure if its publication response was lost.
            # Remaining custody stays fenced even when reconciliation is unavailable.
            finish(api, request, check_id, image, "unavailable", {}, folder, config["app_id"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    config, image = config_at(args.config)
    state = Path(config["state"])
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("controller private state unavailable")
    key = Path(os.environ["CREDENTIALS_DIRECTORY"]) / "app-key.pem"
    api = App(config["app_id"], config["installation_id"], key)
    journal = Journal()
    while not STOP.is_set():
        try:
            retry_terminal(api, state)
            with venue(config, recover=True):
                journal.reconcile()
            runs = api.get(f"actions/workflows/{config['workflow_id']}/runs?status=in_progress&per_page=20")
            if runs["total_count"] > 20:
                raise RuntimeError("active run inventory exceeds bound; hosted fallback remains available")
            for candidate in runs["workflow_runs"]:
                try:
                    consider(api, candidate, config, image, journal)
                except Exception as error:
                    print("Box admission/transport unavailable: " + type(error).__name__ + ": " + str(error)[:2000], flush=True)
        except Exception as error:
            print("Box infrastructure unavailable: " + type(error).__name__ + ": " + str(error)[:2000], flush=True)
        if args.once:
            return
        STOP.wait(10)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    main()
