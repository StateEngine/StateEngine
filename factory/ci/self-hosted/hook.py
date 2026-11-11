#!/usr/bin/python3 -I
"""Fixed container-hook operations; repository code never executes on the host."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BOX = Path("/usr/local/lib/stateengine-box-ci/factory/ci/box")
sys.path.insert(0, str(BOX))
from custody import Journal
from dispatch import trusted
from engine import Container, capacity
from github_binding import policy_paths
from transport import execute, WorkloadFailure
from workload import Cohort, JOBS
from runner_slot import select, venue

CONFIG = Path("/etc/stateengine-ci/self-hosted.json")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def fetch_once(repository, path, token, raw=False):
    url = "https://api.github.com/repos/" + repository + "/" + path
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        response = urllib.request.build_opener(NoRedirect).open(request, timeout=30)
    except urllib.error.HTTPError as error:
        if not raw or error.code != 302:
            raise RuntimeError(f"repository read failed: HTTP {error.code}") from None
        target = urllib.parse.urlsplit(error.headers.get("Location", ""))
        if target.scheme != "https" or target.hostname != "codeload.github.com" or target.port:
            raise RuntimeError("archive redirect left the approved host") from None
        # The signed archive URL needs no credential on its second host.
        response = urllib.request.build_opener(NoRedirect).open(target.geturl(), timeout=30)
    with response:
        data = response.read(64 * 1024**2 + 1)
        declared = response.headers.get("Content-Length")
    if len(data) > 64 * 1024**2:
        raise RuntimeError("repository response exceeds bound")
    if declared is not None and len(data) < int(declared):
        raise http.client.IncompleteRead(data, int(declared) - len(data))
    return data if raw else json.loads(data)


def fetch(repository, path, token, raw=False):
    for attempt in range(3):
        try:
            return fetch_once(repository, path, token, raw)
        except (http.client.IncompleteRead, TimeoutError, urllib.error.URLError) as error:
            short = isinstance(error, http.client.IncompleteRead)
            if isinstance(error, urllib.error.URLError) and not isinstance(error.reason, TimeoutError):
                raise
            if attempt == 2:
                reason = "response ended early" if short else "read timed out"
                raise RuntimeError(f"repository {reason} after three attempts") from None
            # Repeat the complete idempotent GET; partial bytes never become a
            # source archive or a successful metadata observation.
            message = "Short repository response" if short else "Repository read timed out"
            print(message + "; retrying GET", file=sys.stderr, flush=True)
            time.sleep(0.25 * (2**attempt))


def config_at(slot="primary"):
    config = trusted(CONFIG)
    return config_values(select(config, slot))


def config_values(config):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", config["repository"]):
        raise RuntimeError("configured repository is invalid")
    report = trusted(Path(config["image_report"]))
    cache = Path(config["cache"])
    info = cache.lstat()
    if info.st_size > 3*1024**3 or info.st_uid or info.st_mode & 0o022 or not cache.is_file() or cache.is_symlink():
        raise RuntimeError("root-owned dependency snapshot required")
    with cache.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != config["cache_sha256"]:
            raise RuntimeError("dependency snapshot differs")
    return config, report


def approve_main(config, report, context, token):
    helper = config.get("main_approval_helper")
    if (not helper or context.get("GITHUB_REF") != "refs/heads/main"
            or context.get("GITHUB_EVENT_NAME") != "push"):
        return config, report
    path = Path(helper)
    info = path.lstat()
    if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o022:
        raise RuntimeError("fixed root-owned main approval helper required")
    # The credential crosses only this fixed process boundary via stdin. The
    # owner verifies the actual main workflow/merge through the repository API.
    child = subprocess.Popen(["/usr/bin/sudo", "-n", str(path)], stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    try:
        child.communicate(json.dumps({"context": context, "token": token}).encode(), timeout=3900)
        if child.returncode:
            print("Main approval did not finish; using the last published approval", file=sys.stderr, flush=True)
    except BaseException:
        if child.poll() is None:
            arguments = Path("/proc", str(child.pid), "cmdline").read_bytes().split(b"\0")
            if str(path).encode() in arguments:
                child.terminate()
            elif child.poll() is None:
                raise RuntimeError("approval helper identity changed; preserving process custody")
            child.wait(timeout=210)
        raise
    return config_at(config.get("slot", "primary"))


def canceled(*_):
    raise InterruptedError("runner canceled this exact preparation")


def write(path, value):
    with path.open("x") as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())


def changed_policy(repository, source, token, policy):
    commit = fetch(repository, "git/commits/" + source, token)
    if not isinstance(commit, dict) or commit.get("sha") != source:
        raise RuntimeError("source commit could not be read")
    tree_id = commit.get("tree", {}).get("sha")
    if not isinstance(tree_id, str) or not re.fullmatch(r"[a-f0-9]{40}", tree_id):
        raise RuntimeError("source tree identity unavailable")
    tree = fetch(repository, "git/trees/" + tree_id + "?recursive=1", token)
    if (not isinstance(tree, dict) or tree.get("sha") != tree_id or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list)
            or any(not isinstance(row, dict) or not isinstance(row.get("path"), str) for row in tree["tree"])
            or len({row["path"] for row in tree["tree"]}) != len(tree["tree"])):
        raise RuntimeError("complete source tree could not be read")
    paths = {row["path"]: row for row in tree["tree"]}
    changed = sorted(policy_paths(paths) - policy.keys())
    for path, expected in policy.items():
        node = paths.get(path)
        if node is None or node.get("type") != "blob" or node.get("mode") not in {"100644", "100755"}:
            changed.append(path)
            continue
        observed = fetch(repository, "contents/" + urllib.parse.quote(path, safe="/") + "?ref=" + source, token)
        if not isinstance(observed, dict) or observed.get("encoding") != "base64" or not isinstance(observed.get("content"), str):
            raise RuntimeError("approved CI policy could not be read")
        content = base64.b64decode(observed["content"].replace("\n", ""), validate=True)
        if hashlib.sha256(content).hexdigest() != expected:
            changed.append(path)
    return sorted(changed)


def prepare(request, config, report, context):
    capacity(2*1024**3)
    job = request["args"].get("container")
    if not job or job.get("image") != "stateengine-ci-approved":
        raise RuntimeError("the approved job container is required")
    if request["args"].get("services") or job.get("userMountVolumes") or job.get("createOptions"):
        raise RuntimeError("services, candidate mounts and container options are unsupported")
    env = job.get("environmentVariables", {})
    repository, source = context["GITHUB_REPOSITORY"], context["GITHUB_SHA"]
    if repository != config["repository"] or not re.fullmatch(r"[a-f0-9]{40}", source):
        raise RuntimeError("source repository or commit differs")
    token = env.get("CI_SOURCE_TOKEN", "")
    if not token:
        raise RuntimeError("the ephemeral repository read token is absent")
    config, report = approve_main(config, report, context, token)
    # Policy is checked through the repository API, without extracting candidate
    # bytes onto the host or trusting a manifest written by the candidate.
    changed = changed_policy(repository, source, token, report["policy"])
    directory = Path(config["state"]) / uuid.uuid4().hex
    directory.mkdir(mode=0o700)
    # Policy drift permits only fixed metadata operations. No candidate archive
    # is downloaded or unpacked on this machine until policy is approved.
    if not changed:
        with (directory / "source.tar.gz").open("xb") as output:
            output.write(fetch(repository, "tarball/" + source, token, raw=True))
    write(directory / "binding.json", {"repository": repository, "source": source,
        "slot": config.get("slot", "primary"),
        "run": context["GITHUB_RUN_ID"], "attempt": context["GITHUB_RUN_ATTEMPT"], "policy_changed": changed,
        "approval": {"image_report": config["image_report"], "cache": config["cache"],
                     "cache_sha256": config["cache_sha256"], "image": report["image"]},
        "all_features": context.get("GITHUB_REF") == "refs/heads/main" and
            context.get("GITHUB_EVENT_NAME") in {"schedule", "workflow_dispatch"}})
    return {"state": {"job": directory.name}, "isAlpine": False}


def directory_at(request, config):
    identity = (request.get("state") or {}).get("job", "")
    if not re.fullmatch(r"[a-f0-9]{32}", identity):
        raise RuntimeError("hook job identity is absent")
    directory = Path(config["state"]) / identity
    if directory.is_symlink() or not directory.is_dir() or directory.stat().st_uid != os.getuid():
        raise RuntimeError("private hook job is unavailable")
    if json.loads((directory / "binding.json").read_text()).get("slot") != config.get("slot", "primary"):
        raise RuntimeError("hook job belongs to another runner slot")
    return directory


def check_step(config, report, directory, results):
    folder = directory / "check"
    folder.mkdir()
    box = Container(report["image"], memory=2*1024**3, cpus=2, deadline=180, journal=journal_at(config))
    try:
        if box.proof["seccomp_profile_sha256"] != report["seccomp_sha256"]:
            raise RuntimeError("approved seccomp identity differs")
        with (directory / "source.tar.gz").open("rb") as source:
            outcome = execute(box, ["python3", "/opt/box/runner.py", "source"], folder / "source.log", stdin=source)
        if not outcome["success"]:
            return False
        # The only step environment entering the container is the required job
        # result object. The source credential and runner state remain outside.
        with (folder / "results.json").open("xb") as output:
            output.write(json.dumps(results).encode())
        with (folder / "results.json").open("rb") as source:
            outcome = execute(box, ["python3", "-c", "import os,sys,subprocess; "
                "os.environ['RESULTS']=sys.stdin.read(); "
                "sys.exit(subprocess.run(['python3','scripts/ci/check.py'],cwd='/work/source').returncode)"],
                folder / "check.log", stdin=source)
        return outcome["success"]

    finally:
        box.close()


def script_step(request, config, report, directory):
    args = request["args"]
    # The shim reads the runner-generated script, but never executes it. Only
    # these four literal operations are admitted by this workflow adapter.
    operation = request.get("operation")
    if operation not in {"changes", "route", "linux", "check"}:
        raise RuntimeError("only the four fixed CI operations are supported")
    binding = json.loads((directory / "binding.json").read_text())
    snapshot = binding.get("approval")
    if snapshot is not None:
        if (not isinstance(snapshot, dict)
                or set(snapshot) != {"image_report", "cache", "cache_sha256", "image"}
                or binding.get("repository") != config["repository"]):
            raise RuntimeError("job approval snapshot is malformed")
        config, report = config_values({**config, **{key: snapshot[key]
            for key in ("image_report", "cache", "cache_sha256")}})
        if report["image"] != snapshot["image"]:
            raise RuntimeError("job approval image differs")
    changed = binding.get("policy_changed", [])
    if changed and operation not in {"changes", "route"}:
        if operation == "linux":
            print("Linux infrastructure unavailable: approved CI policy changed; running on hosted",
                  file=sys.stderr, flush=True)
            return {"exit_code": 0, "outputs": {"status": "unavailable"}}
        raise RuntimeError("approved CI policy changed; this workload must run on hosted")
    if operation == "changes":
        # Conservative full checking avoids running a candidate change detector
        # on the host and needs no shared Git checkout.
        return {"exit_code": 0, "outputs": {"rust": "true", "windows": "true"}}
    if operation == "route":
        return {"exit_code": 0, "outputs": {"route": "hosted" if changed else "box"}}
    if operation == "linux":
        return linux_step(config, report, directory, all_features=binding.get("all_features", False))
    capacity(2*1024**3)
    with venue(config):
        journal = journal_at(config)
        journal.reconcile()
        results = json.loads(args.get("environmentVariables", {}).get("RESULTS", "null"))
        if not isinstance(results, dict):
            raise RuntimeError("required job results are absent")
        success = check_step(config, report, directory, results)
    return {"exit_code": 0 if success else 1}


def journal_at(config):
    return Journal(slot=config["slot"] if config.get("parallel") else None)


def linux_step(config, report, directory, *, all_features=False):
    canceled = threading.Event()
    cohort = None
    outcomes = {}
    unavailable = False

    def stop(*_):
        canceled.set()
        if cohort:
            cohort.stop()
        raise InterruptedError("runner canceled this exact job")

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        memory = (9 if config.get("parallel") else 18) * 1024**3
        capacity(memory)
        with venue(config):
            journal = journal_at(config)
            journal.reconcile()
            print("Feature coverage: " + ("all features" if all_features else "default features"),
                  file=sys.stderr, flush=True)
            cohort = Cohort(report, journal, directory / "source.tar.gz", Path(config["cache"]), directory,
                            canceled, all_features=all_features,
                            memory=memory, cpus=4 if config.get("parallel") else 8,
                            workers=4 if config.get("parallel") else 8)
            try:
                for name in JOBS:
                    if name != "fmt" and not outcomes.get("fmt"):
                        continue
                    if name.startswith("test-") and not outcomes.get("archive"):
                        continue
                    print("Container stage: " + name, file=sys.stderr, flush=True)
                    try:
                        outcomes[name] = cohort.stage(name)
                    except Exception as error:
                        print(f"Container stage {name} refused: {type(error).__name__}: {error}",
                              file=sys.stderr, flush=True)
                        write(directory / (name + "-failure.json"), {"reason": str(error)})
                        if isinstance(error, WorkloadFailure):
                            outcomes[name] = False
                        else:
                            raise
                write(directory / "outcomes.json", outcomes)
            finally:
                try:
                    cohort.stop()
                finally:
                    journal.reconcile()
    except InterruptedError:
        raise
    except Exception as error:
        if canceled.is_set():
            raise InterruptedError("runner canceled this exact job") from error
        unavailable = True
        print(f"Linux infrastructure unavailable: {type(error).__name__}: {error}",
              file=sys.stderr, flush=True)
    # A cleanup or later admission failure cannot erase an already observed red.
    failed = any(value is False for value in outcomes.values()) or bool(cohort and
        any(row.get("exit") == 1 for row in cohort.outcomes.values()))
    if not failed and not unavailable and set(outcomes) != set(JOBS):
        unavailable = True
    status = "failed" if failed else "unavailable" if unavailable else "passed"
    windows = "passed" if outcomes.get("windows-clippy") is True else "unavailable"
    if outcomes.get("windows-clippy") is False:
        windows = "failed"
    return {"exit_code": 1 if failed else 0, "outputs": {"status": status, "windows": windows}}


def main():
    signal.signal(signal.SIGTERM, canceled)
    signal.signal(signal.SIGINT, canceled)
    raw = sys.stdin.buffer.read(1024**2 + 1)
    if len(raw) > 1024**2:
        raise RuntimeError("hook input exceeds bound")
    request = json.loads(raw)
    if len(sys.argv) > 2:
        raise ValueError("only one fixed runner slot argument is allowed")
    config, report = config_at(sys.argv[1] if len(sys.argv) == 2 else "primary")
    if request["command"] == "prepare_job":
        return {"response": prepare(request, config, report, request["context"]), "exit_code": 0}
    if request["command"] == "cleanup_job":
        # Native custody is reconciled under the existing CI mutex.
        with venue(config):
            journal_at(config).reconcile()
        return {"exit_code": 0}
    if request["command"] == "run_script_step":
        return script_step(request, config, report, directory_at(request, config))
    raise RuntimeError("container actions are unsupported; use the fixed operations")


if __name__ == "__main__":
    try:
        print(json.dumps(main()), flush=True)
    except Exception as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        print(json.dumps({"exit_code": 1}), flush=True)
        raise SystemExit(1)
