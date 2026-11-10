#!/usr/bin/python3 -I
"""Fixed container-hook operations; repository code never executes on the host."""
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid

BOX = Path("/usr/local/lib/stateengine-box-ci/factory/ci/box")
sys.path.insert(0, str(BOX))
from custody import Journal
from dispatch import trusted
from engine import Container, capacity
from transport import execute
from workload import Cohort

CONFIG = Path("/etc/stateengine-ci/self-hosted.json")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def fetch(repository, path, token, raw=False):
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
    if len(data) > 64 * 1024**2:
        raise RuntimeError("repository response exceeds bound")
    return data if raw else json.loads(data)


def config_at():
    config = trusted(CONFIG)
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


@contextmanager
def venue(config):
    # Serialize against the existing CI controller. Guest admission is separate;
    # each actual container checks its bounded memory allocation before start.
    with open(config["ci_lock"], "r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


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
    changed = []
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
    return changed


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
    # Policy is checked through the repository API, without extracting candidate
    # bytes onto the host or trusting a manifest written by the candidate.
    changed = changed_policy(repository, source, token, report["policy"])
    directory = Path(config["state"]) / uuid.uuid4().hex
    directory.mkdir(mode=0o700)
    # Policy drift permits only fixed metadata operations. Candidate bytes are
    # neither downloaded nor executed on this machine until policy is approved.
    if not changed:
        with (directory / "source.tar.gz").open("xb") as output:
            output.write(fetch(repository, "tarball/" + source, token, raw=True))
    write(directory / "binding.json", {"repository": repository, "source": source,
        "run": context["GITHUB_RUN_ID"], "attempt": context["GITHUB_RUN_ATTEMPT"], "policy_changed": changed})
    return {"state": {"job": directory.name}, "isAlpine": False}


def directory_at(request, config):
    identity = (request.get("state") or {}).get("job", "")
    if not re.fullmatch(r"[a-f0-9]{32}", identity):
        raise RuntimeError("hook job identity is absent")
    directory = Path(config["state"]) / identity
    if directory.is_symlink() or not directory.is_dir() or directory.stat().st_uid != os.getuid():
        raise RuntimeError("private hook job is unavailable")
    return directory


def check_step(config, report, directory, results):
    folder = directory / "check"
    folder.mkdir()
    box = Container(report["image"], memory=2*1024**3, cpus=2, deadline=180, journal=Journal())
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
    changed = binding.get("policy_changed", [])
    if changed and operation not in {"changes", "route"}:
        raise RuntimeError("approved CI policy changed; this workload must run on hosted")
    if operation == "changes":
        # Conservative full checking avoids running a candidate change detector
        # on the host and needs no shared Git checkout.
        return {"exit_code": 0, "outputs": {"rust": "true", "windows": "true"}}
    if operation == "route":
        return {"exit_code": 0, "outputs": {"route": "hosted" if changed else "box"}}
    capacity(12*1024**3 if operation == "linux" else 2*1024**3)
    canceled = threading.Event()
    cohort = None
    def stop(*_):
        canceled.set()
        if cohort:
            cohort.stop()
        raise InterruptedError("runner canceled this exact job")
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    success = False
    with venue(config):
        journal = Journal()
        journal.reconcile()
        if operation == "check":
            results = json.loads(args.get("environmentVariables", {}).get("RESULTS", "null"))
            if not isinstance(results, dict):
                raise RuntimeError("required job results are absent")
            success = check_step(config, report, directory, results)
        else:
            cohort = Cohort(report, journal, directory / "source.tar.gz", Path(config["cache"]), directory, canceled)
            outcomes = {}
            try:
                for name in ("fmt", "clippy", "archive", "test-1", "test-2"):
                    if name != "fmt" and not outcomes.get("fmt"):
                        continue
                    if name.startswith("test-") and not outcomes.get("archive"):
                        continue
                    print("Container stage: " + name, file=sys.stderr, flush=True)
                    try:
                        outcomes[name] = cohort.stage(name)
                    except Exception as error:
                        outcomes[name] = False
                        write(directory / (name + "-failure.json"), {"reason": str(error)})
                success = len(outcomes) == 5 and all(outcomes.values()) and not canceled.is_set()
                write(directory / "outcomes.json", outcomes)
            finally:
                cohort.stop()
                journal.reconcile()
    return {"exit_code": 0 if success else 1,
            "outputs": {"status": "passed" if success else "failed"} if operation == "linux" else {}}


def main():
    raw = sys.stdin.buffer.read(1024**2 + 1)
    if len(raw) > 1024**2:
        raise RuntimeError("hook input exceeds bound")
    request = json.loads(raw)
    config, report = config_at()
    if request["command"] == "prepare_job":
        return {"response": prepare(request, config, report, request["context"]), "exit_code": 0}
    if request["command"] == "cleanup_job":
        # Native custody is reconciled under the existing CI mutex.
        with venue(config):
            Journal().reconcile()
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
