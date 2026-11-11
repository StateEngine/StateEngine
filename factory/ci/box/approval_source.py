"""Bind automatic CI approval to a merged main commit, never a PR checkout."""
import base64
import json
from pathlib import Path
import re
import subprocess
import uuid


def main_source(api, repository, context):
    source = context.get("GITHUB_SHA", "")
    if (context.get("GITHUB_REPOSITORY") != repository
            or context.get("GITHUB_EVENT_NAME") != "push"
            or context.get("GITHUB_REF") != "refs/heads/main"
            or not re.fullmatch("[a-f0-9]{40}", source)):
        raise ValueError("automatic approval requires an exact main push")
    run_id, attempt = context.get("GITHUB_RUN_ID", ""), context.get("GITHUB_RUN_ATTEMPT", "")
    if not str(run_id).isdigit() or not str(attempt).isdigit() or min(int(run_id), int(attempt)) <= 0:
        raise ValueError("automatic approval requires a run and attempt")
    run = api.get("actions/runs/" + str(run_id))
    if (run.get("id") != int(run_id) or run.get("run_attempt") != int(attempt)
            or run.get("event") != "push" or run.get("head_branch") != "main"
            or run.get("head_sha") != source
            or run.get("path", "").split("@")[0] != ".github/workflows/ci.yml"
            or run.get("repository", {}).get("full_name") != repository
            or run.get("head_repository", {}).get("full_name") != repository
            or run.get("head_repository", {}).get("fork") is not False):
        raise ValueError("approval request does not match its main workflow run")
    current_main(api, source)
    pulls = api.get("commits/" + source + "/pulls?per_page=100")
    if not isinstance(pulls, list) or len(pulls) >= 100:
        raise ValueError("the complete merge association is unavailable")
    merged = [pr for pr in pulls if pr.get("merged_at") and pr.get("merge_commit_sha") == source
              and pr.get("base", {}).get("ref") == "main"
              and pr.get("base", {}).get("repo", {}).get("full_name") == repository]
    if len(merged) != 1:
        raise ValueError("automatic approval requires one merged pull request on main")
    return {"source": source, "run": int(run_id), "attempt": int(attempt), "pull_request": merged[0]["number"]}


def current_main(api, expected):
    reference = api.get("git/ref/heads/main")
    if (reference.get("ref") != "refs/heads/main"
            or reference.get("object", {}).get("type") != "commit"
            or reference.get("object", {}).get("sha") != expected):
        raise ValueError("main advanced; only its newest merged commit may update approval")


def fetch_main(repository, source, token, directory, *, scoped=False):
    """Fetch bare objects with an ephemeral header; no checkout, hooks or secret file."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("configured repository is invalid")
    directory = Path(directory)
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(directory.parent),
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_TERMINAL_PROMPT": "0"}
    def git(*arguments, authenticated=False):
        env = dict(environment)
        if authenticated:
            credential = base64.b64encode(("x-access-token:" + token).encode()).decode()
            env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                       GIT_CONFIG_VALUE_0="Authorization: Basic " + credential)
        command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "http.followRedirects=false", *arguments]
        unit = "se-ci-source-" + uuid.uuid4().hex if authenticated and scoped else None
        if unit:
            (directory.parent / "source-fetch.json").write_text(json.dumps({"unit": unit, "source": source}))
            command = ["systemd-run", "--scope", "--quiet", "--collect", "--unit=" + unit,
                       "-p", "RuntimeMaxSec=180", "-p", "MemoryMax=512M", "-p", "MemorySwapMax=0",
                       "-p", "TasksMax=64", *command]
        try:
            result = subprocess.run(command, env=env, capture_output=True, timeout=190, close_fds=True)
        finally:
            if unit:
                # Stop the exact generated scope, including Git's HTTP child.
                # Exit 5 means the completed, collected scope is already absent.
                stopped = subprocess.run(["systemctl", "stop", unit + ".scope"], env=environment,
                                         capture_output=True, timeout=30, close_fds=True)
                if stopped.returncode not in (0, 5):
                    raise RuntimeError("source transport closure is unproved")
        if result.returncode:
            raise RuntimeError("trusted main fetch failed; credential-bearing transport output withheld")
        return result.stdout
    git("init", "--bare", str(directory))
    git("-C", str(directory), "fetch", "--no-tags", "--depth=1", "https://github.com/" + repository + ".git",
        source + ":refs/heads/main", authenticated=True)
    if git("-C", str(directory), "rev-parse", "main").decode().strip() != source:
        raise ValueError("fetched main commit differs")
    return directory
