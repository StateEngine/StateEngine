"""Independently bind a live same-origin run before any source reaches a worker."""
import base64
from dataclasses import dataclass, asdict
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.parse

from github_binding import REPOSITORY, checkout_from_log, policy_paths
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts/ci"))
from box_result import binding


@dataclass(frozen=True)
class Request:
    identity: dict
    number: int
    changes_job: int


def jobs(api, run, attempt):
    value = api.get(f"actions/runs/{run}/attempts/{attempt}/jobs?per_page=100")
    if value["total_count"] > 100 or len(value["jobs"]) != value["total_count"]:
        raise ValueError("attempt job inventory incomplete")
    return value["jobs"]


def job(rows, name):
    selected = [j for j in rows if j["name"] == name]
    if len(selected) != 1:
        raise ValueError("one exact attempt job required: " + name)
    return selected[0]


def policy_at(api, checkout, approved):
    tree = api.get("git/trees/" + checkout + "?recursive=1")
    if tree.get("truncated") or policy_paths([p["path"] for p in tree["tree"] if p["type"] == "blob"]) != set(approved):
        raise ValueError("candidate CI/tool/dependency policy footprint differs")
    for path, digest in approved.items():
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("approved policy digest malformed")
        value = api.get("contents/" + path + "?ref=" + checkout)
        data = base64.b64decode("".join(value["content"].split()), validate=True)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("candidate workflow/tool/dependency differs: " + path)


def bind(api, run_id, attempt, repository_id, workflow_id, approved):
    run = api.get(f"actions/runs/{run_id}")
    if (run["id"] != run_id or run["run_attempt"] != attempt or run["workflow_id"] != workflow_id or
            run["path"].split("@")[0] != ".github/workflows/ci.yml" or
            run["repository"]["id"] != repository_id or
            run["repository"]["full_name"] != REPOSITORY or
            run["head_repository"]["id"] != repository_id or run["head_repository"]["fork"] or
            run["status"] == "completed"):
        raise ValueError("run identity, current attempt or same-origin repository differs")
    number = 0
    if run["event"] == "pull_request":
        # GitHub can return an empty pull_requests association, including same-origin runs.
        query = urllib.parse.urlencode({"state": "open", "head": "StateEngine:" + run["head_branch"], "per_page": 100})
        prs = api.get("pulls?" + query)
        if len(prs) >= 100:
            raise ValueError("open PR inventory exceeds checked page")
        prs = [pr for pr in prs if pr["state"] == "open" and
               pr["head"]["sha"] == run["head_sha"] and
               pr["head"]["repo"]["id"] == repository_id and
               pr["head"]["ref"] == run["head_branch"]]
        if len(prs) != 1:
            raise ValueError("one exact open same-origin PR required")
        number = prs[0]["number"]
        pr = api.get(f"pulls/{number}")
        if (pr["state"] != "open" or pr["head"]["repo"]["id"] != repository_id or
                pr["base"]["repo"]["id"] != repository_id or pr["head"]["repo"]["fork"] or
                pr["head"]["sha"] != run["head_sha"] or pr["head"]["ref"] != run["head_branch"]):
            raise ValueError("PR closed, forked or superseded")
        checkout = pr["merge_commit_sha"]
    elif run["event"] == "push" and run["head_branch"] == "main":
        checkout = run["head_sha"]
        if api.get("git/ref/heads/main")["object"]["sha"] != checkout:
            raise ValueError("main run superseded")
    else:
        raise ValueError("unsupported event uses hosted CI")
    identity = binding(repository_id, run_id, attempt, checkout, run["head_sha"])
    rows = jobs(api, run_id, attempt)
    changes = job(rows, "changes")
    route = job(rows, "linux-route")
    if changes["conclusion"] != "success" or route["status"] != "in_progress":
        raise ValueError("routing window is not active after successful changes")
    actual = checkout_from_log(api.get(f"actions/jobs/{changes['id']}/logs", raw=True))
    if actual != checkout:
        raise ValueError("actual changes checkout differs from current run")
    policy_at(api, checkout, approved)
    return Request(identity, number, changes["id"])


def live(api, request):
    b = request.identity
    run = api.get(f"actions/runs/{b['run']}")
    if run["run_attempt"] != b["attempt"] or run["status"] == "completed":
        return False
    if request.number:
        pr = api.get(f"pulls/{request.number}")
        return (pr["state"] == "open" and pr["head"]["sha"] == b["head"] and
                pr["merge_commit_sha"] == b["checkout"])
    return api.get("git/ref/heads/main")["object"]["sha"] == b["checkout"]
