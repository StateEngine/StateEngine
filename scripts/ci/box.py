"""Hosted read-only routing/result consumer. Infrastructure absence selects hosted CI."""
import argparse
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request
import urllib.parse

from box_result import NAME, binding, failures, outcome, select


class API:
    def __init__(self):
        self.repository = os.environ["GITHUB_REPOSITORY"]
        self.token = os.environ["GH_TOKEN"]

    def checks(self, checkout):
        request = urllib.request.Request(
            "https://api.github.com/repos/" + self.repository + "/commits/" + checkout +
            "/check-runs?check_name=" + urllib.parse.quote(NAME) + "&filter=all&per_page=100",
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise ValueError("check response exceeds limit")
            value = json.loads(data)
            if value["total_count"] > 100:
                raise ValueError("ambiguous check pagination")
            return value["check_runs"]
        except (urllib.error.URLError, TimeoutError):
            raise RuntimeError("check transport unavailable; credential details withheld") from None


def context(env):
    return binding(int(env["GITHUB_REPOSITORY_ID"]), int(env["GITHUB_RUN_ID"]),
                   int(env["GITHUB_RUN_ATTEMPT"]), env["GITHUB_SHA"], env["BOX_HEAD_SHA"])


def eligible(env, event):
    if env.get("BOX_CI_ENABLED") != "true":
        return False
    if env.get("GITHUB_EVENT_NAME") == "push":
        return env.get("GITHUB_REF") == "refs/heads/main"
    if env.get("GITHUB_EVENT_NAME") != "pull_request":
        return False
    pr = event.get("pull_request", {})
    repo = pr.get("head", {}).get("repo", {})
    return repo.get("full_name") == env["GITHUB_REPOSITORY"] and repo.get("fork") is False


def route(api, identity, app, *, seconds=90, clock=time.monotonic, sleep=time.sleep):
    end = clock() + seconds
    while True:
        try:
            checks = api.checks(identity["checkout"])
            if failures(checks, app, identity):
                return "box"
            row = select(checks, app, identity)
            if row and row.get("status") == "queued":
                return "box"
        except (RuntimeError, ValueError, KeyError, TypeError):
            pass
        if clock() >= end:
            return "hosted"
        sleep(min(5, max(0, end-clock())))


def wait(api, identity, app, *, seconds=1500, clock=time.monotonic, sleep=time.sleep):
    end = clock() + seconds
    selected_id = None
    while True:
        try:
            checks = api.checks(identity["checkout"])
            if failures(checks, app, identity):
                return "failed"
            row = select(checks, app, identity)
            if row is None or (selected_id is not None and row["id"] != selected_id):
                return "unavailable"
            selected_id = row["id"]
            result = outcome(row, identity)
            if result:
                return result
        except (RuntimeError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            # Malformed or wrong-bound output never supplies success.
            pass
        if clock() >= end:
            return "unavailable"
        sleep(min(10, max(0, end-clock())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("route", "wait"))
    args = parser.parse_args()
    identity = context(os.environ)
    fallback = "hosted" if args.action == "route" else "unavailable"
    try:
        app = int(os.environ["BOX_CI_APP_ID"])
        if app <= 0:
            raise ValueError("App ID missing")
        if args.action == "route":
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
            result = route(API(), identity, app) if eligible(os.environ, event) else fallback
        else:
            result = wait(API(), identity, app)
    except (ValueError, KeyError, OSError):
        result = fallback
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(("route" if args.action == "route" else "status") + "=" + result + "\n")
    print("Linux box " + args.action + ": " + result)
    return 1 if result == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
