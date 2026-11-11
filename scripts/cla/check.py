"""Check authenticated agreement comments using only the trusted default-branch checkout."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
CONTEXT = "cla"


class GitHub:
    def __init__(self):
        self.repository = os.environ["GITHUB_REPOSITORY"]
        self.token = os.environ["GITHUB_TOKEN"]
        self.run_url = (f"https://github.com/{self.repository}/actions/runs/"
                        + os.environ["GITHUB_RUN_ID"])

    def request(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            f"https://api.github.com/repos/{self.repository}/{path}".rstrip("/"), data=body,
            headers={"Authorization": f"Bearer {self.token}",
                     "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json",
                     "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    def pages(self, path):
        page = 1
        while True:
            rows = self.request(f"{path}?per_page=100&page={page}")
            if not isinstance(rows, list):
                raise ValueError("GitHub returned an unreadable list")
            yield from rows
            if len(rows) < 100:
                return
            page += 1

    def status(self, head, state, description):
        self.request(f"statuses/{head}", {"state": state, "context": CONTEXT,
                     "description": description[:140], "target_url": self.run_url})


def individual_statement(login, digest):
    return ("I have read and agree to the StateEngine Individual Contributor License Agreement "
            f"(SHA-256: {digest}). I sign as @{login}.")


def entity_statement(login, digest, entity):
    return ("I have read and agree to the StateEngine Entity Contributor License Agreement "
            f"(SHA-256: {digest}). I am authorized to sign for {entity}, which owns or controls "
            f"my contributions. I sign as @{login}.")


def signed(comment, user, digests):
    # The account in the API envelope signs; names written by someone else do not.
    if (comment.get("user") or {}).get("id") != user["id"]:
        return False
    body = (comment.get("body") or "").strip()
    if body == individual_statement(user["login"], digests["individual"]):
        return True
    before = ("I have read and agree to the StateEngine Entity Contributor License Agreement "
              f"(SHA-256: {digests['entity']}). I am authorized to sign for ")
    after = f", which owns or controls my contributions. I sign as @{user['login']}."
    if body.startswith(before) and body.endswith(after):
        entity = body[len(before):-len(after)]
        return (bool(entity.strip()) and entity != "YOUR LEGAL ENTITY NAME"
                and len(entity) <= 200 and not re.search(r"[\r\n]", entity))
    return False


def check_pull(github, number):
    pull = github.request(f"pulls/{number}")
    if pull["state"] != "open":
        return True
    head = pull["head"]["sha"]
    github.status(head, "pending", "Checking contributor agreement signatures")
    repository = github.request("")
    branch = repository["default_branch"]
    if pull["base"]["repo"]["full_name"] != github.repository or pull["base"]["ref"] != branch:
        raise ValueError("agreement check requires a pull request targeting the default branch")
    trusted = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if github.request(f"git/ref/heads/{branch}")["object"]["sha"] != trusted:
        raise ValueError("trusted agreement checkout changed; rerun the check")
    if pull["commits"] > 250:
        raise ValueError("GitHub limits this commit list to 250; split the pull request")
    commits = list(github.pages(f"pulls/{number}/commits"))
    if len(commits) != pull["commits"]:
        raise ValueError("commit list is incomplete; retry the check")
    # Organization members and the repository owner are internal contributors.
    internal = pull.get("author_association") in {"OWNER", "MEMBER"}
    users = {} if internal else {pull["user"]["id"]: pull["user"]}
    for commit in commits:
        user = commit.get("author")
        if not user or user.get("type") != "User":
            raise ValueError("a commit has no human GitHub author; associate its email with an account")
        if not internal or user["id"] != pull["user"]["id"]:
            users[user["id"]] = user
    digests = {kind: hashlib.sha256((ROOT / f"docs/cla/{kind}.md").read_bytes()).hexdigest()
               for kind in ("individual", "entity")}
    comments = list(github.pages(f"issues/{number}/comments"))
    missing = [user for user in users.values()
               if not any(signed(comment, user, digests) for comment in comments)]
    for user in missing:
        print(f"@{user['login']}: read the agreement, then post ONE of these statements as a new comment:")
        print(individual_statement(user["login"], digests["individual"]))
        print(entity_statement(user["login"], digests["entity"], "YOUR LEGAL ENTITY NAME"))
    # A synchronization or main merge during this read must never acquire stale success.
    current = github.request(f"pulls/{number}")
    if current["head"]["sha"] != head or current["base"]["sha"] != pull["base"]["sha"]:
        raise ValueError("pull request changed; the new revision needs its own check")
    if github.request(f"git/ref/heads/{branch}")["object"]["sha"] != trusted:
        raise ValueError("agreement source changed; rerun against the current default branch")
    state = "failure" if missing else "success"
    description = f"{len(missing)} contributor signature(s) missing" if missing else "Contributor agreements signed"
    github.status(head, state, description)
    print(description)
    return not missing


def run():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    github = GitHub()
    if os.environ["GITHUB_EVENT_NAME"] == "push":
        pulls = [pull for pull in github.pages("pulls")
                 if pull["base"]["ref"] == event["repository"]["default_branch"]]
        # Clear every old success before any individual update can refuse.
        for pull in pulls:
            github.status(pull["head"]["sha"], "pending", "Agreement source changed; rechecking signatures")
        numbers = [pull["number"] for pull in pulls]
    else:
        number = event.get("pull_request", {}).get("number")
        if number is None:
            if not event.get("issue", {}).get("pull_request"):
                return
            number = event["issue"]["number"]
        if not isinstance(number, int) or number < 1:
            raise ValueError("pull request number is absent or invalid")
        numbers = [number]
    complete = True
    for number in numbers:
        try:
            complete = check_pull(github, number) and complete
        except (KeyError, OSError, ValueError, urllib.error.URLError, subprocess.SubprocessError) as error:
            print(f"Pull request {number}: agreement check refused: {error}")
            complete = False
    if not complete:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        run()
    except (KeyError, OSError, ValueError, urllib.error.URLError, subprocess.SubprocessError) as error:
        # Once a head is known its status is pending, so unreadable inputs cannot pass.
        print(f"Agreement check refused: {error}")
        raise SystemExit(1)
