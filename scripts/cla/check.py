"""Check authenticated agreement comments using only the trusted default-branch checkout."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
CONTEXT = "cla"
CHECK_ERRORS = (KeyError, OSError, ValueError, urllib.error.URLError,
                subprocess.SubprocessError)


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
        # GitHub returns newest first. A new run URL alone is not a new result;
        # repeated pending/terminal pairs exhaust the per-head context limit.
        current = next((row for row in self.pages(f"commits/{head}/statuses")
                        if row["context"].lower() == CONTEXT), None)
        description = description[:140]
        if current is not None:
            if state == "pending" or (current["state"] == state
                                      and current.get("description") == description):
                return
        self.request(f"statuses/{head}", {"state": state, "context": CONTEXT,
                     "description": description, "target_url": self.run_url})


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


def exempt(github, user, association=None):
    configured = os.environ.get("CLA_INTERNAL_APP_BOT_ID", "")
    if configured and (not configured.isascii() or not configured.isdecimal() or int(configured) < 1):
        raise ValueError("configure the internal App bot's positive numeric account ID")
    if user.get("type") == "Bot" and configured and user["id"] == int(configured):
        return True
    if association in {"OWNER", "MEMBER", "COLLABORATOR"}:
        return True
    # Read each author's current repository role, including organization and
    # team grants. An API failure is not evidence that an author is external.
    login = urllib.parse.quote(user["login"], safe="")
    role = github.request(f"collaborators/{login}/permission")
    account = role.get("user") or {}
    if account.get("id") != user["id"]:
        raise ValueError("repository permission response has a different author identity")
    permission = role.get("permission")
    if permission not in {"admin", "write", "read", "none"}:
        raise ValueError("repository author permission is unreadable")
    return permission != "none"


def validate_pull(github, pull):
    number, head = pull["number"], pull["head"]["sha"]
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
    users = {}
    authors = {pull["user"]["id"]: pull["user"]}
    for commit in commits:
        user = commit.get("author")
        if not user:
            raise ValueError("a commit has no GitHub author; associate its email with an account")
        authors[user["id"]] = user
    for user in authors.values():
        association = pull.get("author_association") if user["id"] == pull["user"]["id"] else None
        if exempt(github, user, association):
            continue
        if user.get("type") != "User":
            raise ValueError("a nonhuman author is not the configured internal App or a repository collaborator")
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
    if (current["state"] != "open" or current["head"]["sha"] != head
            or current["base"]["sha"] != pull["base"]["sha"]):
        raise ValueError("pull request changed; the new revision needs its own check")
    if github.request(f"git/ref/heads/{branch}")["object"]["sha"] != trusted:
        raise ValueError("agreement source changed; rerun against the current default branch")
    return not missing


def same_head(github, head, branch):
    return sorted(pull["number"] for pull in github.pages("pulls")
                  if pull["head"]["sha"] == head and pull["base"]["ref"] == branch)


def membership(pulls):
    members = {}
    for pull in pulls:
        members.setdefault(pull["head"]["sha"], set()).add(
            (pull["number"], pull["base"]["sha"]))
    return members


def refuse_head(github, head, members, description):
    numbers = ", ".join(str(number) for number, _ in sorted(members))
    print(f"Pull requests {numbers}: {description}")
    try:
        github.status(head, "failure", description)
    except CHECK_ERRORS as error:
        # The failure report must survive the same API refusal as the first
        # write, so other heads still get their own validation and result.
        print(f"Pull requests {numbers}: failure status could not be published: {error}")


def check_pull(github, number):
    # Commit statuses belong to a SHA, not a pull request. Every open request
    # sharing that head must qualify before the SHA can receive success.
    pull = github.request(f"pulls/{number}")
    head = pull["head"]["sha"]
    github.status(head, "pending", "Checking all pull requests sharing this head")
    branch = github.request("")["default_branch"]
    peers = same_head(github, head, branch)
    if not peers:
        return True
    complete = True
    for peer in peers:
        current = github.request(f"pulls/{peer}")
        if current["state"] != "open" or current["head"]["sha"] != head:
            raise ValueError("shared-head pull request changed; rerun the check")
        complete = validate_pull(github, current) and complete
    if same_head(github, head, branch) != peers:
        raise ValueError("shared-head membership changed; rerun the check")
    description = ("Contributor agreements signed for every shared-head pull request" if complete
                   else "A shared-head pull request is missing contributor signatures")
    github.status(head, "success" if complete else "failure", description)
    print(description)
    return complete


def run():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    name = os.environ["GITHUB_EVENT_NAME"]
    if name == "issue_comment" and not event.get("issue", {}).get("pull_request"):
        return
    subject = (event["issue"]["number"] if name == "issue_comment" else
               event["pull_request"]["number"] if name == "pull_request_target" else None)
    if subject is not None and (type(subject) is not int or subject < 1):
        raise ValueError("event pull request identity is unreadable")
    github = GitHub()
    branch = github.request("")["default_branch"]
    pulls = [pull for pull in github.pages("pulls") if pull["base"]["ref"] == branch]
    checked_members = membership(pulls)
    # Every serialized event checks the current open set, including signature
    # deletions. Pending is published inside each head's error boundary.
    heads = {pull["head"]["sha"]: pull["number"] for pull in pulls}
    results = {}
    for head, number in heads.items():
        try:
            results[head] = check_pull(github, number)
        except CHECK_ERRORS as error:
            print(f"Pull request {number}: agreement check refused: {error}")
            results[head] = False
            refuse_head(github, head, checked_members[head],
                        "Contributor identity or agreement could not be verified")
    # Later status writes can race a synchronization after check_pull's own
    # final read. Approval remains bound to the requests and bases we checked.
    try:
        current_members = membership(pull for pull in github.pages("pulls")
                                     if pull["base"]["ref"] == branch)
    except CHECK_ERRORS as error:
        for head in results:
            refuse_head(github, head, checked_members[head],
                        "Pull-request membership could not be rechecked")
        raise ValueError("pull-request membership is unreadable; rerun the check") from error
    for head in checked_members.keys() | current_members.keys():
        if checked_members.get(head) != current_members.get(head):
            results[head] = False
            refuse_head(github, head,
                        checked_members.get(head, set()) | current_members.get(head, set()),
                        "Pull-request membership changed; rerun the check")
    # Keep validating every head under global serialization, but a pull-request
    # event's run belongs to that request. Shared-head peers still qualify together.
    if subject is not None:
        current = github.request(f"pulls/{subject}")
        if current["state"] == "closed":
            return
        head = current["head"]["sha"]
        if (subject, current["base"]["sha"]) not in checked_members.get(head, set()):
            results[head] = False
            refuse_head(github, head, {(subject, current["base"]["sha"])},
                        "Pull request changed; the new revision needs its own check")
        complete = results.get(head, False)
    else:
        complete = all(results.values())
    if not complete:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        run()
    except CHECK_ERRORS as error:
        print(f"Agreement check refused: {error}")
        raise SystemExit(1)
