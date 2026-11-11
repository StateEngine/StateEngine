"""Read-only GitHub binding, outside both the CI account and candidate namespace."""
import base64
from dataclasses import dataclass
import hashlib
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "StateEngine/StateEngine"
POLICY_FILES = (".github/workflows/ci.yml", ".github/actions/rust/action.yml", ".github/actions/test/action.yml")


def policy_paths(paths):
    return {p for p in paths if p in POLICY_FILES or p in
            {"Cargo.lock", ".config/nextest.toml", ".cargo/config.toml", "rust-toolchain.toml"} or
            p.endswith("Cargo.toml") or p.startswith(("scripts/ci/", "factory/ci/box/", "factory/ci/self-hosted/"))}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    def __init__(self, helper=None, *, token=None):
        if (helper is None) == (token is None):
            raise ValueError("one repository credential source is required")
        if helper is not None:
            result = subprocess.run([str(helper)], capture_output=True, text=True, timeout=30, close_fds=True)
            if result.returncode or not result.stdout.strip():
                raise RuntimeError("repository credential helper failed; output withheld")
            token = result.stdout.strip()
        if not isinstance(token, str) or not token or any(c.isspace() for c in token):
            raise ValueError("repository credential is absent or malformed")
        self.headers = {"Authorization": "Bearer " + token,
                        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

    def get(self, path, limit=16 * 1024**2, raw=False, timeout=45):
        end = time.monotonic() + timeout
        def remaining():
            value = end - time.monotonic()
            if value <= 0:
                raise TimeoutError("repository read deadline expired")
            return value
        request = urllib.request.Request("https://api.github.com/repos/" + REPOSITORY + "/" + path,
                                         headers=self.headers)
        try:
            try:
                response = urllib.request.build_opener(NoRedirect).open(request, timeout=remaining())
            except urllib.error.HTTPError as error:
                if error.code not in (301, 302, 303, 307, 308):
                    raise RuntimeError(f"repository read refused: HTTP {error.code}") from None
                target = urllib.parse.urlsplit(error.headers["Location"])
                allowed = (target.hostname == "codeload.github.com" or
                           (target.hostname or "").endswith((".blob.core.windows.net", ".actions.githubusercontent.com")))
                if target.scheme != "https" or not allowed or target.username or target.password or target.port not in (None, 443):
                    raise RuntimeError("repository download redirect refused") from None
                # Signed download URLs receive no repository credential and are never logged.
                response = urllib.request.build_opener(NoRedirect).open(error.headers["Location"], timeout=remaining())
            with response:
                data = response.read(limit + 1)
            remaining()
            if len(data) > limit:
                raise RuntimeError("repository response exceeds the bounded input size")
            return data if raw else json.loads(data)
        except (urllib.error.URLError, TimeoutError):
            raise RuntimeError("repository read unavailable; transport details withheld") from None


@dataclass(frozen=True)
class Binding:
    repository: str
    run: int
    attempt: int
    pull_request: int
    checkout: str
    head: str
    archive_job: int


def checkout_from_log(data):
    lines = data.decode("utf-8").splitlines()
    for index, line in enumerate(lines[:-1]):
        if re.search(r"\bgit log -1 --format=['\"]?%H", line):
            value = lines[index + 1].rsplit(" ", 1)[-1].strip()
            if re.fullmatch("[a-f0-9]{40}", value):
                return value
            raise ValueError("first trusted checkout observation is not one complete SHA")
    raise ValueError("actual archive checkout was not observed")


def bind(api, run_id, attempt, number, checkout, policy):
    if min(run_id, attempt, number) <= 0 or not re.fullmatch("[a-f0-9]{40}", checkout):
        raise ValueError("positive run/attempt/PR and exact checkout SHA required")
    run = api.get(f"actions/runs/{run_id}")
    if (run["id"] != run_id or run["run_attempt"] != attempt or run["event"] != "pull_request" or
            run["path"].split("@")[0] != ".github/workflows/ci.yml"):
        raise ValueError("run is not the current attempt of the admitted PR workflow")
    if (run["repository"]["full_name"] != REPOSITORY or
            run["head_repository"]["full_name"] != REPOSITORY or run["head_repository"]["fork"]):
        raise ValueError("foreign repositories and forks use hosted CI")
    pr = api.get(f"pulls/{number}")
    if (pr["state"] != "open" or pr["head"]["repo"]["full_name"] != REPOSITORY or
            pr["base"]["repo"]["full_name"] != REPOSITORY or pr["head"]["sha"] != run["head_sha"] or
            pr["head"]["ref"] != run["head_branch"] or pr["merge_commit_sha"] != checkout):
        raise ValueError("PR moved, is closed/forked, or does not name this exact run checkout")
    for path in POLICY_FILES:
        value = api.get("contents/" + path + "?ref=" + checkout)
        data = base64.b64decode("".join(value["content"].split()), validate=True)
        if hashlib.sha256(data).hexdigest() != policy[path]:
            raise ValueError("workflow/tools differ from the maintainer-approved shadow policy: " + path)
    jobs = api.get(f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    if jobs["total_count"] > 100:
        raise ValueError("attempt jobs exceed the checked page")
    candidates = [j for j in jobs["jobs"] if j["name"] == "archive" and j["run_id"] == run_id]
    if len(candidates) != 1 or candidates[0]["conclusion"] != "success":
        raise ValueError("one completed successful Linux archive is required for checkout readback")
    job = candidates[0]
    actual = checkout_from_log(api.get(f"actions/jobs/{job['id']}/logs", raw=True))
    if actual != checkout:
        raise ValueError("hosted archive's actual checkout differs")
    return Binding(REPOSITORY, run_id, attempt, number, checkout, run["head_sha"], job["id"])
