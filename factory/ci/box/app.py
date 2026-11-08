"""Short-lived, repository-only App credentials; never passed into a worker."""
import base64
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from github_binding import GitHub, NoRedirect


def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=")


class App(GitHub):
    def __init__(self, app_id, installation, key):
        self.app_id = app_id
        self.installation = installation
        self.key = key
        self.expires = 0
        self.headers = {}

    def refresh(self, timeout=45):
        end = time.monotonic() + timeout
        def remaining(cap):
            value = min(cap, end - time.monotonic())
            if value <= 0:
                raise TimeoutError("App credential deadline expired")
            return value
        if time.monotonic() < self.expires:
            return
        now = int(time.time())
        signing = encode({"alg": "RS256", "typ": "JWT"}) + b"." + encode(
            {"iat": now-60, "exp": now+540, "iss": str(self.app_id)})
        signed = subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(self.key)],
                                input=signing, capture_output=True, timeout=remaining(10), close_fds=True)
        if signed.returncode:
            raise RuntimeError("App signature unavailable; diagnostics withheld")
        jwt = signing + b"." + base64.urlsafe_b64encode(signed.stdout).rstrip(b"=")
        request = urllib.request.Request(
            "https://api.github.com/app/installations/" + str(self.installation) + "/access_tokens",
            data=b"{}", method="POST", headers={"Authorization": "Bearer " + jwt.decode(),
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=remaining(30)) as response:
                value = json.loads(response.read(65536))
            remaining(30)
        except (urllib.error.URLError, ValueError):
            raise RuntimeError("App token unavailable; credential details withheld") from None
        permissions = value.get("permissions", {})
        if (permissions.get("checks") != "write" or permissions.get("actions") != "read" or
                permissions.get("contents") != "read" or permissions.get("pull_requests") != "read" or
                any(k not in {"checks", "actions", "contents", "pull_requests", "metadata"} for k in permissions)):
            raise RuntimeError("App installation permissions differ from the dedicated profile")
        self.headers = {"Authorization": "Bearer " + value["token"],
                        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        self.expires = time.monotonic() + 2700

    def get(self, *args, **kwargs):
        end = time.monotonic() + kwargs.get("timeout", 45)
        self.refresh(timeout=max(0, end-time.monotonic()))
        kwargs["timeout"] = max(0, end-time.monotonic())
        return super().get(*args, **kwargs)

    def write(self, path, value, method="POST"):
        self.refresh()
        request = urllib.request.Request("https://api.github.com/repos/StateEngine/StateEngine/" + path,
            data=json.dumps(value).encode(), method=method, headers=self.headers)
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
                data = response.read(1024*1024+1)
            if len(data) > 1024*1024:
                raise RuntimeError("App write response exceeds limit")
            return json.loads(data)
        except urllib.error.URLError:
            raise RuntimeError("App check write unavailable; credential details withheld") from None
