"""An early local client must not prevent the public startup parent committing.

Run in a real standard-user Windows desktop using a fresh output directory:
  python windows_startup_competing_client.py --se INSTALLED_SE --out NEW_DIRECTORY
The exact child is retained on timeout. No provider is launched or configured.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from windows_startup_cli import standard_user
from windows_startup_native import Native, PausedParent


class Case:
    def __init__(self, image, root):
        self.image, self.root = image, root
        self.home = root / "state"
        self.repo = root / "repository"
        self.repo.mkdir()
        self.rows = []
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("SE_", "STATEENGINE_", "SECODE_", "CODEX_",
                                           "CLAUDE", "OPENAI_", "ANTHROPIC_"))
                    and key not in ("GH_TOKEN", "GITHUB_TOKEN")}
        user = root / "user"
        user.mkdir()
        self.env.update(HOME=str(user), USERPROFILE=str(user))

    def start(self, operation):
        command = [str(self.image), "--home", str(self.home), "--json", operation]
        if operation in ("init", "down"):
            command.extend(["--key", "synthetic-competing-" + operation])
        stem = self.root / f"{len(self.rows):02}-{operation}"
        with stem.with_suffix(".stdout").open("wb") as out, \
                stem.with_suffix(".stderr").open("wb") as err:
            child = subprocess.Popen(command, env=self.env, cwd=self.repo,
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        row = dict(argv=command, pid=child.pid, started=time.monotonic(), exit=None,
                   stdout=str(stem.with_suffix(".stdout")),
                   stderr=str(stem.with_suffix(".stderr")))
        self.rows.append(row)
        self.save()
        return child, row

    def join(self, child, row, seconds):
        try:
            row["exit"] = child.wait(timeout=seconds)
        finally:
            row["seconds"] = time.monotonic() - row["started"]
            self.save()
        return row["exit"]

    def call(self, operation):
        child, row = self.start(operation)
        if self.join(child, row, 45) != 0:
            raise RuntimeError(f"Public {operation} failed; original streams retained")
        return row

    def save(self):
        (self.root / "commands.json").write_text(json.dumps(self.rows, indent=2))


def exercise(case, result):
    native = Native()
    case.call("init")
    parent, row = case.start("up")
    pause, early = None, None
    try:
        # Wait for the new child to own the writer lease, then freeze only our
        # retained startup parent. A published endpoint before freezing makes
        # the fixture inconclusive, rather than a false regression pass.
        until = time.monotonic() + 15
        while True:
            if parent.poll() is not None or time.monotonic() >= until:
                raise RuntimeError("REFUSE: did not observe a writer before startup ended")
            try:
                if native.writer_present(case.home / "runtime.lock"):
                    break
            except OSError as error:
                if error.winerror != 2:
                    raise
            time.sleep(0.001)
        pause = PausedParent(native, parent)
        path = case.home / "endpoint.json"
        if path.exists():
            raise RuntimeError("REFUSE: endpoint was published before the parent was paused")
        endpoint = native.endpoint(path, time.monotonic() + 10)
        result["paused_parent_before_publication"] = True
        result["endpoint_pid"] = endpoint["epoch"]["owner"]["pid"]
        early = native.connect(endpoint)
        result["early_client_connected_before_parent_resumed"] = True
        pause.resume()
        pause = None
        # This is an outside join allowance, never an extension of the product's
        # original startup deadline. The early pipe stays connected throughout.
        code = case.join(parent, row, 40)
        result["up_exit_with_early_client_held"] = code
        if code != 0:
            raise AssertionError("Early connected client prevented public up from completing")
        result["up_total_seconds"] = row["seconds"]
        if row["seconds"] > 30:
            raise AssertionError("Public up exceeded its original 30-second startup budget")
        result["startup_passed"] = True
    finally:
        cleanup_errors = []
        for release in ([pause.resume] if pause else []) + (
                [lambda: native.close(early)] if early is not None else []):
            try:
                release()
            except (OSError, RuntimeError) as error:
                cleanup_errors.append(str(error))
        result["parent_joined"] = parent.poll() is not None
        if result["parent_joined"]:
            row["exit"] = parent.returncode
            case.save()
            # Closing the competing stream precedes authenticated cleanup. A
            # missing success witness remains a failed cleanup, never absence.
            try:
                cleanup = case.call("down")
                reply = json.loads(Path(cleanup["stdout"]).read_bytes())
                if reply.get("complete") is not True:
                    raise RuntimeError("Public down did not witness complete cleanup")
                result["cleanup_complete"] = not cleanup_errors
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(str(error))
        else:
            result["cleanup"] = "Exact startup parent retained; no overlapping operation issued"
        if cleanup_errors:
            result["cleanup_failures"] = cleanup_errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    account = standard_user()
    image = args.se.resolve(strict=True)
    args.out.mkdir(parents=True, exist_ok=False)
    case = Case(image, args.out.resolve())
    result = dict(account=account, image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                  passed=False)
    try:
        exercise(case, result)
        result["passed"] = result.get("startup_passed") and result.get("cleanup_complete")
    except (OSError, RuntimeError, AssertionError, ValueError, subprocess.TimeoutExpired) as error:
        result["failure"] = str(error)
    finally:
        (case.root / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
