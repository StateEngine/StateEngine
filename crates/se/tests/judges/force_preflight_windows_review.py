"""Drive three real force attempts against managed provider work on Windows."""

import argparse
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from time import monotonic, sleep
import traceback
import tomllib
from uuid import uuid4

from force_preflight_windows_handles import pause_source_read, process_identity, ready
from mail_cli import Fixture as MailFixture


HERE = Path(__file__).resolve().parent
TERMINAL = HERE.parents[3] / "scripts/windows_journeys/terminal.ps1"
ABSENT_SESSION = "ses_01234567-89ab-7cde-8fab-0123456789ab"


def require(condition, evidence):
    if not condition:
        raise AssertionError(evidence)


class Fixture(MailFixture):
    def __init__(self, se, root):
        super().__init__(se, root)
        self.prefix = [str(self.se), "--json", "--home", str(self.home)]
        config = self.home / "config.toml"
        updated = config.read_text(encoding="utf-8") + "\n[profiles.revised]\n"
        tomllib.loads(updated)
        config.write_text(updated, encoding="utf-8")

    def start_host(self):
        self.host_stdout = self.root / "host.stdout"
        self.host_stderr = self.root / "host.stderr"
        with self.host_stdout.open("wb") as out, self.host_stderr.open("wb") as err:
            return subprocess.Popen([*self.prefix, "up", "--foreground"], cwd=self.repo,
                                    env=self.env, stdin=subprocess.DEVNULL, stdout=out, stderr=err)

    def host_ready(self, host):
        deadline = monotonic() + 30
        while monotonic() < deadline:
            require(host.poll() is None, self.host_stderr.read_text(errors="replace"))
            try:
                ready = json.loads(self.host_stdout.read_bytes())
            except json.JSONDecodeError:
                sleep(0.05)
                continue
            require(ready["state"] == "running" and ready["process"]["pid"] == host.pid, ready)
            return ready
        raise RuntimeError("foreground fixture host did not publish readiness")

    def attempt(self, force=False, resume=None):
        argv = ["--project", self.project, "--key", uuid4().hex,
                "launch", self.agent, "--detach", "--task", "Finish the local fixture turn"]
        if force:
            argv.append("--force")
        if resume is not None:
            argv.extend(("--resume", resume))
        return self.call(*argv)

    def change_profile(self):
        argv = [*self.prefix, "--project", self.project, "config", "set",
                f"agent.{self.agent}.profile", "revised"]
        encoded = b64encode(json.dumps(argv).encode()).decode()
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(TERMINAL),
                                 "-ArgvBase64", encoded], cwd=self.repo, env=self.env,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        require(result.returncode == 0, result.stdout + result.stderr)


def running(launch, stack):
    require(launch.returncode == 0, launch.stdout + launch.stderr)
    reply = json.loads(launch.stdout)
    require(reply["state"] == "running", reply)
    handle, identity = stack.enter_context(process_identity(reply["process"]["pid"]))
    require(not ready(handle), identity)
    return reply, handle, identity


def force_during_profile_change(fixture, seed, original_handle, evidence):
    sources = list((fixture.root / "owner/.claude/projects").glob(f"*/{seed['conversation_id']}.jsonl"))
    require(len(sources) == 1, "the stopped fixture transcript is unavailable")
    with ThreadPoolExecutor(max_workers=1) as executor:
        with pause_source_read(sources[0]) as signal:
            require(not ready(signal), "the fixture transcript was opened before the force call")
            pending = executor.submit(fixture.attempt, True, seed["session_id"])
            require(ready(signal, 10000) and not pending.done(), "force did not enter transcript preflight")
            evidence["preflight_read_held"] = True
            require(not ready(original_handle), "original client stopped inside preflight")
            fixture.change_profile()
            require(not pending.done(), "force completed before the preflight gate opened")
        return pending.result()


def exercise(case, fixture, original, seed, handle, stack, evidence):
    if case == "profile_changed":
        result = force_during_profile_change(fixture, seed, handle, evidence)
    else:
        resume = ABSENT_SESSION if case == "preflight_refused" else None
        result = fixture.attempt(force=True, resume=resume)
    evidence["exit"] = result.returncode
    evidence["original_alive_after_force"] = not ready(handle)
    if case == "replacement":
        replacement, successor, identity = running(result, stack)
        evidence["successor"] = identity
        require(replacement["session_id"] != original["session_id"], replacement)
        require(replacement["takeover"]["previous_session"] == original["session_id"], replacement)
        require(ready(handle, 10000), "force did not retire the original Windows process")
        evidence["original_alive_after_force"] = False
        return successor
    observed = (result.stdout + result.stderr).decode(errors="replace").lower()
    expected = {"preflight_refused": "selected saved conversation",
                "profile_changed": "saved launch profile changed"}[case]
    require(result.returncode != 0 and expected in observed, observed)
    require(evidence["original_alive_after_force"], "force refusal stopped the original Windows process")
    return None


def run_case(case, se, root, evidence):
    fixture = Fixture(se, root)
    with ExitStack() as stack:
        runtime = original_handle = successor = None
        host = fixture.start_host()
        try:
            up = fixture.host_ready(host)
            runtime, _ = stack.enter_context(process_identity(up["process"]["pid"]))
            seed = None
            if case == "profile_changed":
                seed, previous, _ = running(fixture.attempt(), stack)
                fixture.ok("--project", fixture.project, "stop", fixture.agent)
                require(ready(previous, 10000), "the seed session still holds its transcript")
            original, original_handle, evidence["original"] = running(fixture.attempt(), stack)
            successor = exercise(case, fixture, original, seed, original_handle, stack, evidence)
        finally:
            if (fixture.home / "endpoint.json").exists():
                down = fixture.ok("down")
                require(down["complete"] and down["witness"]["state"] == "witnessed", down)
            require(host.wait(timeout=10) == 0 or runtime is None, "foreground fixture host did not exit cleanly")
            require(all(ready(handle, 10000) for handle in (runtime, original_handle, successor)
                        if handle is not None), "an owned process survived cleanup")
            require(not (fixture.home / "endpoint.json").exists(), "fixture endpoint remains")
            evidence["cleanup_witnessed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    evidence = {}
    for case in ("replacement", "preflight_refused", "profile_changed"):
        receipt = evidence[case] = {"pass": False}
        try:
            with tempfile.TemporaryDirectory(prefix="se-force-") as root:
                # Windows runtime custody requires a regular executable with one link.
                image = Path(root) / "se.exe"
                shutil.copyfile(args.se.resolve(strict=True), image)
                run_case(case, image, Path(root) / "case", receipt)
            receipt["pass"] = True
        except Exception:
            receipt["error"] = traceback.format_exc()
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    raise SystemExit(0 if all(receipt["pass"] for receipt in evidence.values()) else 1)


if __name__ == "__main__":
    main()
