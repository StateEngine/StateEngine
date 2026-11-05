"""Bug: 7734bbdc H8-01 — plain resume advice must explain the actual public state.

Read an existing isolated test home through the installed binary only. The caller
establishes a real new/running/ready/reconcile/unavailable state; this judge never
fabricates store rows, provider records or renderer arguments. Native-provider
review runs establish the running and saved-conversation cases separately.

  python3 resume_plain_cli.py --se /installed/se --home /isolated/state \
    --project PROJECT --agent AGENT --expect-mode running --out /new/log/path
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def normalize(text):
    return " ".join(re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text).split())


class Judge:
    def __init__(self, options):
        self.options = options
        self.image = options.se.resolve(strict=True)
        self.out = options.out
        self.out.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("SE_", "STATEENGINE_", "SECODE_", "CODEX_"))
            and key != "CLAUDECODE"
        }
        self.calls = []

    def call(self, surface, machine=False):
        args = [str(self.image), "--home", str(self.options.home),
                "--project", self.options.project]
        if machine:
            args.append("--json")
        args.extend(surface)
        reply = subprocess.run(args, env=self.env, capture_output=True,
                               text=True, timeout=30)
        row = dict(argv=args, exit=reply.returncode,
                   stdout=reply.stdout, stderr=reply.stderr)
        self.calls.append(row)
        (self.out / "commands.json").write_text(json.dumps(self.calls, indent=2))
        if reply.returncode:
            raise AssertionError(f"public read failed; see commands.json: {args}")
        return json.loads(reply.stdout) if machine else reply.stdout

    def resume(self, value, surface):
        if surface[0] == "status":
            rows = value["agents"]["items"]
            rows = [row for row in rows if self.options.agent
                    in (row["id"], row["name"])]
            if len(rows) != 1:
                raise AssertionError("REFUSE: selected agent absent or ambiguous")
            row = rows[0]
        else:
            if value["agent"]["state"] != "present":
                raise AssertionError("REFUSE: selected agent is not present")
            row = value["agent"]["value"]
        result = row["resume"]
        if result["mode"] != self.options.expect_mode:
            raise AssertionError(
                f"REFUSE: expected real {self.options.expect_mode} state, got {result}"
            )
        return result

    def check(self, surface):
        before = self.resume(self.call(surface, machine=True), surface)
        plain = self.call(surface)
        after = self.resume(self.call(surface, machine=True), surface)
        if before != after:
            raise AssertionError("REFUSE: resume state changed across the plain read")
        if "--json" in plain:
            raise AssertionError("normal resume advice sends the person to JSON")
        reason, command = before["reason"], before["command"]
        if reason and normalize(reason) not in normalize(plain):
            raise AssertionError(f"plain output hides the actual reason: {reason}")
        if command and command not in plain:
            raise AssertionError(f"plain output hides the scoped next step: {command}")
        if before["ready"] and not command:
            raise AssertionError("ready resume has no executable next step")
        if not before["ready"] and not reason:
            raise AssertionError("unready resume has no explanation")
        if not re.search(r"resume|conversation", plain, re.IGNORECASE):
            raise AssertionError("plain output never describes the conversation")
        return dict(surface=surface, passed=True, resume=before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("se", "home", "out"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("project", "agent"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--expect-mode", required=True,
                        choices=["new", "running", "resume", "reconcile", "unavailable"])
    options = parser.parse_args()
    judge, results = Judge(options), []
    for surface in (["status"], ["agent", "show", options.agent]):
        try:
            result = judge.check(surface)
        except (AssertionError, KeyError, ValueError, subprocess.TimeoutExpired) as error:
            result = dict(surface=surface, passed=False, error=str(error))
        results.append(result)
        print(("ok" if result["passed"] else "FAIL") + " - " + " ".join(surface))
    passed = sum(row["passed"] for row in results)
    (options.out / "results.json").write_text(json.dumps(results, indent=2))
    print(f"{options.expect_mode}: {passed} passed, {len(results) - passed} failed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
