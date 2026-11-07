"""Exercise actual Git diffs and final status decisions without starting hosted jobs."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import changes

spec = importlib.util.spec_from_file_location("ci_check", Path(__file__).with_name("check.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class Routing(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.original = Path.cwd()
        os.chdir(self.root)
        self.git("init", "-q")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "user.name", "CI fixture")
        (self.root / "docs").mkdir()
        (self.root / "docs/guide.md").write_text("old")
        (self.root / "lib.rs").write_text('const TEXT: &str = include_str!("unrelated.txt");')
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self):
        os.chdir(self.original)
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()

    def event(self, path="docs/guide.md", content="new"):
        Path(path).write_text(content)
        self.git("add", ".")
        self.git("commit", "-qm", "fixture change")
        return {"before": self.base, "after": self.git("rev-parse", "HEAD"),
                "ref": "refs/heads/seat-5c/ci-pilot"}

    def test_proved_prose_diff_skips(self):
        self.assertFalse(changes.affected(self.event(), "push"))

    def test_rust_and_unknown_paths_run(self):
        self.assertTrue(changes.affected(self.event("lib.rs"), "push"))

    def test_pull_request_uses_base_and_head(self):
        event = self.event()
        self.assertFalse(changes.affected({"pull_request": {"base": {"sha": self.base},
                                                          "head": {"sha": event["after"]}}}, "pull_request"))

    def test_main_always_runs(self):
        self.assertTrue(changes.affected(dict(self.event(), ref="refs/heads/main"), "push"))

    def test_embedded_markdown_runs(self):
        Path("lib.rs").write_text('include_str!("docs/guide.md");')
        self.git("add", "lib.rs")
        self.git("commit", "-qm", "fixture embedded prose")
        self.base = self.git("rev-parse", "HEAD")
        self.assertTrue(changes.affected(self.event(), "push"))

    def test_unknown_file_runs(self):
        self.assertTrue(changes.affected(self.event("new.config"), "push"))

    def test_empty_diff_runs(self):
        self.assertTrue(changes.affected({"before": self.base, "after": self.base}, "push"))

    def test_unavailable_diff_fails_open_through_entrypoint(self):
        event = self.root / "event.json"
        event.write_text(json.dumps({"before": "0" * 40, "after": self.base}))
        output = self.root / "output"
        with patch.dict(os.environ, GITHUB_EVENT_PATH=str(event), GITHUB_EVENT_NAME="push",
                        GITHUB_OUTPUT=str(output)):
            changes.main()
        self.assertEqual(output.read_text(), "rust=true\n")


class FinalStatus(unittest.TestCase):
    def jobs(self):
        return {key: {"result": "success", "outputs": {"rust": "true"}}
                for key in ["changes", "fmt", "clippy", "archive", "test"]}

    def test_success_and_explicit_prose_exemption(self):
        jobs = self.jobs()
        self.assertTrue(check.accepted(jobs))
        jobs["changes"]["outputs"]["rust"] = "false"
        for key in set(jobs) - {"changes"}:
            jobs[key]["result"] = "skipped"
        self.assertTrue(check.accepted(jobs))

    def test_failed_cancelled_and_unexplained_skips_refuse(self):
        for key in self.jobs():
            for status in ["failure", "cancelled", "skipped"]:
                with self.subTest(key=key, status=status):
                    jobs = self.jobs()
                    jobs[key]["result"] = status
                    self.assertFalse(check.accepted(jobs))

    def test_missing_job_refuses(self):
        jobs = self.jobs()
        del jobs["test"]
        self.assertFalse(check.accepted(jobs))


if __name__ == "__main__":
    unittest.main()
