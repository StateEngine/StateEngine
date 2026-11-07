"""Exercise actual Git diffs and final status decisions without starting hosted jobs."""
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import changes

spec = importlib.util.spec_from_file_location("ci_check", Path(__file__).with_name("check.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class Concurrency(unittest.TestCase):
    def test_proof_runs_do_not_share_the_main_push_group(self):
        workflow = Path(__file__).parents[2] / ".github/workflows/ci.yml"
        group = next(line.strip().removeprefix("group: ")
                     for line in workflow.read_text().splitlines()
                     if line.startswith("  group: "))

        def key(event, **overrides):
            context = {"github.event_name": event, "github.repository": "owner/repo",
                       "github.ref_name": "main", **overrides}

            def expression(match):
                # This group uses only context lookups and the Actions || fallback.
                return next((context.get(name.strip(), "")
                             for name in match[1].split("||")
                             if context.get(name.strip(), "")), "")

            return re.sub(r"\$\{\{(.*?)\}\}", expression, group)

        events = ["push", "pull_request", "workflow_dispatch", "schedule"]
        self.assertEqual(len({key(event) for event in events}), len(events))
        # PR pushes still converge on one group, scoped to the source repository.
        pr = {"github.head_ref": "feature", "github.ref_name": "1/merge",
              "github.event.pull_request.head.repo.full_name": "contributor/repo"}
        self.assertEqual(key("pull_request", **pr),
                         key("pull_request", **{**pr, "github.ref_name": "2/merge"}))
        self.assertNotEqual(key("pull_request", **pr), key("pull_request", **{
            **pr, "github.event.pull_request.head.repo.full_name": "other/repo"}))


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

    def test_root_agent_guide_skips(self):
        self.assertFalse(changes.affected(self.event("AGENTS.md"), "push"))

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
        self.assertEqual(output.read_text(), "rust=true\nwindows=true\n")

    def windows_event(self, *paths):
        self.base = self.git("rev-parse", "HEAD")
        for name in paths:
            path = Path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("routing fixture\n")
        self.git("add", "--", *paths)
        self.git("commit", "-qm", "routing fixture", "--", *paths)
        return {"before": self.base, "after": self.git("rev-parse", "HEAD"),
                "ref": "refs/heads/topic"}

    def detector(self, event, name="pull_request"):
        event_path = self.root / "event.json"
        event_path.write_text(json.dumps(event))
        output = self.root / "output"
        output.unlink(missing_ok=True)
        environment = {**os.environ, "GITHUB_EVENT_PATH": str(event_path),
                       "GITHUB_EVENT_NAME": name, "GITHUB_OUTPUT": str(output)}
        result = subprocess.run([sys.executable, str(Path(changes.__file__).resolve())],
                                env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split("=", 1) for line in output.read_text().splitlines())

    def test_windows_skips_only_named_non_windows_sources_or_box_tools(self):
        for path in ["factory/ci/box/engine.py", "factory/ci/box/Dockerfile",
                     "crates/se-proc/src/platform/linux/group.rs",
                     "crates/se-proc/src/birth_time/macos.rs",
                     "crates/se-proc/src/native_ipc/unix/paths.rs",
                     "crates/se-proc/src/state_files/effects/unix.rs",
                     "crates/se-proc/src/state_files/effects/permissions_linux.rs",
                     "crates/se-proc/src/state_files/effects/permissions_macos.rs",
                     "crates/se-proc/src/state_files/effects/claim_unix.rs",
                     "crates/se-proc/src/state_files/effects/install_child_unix.rs"]:
            with self.subTest(path=path):
                event = self.windows_event(path)
                self.assertFalse(changes.windows_affected(event, "push"))
                self.assertTrue(changes.affected(event, "push"))

    def test_windows_keeps_shared_windows_test_build_and_workflow_paths(self):
        for path in ["crates/se-proc/src/state_files/effects.rs",
                     "crates/se-proc/src/state_files/effects/listing.rs",
                     "crates/se-proc/src/state_files/effects/created.rs",
                     "crates/se-proc/src/state_files/effects/permissions_windows.rs",
                     "crates/se-proc/src/platform/windows/mod.rs",
                     "crates/se-proc/tests/linux_process_exit.rs",
                     "crates/se-proc/Cargo.toml", "Cargo.lock", "build.rs",
                     ".github/workflows/ci.yml", "scripts/ci/changes.py",
                     "factory/ci/boxlike/engine.py", "crates/se-proc/src/linuxish.rs",
                     "crates/se-proc/src/adapter_unix.rs.backup", "unknown.config"]:
            with self.subTest(path=path):
                self.assertTrue(changes.windows_affected(self.windows_event(path), "push"))

    def test_windows_mixed_changes_do_not_hide_shared_code(self):
        event = self.windows_event("factory/ci/box/runner.sh",
                                   "crates/se-proc/src/platform/linux/spawn.rs",
                                   "crates/se-proc/src/state_files/mod.rs")
        self.assertTrue(changes.windows_affected(event, "push"))

    def test_windows_main_manual_schedule_and_empty_diffs_run(self):
        event = self.windows_event("crates/se-proc/src/platform/linux/group.rs")
        self.assertTrue(changes.windows_affected(dict(event, ref="refs/heads/main"), "push"))
        for name in ["workflow_dispatch", "schedule", "unknown"]:
            with self.subTest(event=name):
                self.assertTrue(changes.windows_affected({}, name))
        self.assertTrue(changes.windows_affected({"before": self.base, "after": self.base}, "push"))

    def test_windows_pull_request_uses_merge_base_and_publishes_both_outputs(self):
        common = self.base
        self.git("checkout", "-qb", "base-update")
        target = self.windows_event("crates/se-proc/src/platform/windows/mod.rs")["after"]
        self.git("checkout", "-qb", "topic", common)
        source = self.windows_event("crates/se-proc/src/state_files/effects/claim_unix.rs")["after"]
        event = {"pull_request": {"base": {"sha": target}, "head": {"sha": source}}}
        self.assertEqual(self.detector(event), {"rust": "true", "windows": "false"})
        # Shared work in the same topic must re-enable Windows too.
        source = self.windows_event("crates/se-proc/src/state_files/effects.rs")["after"]
        event["pull_request"]["head"]["sha"] = source
        self.assertEqual(self.detector(event), {"rust": "true", "windows": "true"})

    def test_windows_renames_preserve_both_old_and_new_paths(self):
        for old, new in [("crates/se-proc/src/platform/windows/old.rs",
                          "crates/se-proc/src/platform/linux/new.rs"),
                         ("crates/se-proc/src/native_ipc/unix.rs",
                          "crates/se-proc/src/shared.rs")]:
            with self.subTest(old=old, new=new):
                before = self.windows_event(old)["after"]
                Path(new).parent.mkdir(parents=True, exist_ok=True)
                Path(old).rename(new)
                self.git("add", "--", old, new)
                self.git("commit", "-qm", "rename fixture", "--", old, new)
                event = {"before": before, "after": self.git("rev-parse", "HEAD")}
                self.assertTrue(changes.windows_affected(event, "push"))

    def test_windows_deletions_are_classified_by_the_deleted_path(self):
        for path, expected in [("crates/se-proc/src/platform/linux/old.rs", False),
                               ("crates/se-proc/src/state_files/mod.rs", True)]:
            with self.subTest(path=path):
                before = self.windows_event(path)["after"]
                Path(path).unlink()
                self.git("add", "--", path)
                self.git("commit", "-qm", "delete fixture", "--", path)
                event = {"before": before, "after": self.git("rev-parse", "HEAD")}
                self.assertEqual(changes.windows_affected(event, "push"), expected)

    def test_windows_unavailable_pr_diff_fails_open_through_real_entrypoint(self):
        for event in [{"pull_request": {}},
                      {"pull_request": {"base": {"sha": "0" * 40},
                                        "head": {"sha": self.base}}}]:
            with self.subTest(event=event):
                self.assertEqual(self.detector(event), {"rust": "true", "windows": "true"})


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

    def test_windows_exemption_still_requires_linux_clippy_and_tests(self):
        jobs = self.jobs()
        jobs["changes"]["outputs"]["windows"] = "false"
        self.assertTrue(check.accepted(jobs))
        for name in ["fmt", "clippy", "archive", "test"]:
            with self.subTest(job=name):
                missing = {key: dict(value) for key, value in jobs.items()}
                missing[name]["result"] = "skipped"
                self.assertFalse(check.accepted(missing))


if __name__ == "__main__":
    unittest.main()
