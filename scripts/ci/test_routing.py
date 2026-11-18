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
from test_concurrency import expression

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

        events = ["push", "pull_request", "merge_group", "workflow_dispatch", "schedule"]
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
                "ref": "refs/heads/fixture/ci-pilot"}

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

    def test_merge_group_uses_queue_base_and_group_head(self):
        prose = self.event()
        group = {"merge_group": {"base_sha": self.base, "head_sha": prose["after"]}}
        self.assertFalse(changes.affected(group, "merge_group"))
        # A later pull request in the same group brings Rust into the group's diff.
        group["merge_group"]["head_sha"] = self.event("lib.rs")["after"]
        self.assertTrue(changes.affected(group, "merge_group"))

    def test_unresolved_merge_group_diff_runs_everything(self):
        for event in [{"merge_group": {}},
                      {"merge_group": {"base_sha": "0" * 40, "head_sha": self.base}}]:
            with self.subTest(event=event):
                self.assertEqual(self.detector(event, "merge_group"), {"rust": "true", "windows": "true"})

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
    windows_jobs = ("windows-archive", "windows-test")

    def jobs(self):
        value = {key: {"result": "success", "outputs": {}}
                 for key in ["changes", "linux-route", "linux-box", "fmt", "clippy", "windows-clippy", "archive", "test", "macos-test"]}
        value["changes"]["outputs"] = {"rust": "true", "windows": "true"}
        value["linux-route"]["outputs"] = {"route": "hosted"}
        value["linux-box"]["result"] = "skipped"
        return value

    def test_success_and_explicit_prose_exemption(self):
        jobs = self.jobs()
        self.assertTrue(check.accepted(jobs))
        jobs["changes"]["outputs"]["rust"] = "false"
        for key in set(jobs) - {"changes"}:
            jobs[key]["result"] = "skipped"
        self.assertTrue(check.accepted(jobs))

    def gate_routes(self):
        hosted = self.jobs()
        box = self.jobs()
        box["linux-route"]["outputs"]["route"] = "box"
        box["linux-box"] = {"result": "success", "outputs": {
            "status": "passed", "windows": "passed"}}
        for name in ("fmt", "clippy", "archive", "test", "windows-clippy"):
            box[name]["result"] = "skipped"
        fallback = self.jobs()
        fallback["linux-route"]["outputs"]["route"] = "box"
        fallback["linux-box"] = {"result": "success", "outputs": {
            "status": "unavailable"}}
        route_failure = self.jobs()
        route_failure["linux-route"] = {"result": "failure", "outputs": {}}
        windows_exempt = self.jobs()
        windows_exempt["changes"]["outputs"]["windows"] = "false"
        windows_exempt["windows-clippy"]["result"] = "skipped"
        return {"hosted": hosted, "box": box, "fallback": fallback,
                "route_failure": route_failure, "windows_exempt": windows_exempt}

    def assert_macos_gate(self, jobs, expected):
        result = subprocess.run(
            [sys.executable, str(Path(check.__file__).resolve())],
            env={**os.environ, "RESULTS": json.dumps(jobs)},
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0 if expected else 1,
                         result.stdout + result.stderr)
        self.assertIs(check.accepted(jobs), expected)

    def test_macos_test_success_passes_each_linux_route(self):
        for route, jobs in self.gate_routes().items():
            with self.subTest(route=route):
                jobs["macos-test"] = {"result": "success"}
                self.assert_macos_gate(jobs, True)

    def test_macos_test_non_success_refuses_each_linux_route(self):
        for route, jobs in self.gate_routes().items():
            for status in ("failure", "cancelled", "skipped"):
                with self.subTest(route=route, status=status):
                    jobs["macos-test"] = {"result": status}
                    self.assert_macos_gate(jobs, False)

    def test_macos_test_absent_refuses_each_linux_route(self):
        for route, jobs in self.gate_routes().items():
            with self.subTest(route=route):
                del jobs["macos-test"]
                self.assert_macos_gate(jobs, False)
                jobs["changes"]["result"] = "failure"
                self.assert_macos_gate(jobs, False)
        jobs = self.jobs()
        jobs["changes"]["outputs"]["rust"] = "false"
        for name in set(jobs) - {"changes"}:
            jobs[name]["result"] = "skipped"
        del jobs["macos-test"]
        self.assert_macos_gate(jobs, False)

    def test_macos_test_rust_exemption_requires_skipped(self):
        for status in ("skipped", "success", "failure", "cancelled"):
            with self.subTest(status=status):
                jobs = self.jobs()
                jobs["changes"]["outputs"]["rust"] = "false"
                for name in set(jobs) - {"changes"}:
                    jobs[name]["result"] = "skipped"
                jobs["macos-test"] = {"result": status}
                self.assert_macos_gate(jobs, status == "skipped")

    def test_remote_test_is_optional_but_success_is_accepted_on_every_route(self):
        for route, jobs in self.gate_routes().items():
            with self.subTest(route=route):
                self.assert_macos_gate(jobs, True)
                jobs["remote-test"] = {"result": "success"}
                self.assert_macos_gate(jobs, True)

    def test_remote_test_non_success_refuses_on_every_route(self):
        for route, jobs in self.gate_routes().items():
            for status in ("failure", "cancelled", "skipped", "", None, "unknown"):
                with self.subTest(route=route, status=status):
                    jobs["remote-test"] = {"result": status}
                    self.assert_macos_gate(jobs, False)

    def test_remote_test_rust_exemption_requires_skipped(self):
        for status in ("skipped", "success", "failure", "cancelled", "", None):
            with self.subTest(status=status):
                jobs = self.jobs()
                jobs["changes"]["outputs"]["rust"] = "false"
                for name in set(jobs) - {"changes"}:
                    jobs[name]["result"] = "skipped"
                self.assert_macos_gate(jobs, True)
                jobs["remote-test"] = {"result": status}
                self.assert_macos_gate(jobs, status == "skipped")

    def test_remote_test_does_not_replace_required_jobs_or_allow_unknown_jobs(self):
        for missing in self.jobs():
            with self.subTest(missing=missing):
                jobs = self.jobs()
                del jobs[missing]
                jobs["remote-test"] = {"result": "success"}
                self.assert_macos_gate(jobs, False)
        jobs = self.jobs()
        jobs["remote-tests"] = {"result": "success"}
        self.assert_macos_gate(jobs, False)

    def test_remote_test_success_does_not_hide_an_existing_gate_failure(self):
        for name in ("changes", "fmt", "clippy", "windows-clippy", "archive", "test", "macos-test"):
            with self.subTest(name=name):
                jobs = self.jobs()
                jobs[name]["result"] = "failure"
                jobs["remote-test"] = {"result": "success"}
                self.assert_macos_gate(jobs, False)

    def test_failed_cancelled_and_unexplained_skips_refuse(self):
        for key in {"changes", "fmt", "clippy", "windows-clippy", "archive", "test", "macos-test"}:
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
        jobs["windows-clippy"]["result"] = "skipped"
        self.assertTrue(check.accepted(jobs))
        for name in ["fmt", "clippy", "archive", "test"]:
            with self.subTest(job=name):
                missing = {key: dict(value) for key, value in jobs.items()}
                missing[name]["result"] = "skipped"
                self.assertFalse(check.accepted(missing))

    def test_box_success_and_red_do_not_fall_through_to_hosted(self):
        jobs = self.jobs()
        jobs["linux-route"]["outputs"]["route"] = "box"
        jobs["linux-box"] = {"result": "success", "outputs": {"status": "passed"}}
        for name in ("fmt", "clippy", "archive", "test"):
            jobs[name]["result"] = "skipped"
        self.assertTrue(check.accepted(jobs))
        jobs["linux-box"]["outputs"]["status"] = "failed"
        for name in ("fmt", "clippy", "archive", "test"):
            jobs[name]["result"] = "success"
        self.assertFalse(check.accepted(jobs))

    def test_unavailable_requires_complete_hosted_chain(self):
        jobs = self.jobs()
        jobs["linux-route"]["outputs"]["route"] = "box"
        jobs["linux-box"] = {"result": "success", "outputs": {"status": "unavailable"}}
        self.assertTrue(check.accepted(jobs))
        for name in ("fmt", "clippy", "archive", "test"):
            changed = json.loads(json.dumps(jobs))
            changed[name]["result"] = "skipped"
            self.assertFalse(check.accepted(changed))
        jobs["linux-box"] = {"result": "failure", "outputs": {}}
        self.assertTrue(check.accepted(jobs))
        jobs["linux-box"]["result"] = "cancelled"
        self.assertFalse(check.accepted(jobs))

    def guard(self):
        jobs = self.jobs()
        for name in ("test", "macos-test"):
            jobs[name]["result"] = "skipped"
        jobs["remote-test"] = {"result": "skipped"}
        return jobs

    def run_gate(self, jobs, mode):
        return subprocess.run([sys.executable, str(Path(check.__file__).resolve())],
                              env={**os.environ, "RESULTS": json.dumps(jobs), "CHECK_MODE": mode},
                              capture_output=True, text=True, timeout=10).returncode

    def test_native_windows_accepts_a_successful_pair(self):
        for route in ("hosted", "box"):
            with self.subTest(route=route):
                jobs = self.gate_routes()[route]
                jobs.update({name: {"result": "success"} for name in self.windows_jobs})
                self.assertEqual(self.run_gate(jobs, "full"), 0)

    def test_native_windows_refuses_either_job_on_its_own(self):
        for name in self.windows_jobs:
            with self.subTest(name=name):
                jobs = self.jobs()
                jobs[name] = {"result": "success"}
                self.assertEqual(self.run_gate(jobs, "full"), 1)

    def test_native_windows_requires_success_from_each_job(self):
        for name in self.windows_jobs:
            for status in ("failure", "cancelled", "skipped"):
                with self.subTest(name=name, status=status):
                    jobs = self.jobs()
                    jobs.update({job: {"result": "success"} for job in self.windows_jobs})
                    jobs[name]["result"] = status
                    self.assertEqual(self.run_gate(jobs, "full"), 1)

    def test_native_windows_requires_both_skips_on_a_guard_push(self):
        jobs = self.guard()
        jobs.update({name: {"result": "skipped"} for name in self.windows_jobs})
        self.assertEqual(self.run_gate(jobs, "guard"), 0)
        for name in self.windows_jobs:
            for status in ("success", "failure"):
                with self.subTest(name=name, status=status):
                    jobs[name]["result"] = status
                    self.assertEqual(self.run_gate(jobs, "guard"), 1)
                jobs[name]["result"] = "skipped"

    def test_native_windows_requires_both_skips_when_windows_is_exempt(self):
        jobs = self.gate_routes()["windows_exempt"]
        jobs.update({name: {"result": "skipped"} for name in self.windows_jobs})
        self.assertEqual(self.run_gate(jobs, "full"), 0)
        for name in self.windows_jobs:
            with self.subTest(name=name):
                jobs[name]["result"] = "success"
                self.assertEqual(self.run_gate(jobs, "full"), 1)
                jobs[name]["result"] = "skipped"

    def test_main_guard_accepts_lint_and_cache_refresh_without_the_suite(self):
        jobs = self.guard()
        self.assertTrue(check.accepted(jobs, guard=True))
        self.assertEqual(self.run_gate(jobs, "guard"), 0)
        # Every other mode, including an unknown one, still requires the full suite.
        self.assertFalse(check.accepted(jobs))
        for mode in ("full", "", "unknown"):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_gate(jobs, mode), 1)
        box = self.guard()
        box["linux-route"]["outputs"]["route"] = "box"
        box["linux-box"] = {"result": "success", "outputs": {"status": "passed", "windows": "passed"}}
        for name in ("fmt", "clippy", "archive", "windows-clippy"):
            box[name]["result"] = "skipped"
        self.assertTrue(check.accepted(box, guard=True))

    def test_main_guard_refuses_failed_lint_or_unexpected_suite_runs(self):
        for name in ("changes", "fmt", "clippy", "windows-clippy", "archive"):
            for status in ("failure", "cancelled", "skipped"):
                with self.subTest(name=name, status=status):
                    jobs = self.guard()
                    jobs[name]["result"] = status
                    self.assertFalse(check.accepted(jobs, guard=True))
        for name in ("test", "macos-test", "remote-test"):
            for status in ("success", "failure", "cancelled"):
                with self.subTest(name=name, status=status):
                    jobs = self.guard()
                    jobs[name]["result"] = status
                    self.assertFalse(check.accepted(jobs, guard=True))

    def test_route_transport_failure_falls_back_but_unexplained_skip_does_not(self):
        jobs = self.jobs()
        jobs["linux-route"] = {"result": "failure", "outputs": {}}
        self.assertTrue(check.accepted(jobs))
        jobs["linux-route"]["result"] = "skipped"
        self.assertFalse(check.accepted(jobs))


class MergeQueueWorkflow(unittest.TestCase):
    """The workflow text that decides which jobs a merge group and a main push run."""

    def setUp(self):
        self.text = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text()

    def job(self, name):
        match = re.search(r"^  " + re.escape(name) + r":\n(.*?)(?=^  [a-z][\w-]*:\n|\Z)",
                          self.text, re.M | re.S)
        self.assertIsNotNone(match, name)
        return match[1]

    def value(self, job, key):
        match = re.search(r"^ {4,}" + re.escape(key) + r": \$\{\{(.*?)\}\}$", self.job(job), re.M)
        self.assertIsNotNone(match, f"{job}.{key}")
        return match[1]

    def context(self, event):
        return {"github.event_name": event, "github.repository": "owner/repo"}

    def test_merge_group_requests_checks(self):
        self.assertRegex(self.text, r"(?m)^  merge_group:\n    types: \[checks_requested\]$")

    def test_only_main_pushes_report_under_another_name_and_mode(self):
        for event in ("pull_request", "merge_group", "schedule", "workflow_dispatch", "push"):
            with self.subTest(event=event):
                push = event == "push"
                self.assertEqual(expression(self.value("check", "name"), self.context(event)),
                                 "main guard" if push else "check")
                self.assertEqual(expression(self.value("check", "CHECK_MODE"), self.context(event)),
                                 "guard" if push else "full")

    def test_main_push_skips_only_suite_jobs(self):
        for name in ("test", "windows-archive", "windows-test", "macos", "macos-test", "remote-test"):
            with self.subTest(job=name):
                self.assertIn("github.event_name != 'push'", self.value(name, "if"))
        for name in ("changes", "linux-route", "linux-box", "fmt", "clippy", "windows-clippy",
                     "archive", "check"):
            with self.subTest(job=name):
                self.assertNotIn("'push'", self.value(name, "if"))

    def test_trusted_checkouts_use_the_queue_base(self):
        for name in ("changes", "check"):
            with self.subTest(job=name):
                ref = self.value(name, "ref")
                self.assertEqual(expression(ref, {"github.event.merge_group.base_sha": "b" * 40}),
                                 "b" * 40)
                self.assertEqual(expression(ref, {"github.event.pull_request.base.sha": "a" * 40}),
                                 "a" * 40)

    def test_merge_groups_never_save_caches_only_their_own_ref_could_restore(self):
        for name in ("clippy", "windows-clippy", "archive", "macos", "macos-test", "remote-test"):
            with self.subTest(job=name):
                save = self.value(name, "save-if")
                self.assertFalse(expression(save, self.context("merge_group")))
                for event in ("pull_request", "push", "schedule"):
                    self.assertTrue(expression(save, self.context(event)))


if __name__ == "__main__":
    unittest.main()
