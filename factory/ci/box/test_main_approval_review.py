"""Independent controls for main-source binding and immutable approval publication.

API replies and expensive builders are external fixtures. Native file admission and
argument refusal run against real files/processes; no live approval is changed.
"""
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
# Resolve candidate dependencies before the installed entrypoint adds its fixed path.
previous_path = sys.path[:]
try:
    for name in ("approval_source", "build", "dispatch", "engine", "github_binding"):
        __import__(name)
    import approval
    import approval_source
    from approval_source import main_source

    spec = importlib.util.spec_from_file_location("approval_hook_review", HERE.parent / "self-hosted/hook.py")
    hook = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hook)
finally:
    sys.path[:] = previous_path
SOURCE = "a" * 40
REPOSITORY = "example/project"
TOKEN = "synthetic-review-token"


def context():
    return dict(GITHUB_REPOSITORY=REPOSITORY, GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/heads/main", GITHUB_SHA=SOURCE,
                GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="2")


def replies():
    return {
        "actions/runs/123": dict(id=123, run_attempt=2, event="push", head_branch="main",
            head_sha=SOURCE, path=".github/workflows/ci.yml", repository={"full_name": REPOSITORY},
            head_repository={"full_name": REPOSITORY, "fork": False}),
        "git/ref/heads/main": dict(ref="refs/heads/main", object={"type": "commit", "sha": SOURCE}),
        "commits/" + SOURCE + "/pulls?per_page=100": [dict(number=7, merged_at="2026-01-01T00:00:00Z",
            merge_commit_sha=SOURCE, base={"ref": "main", "repo": {"full_name": REPOSITORY}})],
    }


class API:
    def __init__(self, values=None):
        self.values = replies() if values is None else values
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        return copy.deepcopy(self.values[path])


class MainSourceReview(unittest.TestCase):
    def test_exact_merged_main_push_is_bound(self):
        self.assertEqual(main_source(API(), REPOSITORY, context()),
                         dict(source=SOURCE, run=123, attempt=2, pull_request=7))

    def test_pr_and_forged_contexts_refuse_before_api_access(self):
        for key, value in [("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/pull/7/merge"),
                           ("GITHUB_REPOSITORY", "different/project"), ("GITHUB_SHA", "../main"),
                           ("GITHUB_RUN_ID", "123/other"), ("GITHUB_RUN_ATTEMPT", "0")]:
            with self.subTest(key=key):
                api = API()
                with self.assertRaises(ValueError):
                    main_source(api, REPOSITORY, {**context(), key: value})
                self.assertEqual(api.calls, [])

    def test_actual_run_must_match_every_context_field(self):
        for key, value in [("id", 124), ("run_attempt", 1), ("event", "pull_request"),
                           ("head_branch", "topic"), ("head_sha", "b" * 40),
                           ("path", ".github/workflows/other.yml"),
                           ("repository", {"full_name": "different/project"}),
                           ("head_repository", {"full_name": REPOSITORY, "fork": True})]:
            with self.subTest(key=key):
                values = replies()
                values["actions/runs/123"][key] = value
                with self.assertRaises(ValueError):
                    main_source(API(values), REPOSITORY, context())

    def test_current_main_and_complete_merge_association_are_required(self):
        key = "commits/" + SOURCE + "/pulls?per_page=100"
        for change in ("advanced", "unmerged", "other-source", "other-base", "other-repo", "ambiguous", "truncated"):
            with self.subTest(change=change):
                values = replies()
                if change == "advanced":
                    values["git/ref/heads/main"]["object"]["sha"] = "b" * 40
                elif change == "unmerged":
                    values[key][0]["merged_at"] = None
                elif change == "other-source":
                    values[key][0]["merge_commit_sha"] = "b" * 40
                elif change == "other-base":
                    values[key][0]["base"]["ref"] = "topic"
                elif change == "other-repo":
                    values[key][0]["base"]["repo"]["full_name"] = "different/project"
                elif change == "ambiguous":
                    values[key] *= 2
                else:
                    values[key] *= 100
                with self.assertRaises(ValueError):
                    main_source(API(values), REPOSITORY, context())

    def test_argument_free_entrypoint_refuses_a_real_process_argument(self):
        program = ("import sys,runpy;sys.path.insert(0," + repr(str(HERE)) + ");"
                   "import approval_source,build,dispatch,engine,github_binding;"
                   "sys.argv=[" + repr(str(HERE / "approval.py")) + ",'untrusted-argument'];"
                   "runpy.run_path(sys.argv[0],run_name='__main__')")
        result = subprocess.run([sys.executable, "-I", "-c", program], capture_output=True,
                                text=True, timeout=15, input="{}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("accepts no arguments", result.stderr)
        self.assertEqual(result.stdout, "")


class SourceScopeReview(unittest.TestCase):
    def fetch(self, outcome=None, stop=0):
        calls = []
        def run(arguments, **options):
            calls.append((arguments, options))
            if arguments[0] == "systemd-run":
                if isinstance(outcome, BaseException):
                    raise outcome
                return subprocess.CompletedProcess(arguments, outcome or 0, b"", TOKEN.encode())
            if arguments[0] == "systemctl":
                return subprocess.CompletedProcess(arguments, stop, b"", b"")
            if "rev-parse" in arguments:
                return subprocess.CompletedProcess(arguments, 0, (SOURCE + "\n").encode(), b"")
            return subprocess.CompletedProcess(arguments, 0, b"", b"")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "source.git"
            with patch.object(approval_source.subprocess, "run", side_effect=run):
                try:
                    result = approval_source.fetch_main(REPOSITORY, SOURCE, TOKEN, directory, scoped=True)
                    error = None
                except BaseException as cause:
                    result, error = None, cause
            receipt = json.loads((directory.parent / "source-fetch.json").read_text())
        return result, error, calls, receipt

    def test_scoped_fetch_closes_the_exact_generated_scope_and_hides_the_token(self):
        for stop in [0, 5]:
            with self.subTest(stop=stop):
                result, error, calls, receipt = self.fetch(stop=stop)
                self.assertIsNone(error)
                self.assertIsInstance(result, Path)
                scoped = next((a, k) for a, k in calls if a[0] == "systemd-run")
                self.assertIn("--unit=" + receipt["unit"], scoped[0])
                self.assertIn("RuntimeMaxSec=180", scoped[0])
                self.assertIn("MemoryMax=512M", scoped[0])
                self.assertNotIn(TOKEN, repr(scoped[0]))
                self.assertIn("GIT_CONFIG_VALUE_0", scoped[1]["env"])
                stops = [a for a, _ in calls if a[0] == "systemctl"]
                self.assertEqual(stops, [["systemctl", "stop", receipt["unit"] + ".scope"]])
                for arguments, options in calls:
                    if arguments[0] != "systemd-run":
                        self.assertNotIn("GIT_CONFIG_VALUE_0", options["env"])

    def test_fetch_timeout_or_cancellation_still_joins_its_exact_scope(self):
        for outcome in [subprocess.TimeoutExpired(["synthetic-fetch"], 190), InterruptedError("synthetic cancel")]:
            with self.subTest(error=type(outcome).__name__):
                _, error, calls, receipt = self.fetch(outcome)
                self.assertIs(type(error), type(outcome))
                self.assertIn(["systemctl", "stop", receipt["unit"] + ".scope"], [a for a, _ in calls])
                self.assertFalse(any("rev-parse" in a for a, _ in calls))

    def test_failed_transport_withholds_credential_bearing_output(self):
        _, error, _, _ = self.fetch(1)
        self.assertIsInstance(error, RuntimeError)
        self.assertNotIn(TOKEN, str(error))
        self.assertIn("output withheld", str(error))

    def test_unproved_scope_closure_never_returns_a_source(self):
        result, error, calls, _ = self.fetch(stop=1)
        self.assertIsNone(result)
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("closure is unproved", str(error))
        self.assertFalse(any("rev-parse" in a for a, _ in calls))

    def test_root_preparation_always_selects_the_scoped_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(approval, "fetch_main", return_value=directory) as fetch, \
                    patch.object(approval, "source_policy", side_effect=RuntimeError("stop before build")):
                with self.assertRaisesRegex(RuntimeError, "stop before build"):
                    approval.prepare(dict(token=TOKEN), dict(repository=REPOSITORY), {},
                                     dict(source=SOURCE), directory, object())
            self.assertEqual(fetch.call_args.kwargs, {"scoped": True})


class NativeOutputReview(unittest.TestCase):
    def test_regular_controller_owned_bytes_can_be_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / "output"
            file.write_bytes(b"synthetic output")
            with approval.controller_file(file, SimpleNamespace(pw_uid=os.getuid()), 64) as stream:
                self.assertEqual(stream.read(), b"synthetic output")

    def test_symlink_hardlink_fifo_and_oversize_never_become_prepared_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ordinary = root / "ordinary"
            ordinary.write_bytes(b"synthetic output")
            symlink = root / "symlink"
            symlink.symlink_to(ordinary)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            hardlink = root / "hardlink"
            os.link(ordinary, hardlink)
            for file in [symlink, fifo, hardlink]:
                with self.subTest(file=file.name), self.assertRaises((OSError, ValueError)):
                    approval.controller_file(file, SimpleNamespace(pw_uid=os.getuid()), 64)
            large = root / "large"
            large.write_bytes(b"x" * 65)
            with self.assertRaises(ValueError):
                approval.controller_file(large, SimpleNamespace(pw_uid=os.getuid()), 64)

    def test_root_storage_refuses_native_controller_owned_or_writable_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(approval.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=os.getuid())):
                with self.assertRaises(ValueError):
                    approval.check_directory(root, SimpleNamespace(pw_uid=os.getuid()))
                root.chmod(0o777)
                with self.assertRaises(ValueError):
                    approval.check_directory(root, SimpleNamespace(pw_uid=os.getuid()))


class PublicationReview(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.live = self.root / "live.json"
        self.report = self.root / "old-report.json"
        self.cache = self.root / "old-cache"
        self.cache.write_bytes(b"synthetic dependency seed")
        self.cache.chmod(0o644)
        self.old_report = dict(policy_source="b" * 40, image="sha256:" + "c" * 64, policy={})
        self.report.write_text(json.dumps(self.old_report))
        self.live.write_text(json.dumps(dict(repository=REPOSITORY, image_report=str(self.report),
            cache=str(self.cache), cache_sha256=hashlib.sha256(self.cache.read_bytes()).hexdigest())))
        self.original = self.live.read_bytes()
        self.binding = dict(source=SOURCE, run=123, attempt=2, pull_request=7)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        def patched(target, *args, **kwargs):
            return self.stack.enter_context(patch.object(target, *args, **kwargs))
        patched(approval, "CONFIG", self.root / "config.json")
        patched(approval, "LIVE", self.live)
        (self.root / "config.json").write_text(json.dumps(dict(state=str(self.state))))
        patched(approval, "trusted", side_effect=lambda p: json.loads(Path(p).read_text()))
        patched(approval, "check_directory", side_effect=lambda p, _: Path(p))
        patched(approval, "GitHub", return_value=object())
        patched(approval, "main_source", return_value=self.binding)
        patched(approval.os, "geteuid", return_value=0)
        patched(approval.os, "chown")
        native_stat = Path.lstat
        def root_cache(path, *args, **kwargs):
            value = native_stat(path, *args, **kwargs)
            if path == self.cache:
                return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_size=value.st_size)
            return value
        patched(Path, "lstat", root_cache)
        patched(approval.pwd, "getpwnam", return_value=SimpleNamespace(
            pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name="synthetic-controller"))
        read_text = Path.read_text
        patched(Path, "read_text", lambda p, *a, **k: "MemAvailable: 134217728 kB\n"
                if p == Path("/proc/meminfo") else read_text(p, *a, **k))
        patched(approval.shutil, "disk_usage", return_value=SimpleNamespace(free=100 * 1024**3))
        self.prepare = patched(approval, "prepare", return_value=(
            {**self.old_report, "policy_source": SOURCE}, self.cache,
            hashlib.sha256(self.cache.read_bytes()).hexdigest()))
        self.cleanup = patched(approval, "cleanup")
        self.current = patched(approval, "current_main")

    def call(self):
        return approval.approve(dict(context=context(), token=TOKEN))

    def test_failed_or_cancelled_preparation_keeps_previous_publication(self):
        for error in [RuntimeError("synthetic build failure"), InterruptedError("synthetic cancel")]:
            with self.subTest(error=type(error).__name__):
                self.prepare.side_effect = error
                with self.assertRaises(type(error)):
                    self.call()
                self.assertEqual(self.live.read_bytes(), self.original)
                self.assertEqual(json.loads(self.report.read_text()), self.old_report)

    def test_cleanup_and_stale_main_fail_before_publication(self):
        for dependency in [self.cleanup, self.current]:
            with self.subTest(dependency=dependency):
                dependency.side_effect = RuntimeError("synthetic failure")
                with self.assertRaises(RuntimeError):
                    self.call()
                self.assertEqual(self.live.read_bytes(), self.original)
                dependency.side_effect = None

    def test_maintainer_configuration_change_is_not_overwritten(self):
        changed = self.original + b"\n"
        def prepare(*_):
            self.live.write_bytes(changed)
            return self.prepare.return_value
        self.prepare.side_effect = prepare
        with self.assertRaisesRegex(RuntimeError, "maintainer configuration changed"):
            self.call()
        self.assertEqual(self.live.read_bytes(), changed)

    def test_success_publishes_an_existing_immutable_snapshot(self):
        result = self.call()
        self.assertEqual(result["status"], "approved")
        published = json.loads(self.live.read_text())
        self.assertNotEqual(published["image_report"], str(self.report))
        self.assertEqual(json.loads(Path(published["image_report"]).read_text())["policy_source"], SOURCE)
        self.assertEqual(json.loads(self.report.read_text()), self.old_report)

    def test_cancellation_after_commit_records_actual_published_snapshot(self):
        record = approval.record
        def canceled(path, value, group=None):
            if Path(path).name == "result.json":
                raise InterruptedError("synthetic cancellation after commit")
            return record(path, value, group)
        with patch.object(approval, "record", side_effect=canceled), self.assertRaises(InterruptedError):
            self.call()
        published = json.loads(self.live.read_text())["image_report"]
        self.assertNotEqual(self.live.read_bytes(), self.original)
        failure, = self.state.glob("*/failure.json")
        self.assertEqual(json.loads(failure.read_text())["published_report"], published)


class RebuildWindowReview(unittest.TestCase):
    def test_pr_drift_uses_previous_snapshot_and_routes_hosted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_cache = root / "old-cache"
            config = dict(repository=REPOSITORY, state=str(root), cache=str(old_cache),
                          cache_sha256="c" * 64, image_report=str(root / "old-report"))
            report = dict(image="sha256:" + "d" * 64, policy={"Cargo.toml": "a" * 64})
            request = dict(args={"container": {"image": "stateengine-ci-approved",
                "environmentVariables": {"CI_SOURCE_TOKEN": TOKEN}}})
            cx = {**context(), "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/7/merge"}
            with patch.object(hook, "capacity"), patch.object(hook, "changed_policy", return_value=["Cargo.toml"]), \
                    patch.object(hook, "fetch") as fetch, patch.object(hook.subprocess, "Popen") as spawn:
                response = hook.prepare(request, config, report, cx)
            fetch.assert_not_called()
            spawn.assert_not_called()
            job = root / response["state"]["job"]
            binding = json.loads((job / "binding.json").read_text())
            self.assertEqual(binding["approval"]["image_report"], config["image_report"])
            newer = {**config, "image_report": str(root / "new-report"), "cache": str(root / "new-cache")}
            with patch.object(hook, "config_values", return_value=(config, report)) as values:
                route = hook.script_step(dict(operation="route", args={}), newer, report, job)
                unavailable = hook.script_step(dict(operation="linux", args={}), newer, report, job)
            self.assertEqual(route["outputs"]["route"], "hosted")
            self.assertEqual(unavailable["outputs"]["status"], "unavailable")
            for call in values.call_args_list:
                self.assertEqual(call.args[0]["image_report"], config["image_report"])
                self.assertEqual(call.args[0]["cache"], str(old_cache))


if __name__ == "__main__":
    unittest.main()
