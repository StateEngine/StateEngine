"""The installed idle helper must run its engine query from a fixed accessible cwd.

Base failure control: on base bytes the helper's engine child inherits the private
caller cwd (reproduced in the unit seam below); the fix must make the child cwd
independent of the caller while retaining no-argument enforcement and the
conservative custody refusals. The native locked-worker proof stays the boundary
of the author and second reviewer; this file never runs a live engine command.
"""
import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from custody import idle
import engine
from engine import ACCOUNT, ENGINE_DOOR, command, engine_args

HELPER = Path(__file__).with_name("idle.py")
IDLE_PROOF = {"schema": "stateengine-ci-idle/v1", "idle": True}


class InstalledHelperConsumer(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory()
        self.accessible = tempfile.TemporaryDirectory()
        os.chmod(self.private.name, 0o700)
        self.addCleanup(self.private.cleanup)
        self.addCleanup(self.accessible.cleanup)
        self.old_cwd = os.getcwd()
        self.addCleanup(os.chdir, self.old_cwd)

    def run_helper_from(self, caller_cwd):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append({"argv": list(argv), "child_cwd": os.getcwd()})
            return subprocess.CompletedProcess(list(argv), 0, b"[]", b"")

        old_argv = sys.argv
        os.chdir(caller_cwd)
        try:
            with patch("subprocess.run", side_effect=fake_run), \
                    patch("custody.read_records", return_value=[]), \
                    redirect_stdout(io.StringIO()) as out:
                sys.argv = [str(HELPER)]
                runpy.run_path(str(HELPER), run_name="__main__")
        finally:
            sys.argv = old_argv
        return calls, out.getvalue()

    def test_helper_engine_child_cwd_is_independent_of_caller_cwd(self):
        from_private, out_private = self.run_helper_from(self.private.name)
        from_accessible, _ = self.run_helper_from(self.accessible.name)
        self.assertEqual(len(from_private), 1, "the helper must reach exactly one engine query")
        self.assertEqual(json.loads(out_private.strip()), IDLE_PROOF)
        private_child = from_private[0]["child_cwd"]
        accessible_child = from_accessible[0]["child_cwd"]
        self.assertNotEqual(private_child, self.private.name,
            "engine child inherits the private caller cwd; pin a fixed cwd in the helper")
        self.assertNotEqual(private_child, self.accessible.name)
        self.assertTrue(os.path.isabs(private_child), "pinned helper cwd must be absolute")
        self.assertEqual(private_child, accessible_child,
            "helper engine child cwd must not depend on the caller cwd")

    def test_helper_refuses_arguments_from_any_cwd(self):
        for caller in (self.private, self.accessible):
            os.chdir(caller.name)
            old_argv = sys.argv
            try:
                with redirect_stdout(io.StringIO()) as out, redirect_stderr_capture() as err:
                    sys.argv = [str(HELPER), "--bogus"]
                    with self.assertRaises(SystemExit) as raised:
                        runpy.run_path(str(HELPER), run_name="__main__")
                self.assertEqual(raised.exception.code, "CI idle query accepts no arguments")
                self.assertEqual(out.getvalue(), "")
            finally:
                sys.argv = old_argv


class redirect_stderr_capture:
    def __init__(self):
        self.stream = io.StringIO()

    def __enter__(self):
        self.old = sys.stderr
        sys.stderr = self.stream
        return self.stream

    def __exit__(self, *exc):
        sys.stderr = self.old


class EngineContract(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory()
        os.chmod(self.private.name, 0o700)
        self.addCleanup(self.private.cleanup)
        self.old_cwd = os.getcwd()
        self.addCleanup(os.chdir, self.old_cwd)

    def run_command_from(self, caller_cwd):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append({"argv": list(argv)})
            return subprocess.CompletedProcess(list(argv), 0, b"[]", b"")

        os.chdir(caller_cwd)
        with patch("subprocess.run", side_effect=fake_run):
            out = command("ps", "--all", "--format=json")
        self.assertEqual(json.loads(out), [])
        return calls[0]["argv"]

    def test_worker_branch_keeps_the_conservative_wrapped_environment(self):
        if os.getuid() == 0:
            self.skipTest("worker sudo prefix is only exercised as a non-root caller")
        argv = self.run_command_from(self.private.name)
        self.assertEqual(argv[:4], ["sudo", "-n", "-u", ACCOUNT])
        self.assertEqual(argv[4], "env")
        self.assertEqual(argv[5], "-i")
        self.assertIn(f"HOME=/var/lib/stateengine-ci", argv)
        self.assertTrue(any(a.startswith("XDG_RUNTIME_DIR=/run/user/") for a in argv))
        self.assertTrue(any(a.startswith("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/") for a in argv))
        self.assertEqual(argv[-4:], ["podman", "ps", "--all", "--format=json"])

    def test_controller_branch_still_names_the_fixed_engine_door(self):
        controller = engine.pwd.getpwnam("stateengine-ci-controller")
        with patch.object(engine.pwd, "getpwuid", return_value=controller):
            self.assertEqual(engine_args("ps", "--all", "--format=json"),
                             ["sudo", "-n", "-u", ACCOUNT, ENGINE_DOOR, "ps", "--all", "--format=json"])


class IdleSemantics(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o750)
        self.cwds = [tempfile.TemporaryDirectory() for _ in range(2)]
        self.empty = patch("custody.inventory", return_value=[])
        self.empty.start()

    def tearDown(self):
        self.empty.stop()
        for d in self.cwds:
            d.cleanup()
        self.temp.cleanup()

    def write_record(self, name):
        path = self.root / (name + ".json")
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
        with os.fdopen(fd, "w") as out:
            json.dump({"name": name, "id": None, "native": {}}, out)

    def test_empty_custody_is_the_exact_idle_proof(self):
        self.assertEqual(idle(self.root), IDLE_PROOF)

    def test_unknown_entry_and_nonempty_records_refuse(self):
        self.write_record("se-ci-" + "a" * 32)
        with self.assertRaisesRegex(RuntimeError, "reconciliation"):
            idle(self.root)
        fd = os.open(self.root / "stray.txt", os.O_CREAT | os.O_WRONLY, 0o640)
        os.close(fd)
        with self.assertRaisesRegex(RuntimeError, "unknown entry"):
            idle(self.root)

    def test_persistent_engine_jobs_refuse(self):
        with patch("custody.inventory", return_value=[{"Id": "b" * 64, "Names": []}]):
            with self.assertRaisesRegex(RuntimeError, "persistent engine jobs remain"):
                idle(self.root)

    def test_missing_records_are_not_zero(self):
        with self.assertRaises(Exception):
            idle(self.root / "absent-journal")


if __name__ == "__main__":
    unittest.main()
