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
from contextlib import contextmanager, redirect_stdout
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from custody import idle
import engine
from engine import ACCOUNT, ENGINE_DOOR, command, engine_args

HELPER = Path(__file__).with_name("idle.py")
IDLE_PROOF = {"schema": "stateengine-ci-idle/v1", "idle": True}

# Realistic synthetic provisioning records (the provisioned uids and paths). No
# test may require administrator provisioning or skip a control, so the
# dedicated accounts and the caller identity are supplied by the fixtures.
CI_ACCOUNT = SimpleNamespace(pw_name="stateengine-ci", pw_passwd="x", pw_uid=1004, pw_gid=1004,
                             pw_gecos="", pw_dir="/var/lib/stateengine-ci", pw_shell="/usr/sbin/nologin")
CI_CONTROLLER = SimpleNamespace(pw_name="stateengine-ci-controller", pw_passwd="x", pw_uid=997, pw_gid=997,
                                pw_gecos="", pw_dir="/var/lib/stateengine-ci", pw_shell="/usr/sbin/nologin")
CALLER_UID = 1000


@contextmanager
def synthetic_host(caller=CALLER_UID):
    """Synthetic passwd records and caller identity for the dedicated accounts.

    engine.py and custody.py resolve the dedicated account and the calling uid
    through the shared pwd/os module globals; this replaces only those lookups
    with the provisioned records so argument construction runs unchanged on a
    clean host. subprocess stays the caller's stub; no engine command is run.
    """
    by_name = {CI_ACCOUNT.pw_name: CI_ACCOUNT, CI_CONTROLLER.pw_name: CI_CONTROLLER}
    by_uid = {record.pw_uid: record for record in (CI_ACCOUNT, CI_CONTROLLER)}
    caller_record = SimpleNamespace(pw_name="ordinary", pw_passwd="x", pw_uid=caller, pw_gid=caller,
                                    pw_gecos="", pw_dir="/home/ordinary", pw_shell="/bin/bash")

    def getpwnam(name):
        try:
            return by_name[name]
        except KeyError:
            raise KeyError(f"no such name: {name!r}") from None

    def getpwuid(uid):
        if uid in by_uid:
            return by_uid[uid]
        if uid == caller:
            return caller_record
        raise KeyError(f"no such uid: {uid!r}")

    with patch.object(engine.pwd, "getpwnam", side_effect=getpwnam), \
            patch.object(engine.pwd, "getpwuid", side_effect=getpwuid), \
            patch.object(engine.os, "getuid", return_value=caller):
        yield


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
                    synthetic_host(), \
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
        # The synthetic caller is an ordinary non-provisioned uid, so the sudo
        # prefix is exercised on any host, including root and clean hosts.
        with synthetic_host():
            argv = self.run_command_from(self.private.name)
        self.assertEqual(argv[:4], ["sudo", "-n", "-u", ACCOUNT])
        self.assertEqual(argv[4], "env")
        self.assertEqual(argv[5], "-i")
        self.assertIn(f"HOME={CI_ACCOUNT.pw_dir}", argv)
        self.assertIn(f"XDG_RUNTIME_DIR=/run/user/{CI_ACCOUNT.pw_uid}", argv)
        self.assertIn(f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{CI_ACCOUNT.pw_uid}/bus", argv)
        self.assertEqual(argv[-4:], ["podman", "ps", "--all", "--format=json"])

    def test_controller_branch_still_names_the_fixed_engine_door(self):
        with synthetic_host(caller=CI_CONTROLLER.pw_uid):
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
