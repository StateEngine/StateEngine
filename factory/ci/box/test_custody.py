"""Crash leftovers retain custody until real child identity and journal cleanup join."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from custody import Journal, idle, pin, read_records

NAME = "se-ci-" + "a"*32
CID = "b"*64


class Custody(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o750)
        self.journal = Journal(self.root)
        self.empty = patch("custody.inventory", return_value=[])
        self.empty.start()

    def tearDown(self):
        self.empty.stop()
        self.temp.cleanup()

    def test_creation_intent_blocks_idle_even_without_an_engine_object(self):
        self.journal.intent(NAME)
        with self.assertRaisesRegex(RuntimeError, "reconciliation"):
            idle(self.root)
        self.journal.reconcile()
        self.assertTrue(idle(self.root)["idle"])

    def test_controller_lock_release_does_not_clear_a_real_child_pin(self):
        child = subprocess.Popen([sys.executable, "-c", "import sys;sys.stdin.read()"], stdin=subprocess.PIPE)
        try:
            self.journal.intent(NAME)
            self.journal.write(NAME, {"name": NAME, "id": CID,
                "native": {"processes": [pin(child.pid)], "cgroup": None}})
            with self.assertRaisesRegex(RuntimeError, "native"):
                idle(self.root)
            with self.assertRaisesRegex(RuntimeError, "closure"):
                self.journal.closed(NAME)
            child.communicate(b"stop", timeout=5)
            self.journal.reconcile()
            self.assertTrue(idle(self.root)["idle"])
        finally:
            if child.poll() is None:
                child.communicate(b"stop", timeout=5)

    def test_exited_inspect_does_not_erase_previous_native_pins(self):
        self.journal.intent(NAME)
        old = pin(os.getpid())
        self.journal.write(NAME, {"name": NAME, "id": CID,
                                "native": {"processes": [old], "cgroup": None}})
        with patch("custody.native_state", return_value={"processes": [], "cgroup": None}):
            self.journal.observe(NAME, {"Id": CID, "Name": NAME})
        self.assertEqual(read_records(self.root)[0][1]["native"]["processes"], [old])
        with self.assertRaisesRegex(RuntimeError, "closure"):
            self.journal.closed(NAME)

    def test_unknown_objects_and_unreadable_engine_are_not_zero(self):
        with patch("custody.inventory", return_value=[{"Id": CID, "Names": [NAME]}]):
            with self.assertRaisesRegex(RuntimeError, "persistent"):
                idle(self.root)
            with self.assertRaisesRegex(RuntimeError, "unknown"):
                self.journal.reconcile()
        with patch("custody.inventory", side_effect=RuntimeError("unreadable")):
            with self.assertRaisesRegex(RuntimeError, "unreadable"):
                idle(self.root)

    def test_precreate_child_observes_durable_native_pin_before_acknowledgement(self):
        self.journal.intent(NAME)
        script = ("import os,sys,json; print(json.dumps({'pid':os.getpid()}),flush=True); "
                  "assert sys.stdin.readline()=='RUN\\n'; "
                  "d=json.load(open(sys.argv[1])); assert d['native']['processes'][0]['pid']==os.getpid(); "
                  "print('b'*64,flush=True)")
        # The fixed door argument is an explicit test substitute; no engine operation is run.
        with patch("custody.engine_args", return_value=[sys.executable, "-c", script,
                str(self.root/(NAME+".json")), "/usr/local/libexec/stateengine-ci-engine"]):
            self.assertEqual(self.journal.create(NAME, ["create"]), CID)
        self.journal.reconcile()
        self.assertTrue(idle(self.root)["idle"])
