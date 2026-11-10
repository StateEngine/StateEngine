"""Exercise reservation and durable publication through their real readers."""
from dataclasses import asdict
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import dispatch
from dispatch_binding import Request
from box_result import external_id, report, STAGES
import transport
import workload
import threading

B = dict(repository=1, run=2, attempt=3, checkout="a"*40, head="b"*40)
REQUEST = Request(B, 4, 5)


def terminal():
    stages = {name: dict(exit=0, tests=1, custom=9, docs=1, checks=1) for name in STAGES}
    return dict(app_id=9, request=asdict(REQUEST), report=report(
        B, 7, "sha256:"+"c"*64, "d"*64, "passed", stages))


def current_api(change=None):
    api = Mock()
    def read(path, **kwargs):
        if path == "check-runs/7":
            return dict(app={"id": 9}, head_sha=B["checkout"], external_id=external_id(B))
        if path == "actions/runs/2":
            value = dict(run_attempt=3, status="in_progress")
        elif path == "pulls/4":
            value = dict(state="open", head={"sha": B["head"]}, merge_commit_sha=B["checkout"])
        elif path == "actions/runs/2/attempts/3/jobs?per_page=100":
            value = dict(total_count=2, jobs=[dict(name="linux-route", conclusion="success"),
                         dict(name="linux-box", status="in_progress")])
        else:
            raise AssertionError("unexpected API path: "+path)
        if change:
            change(path, value)
        return value
    api.get.side_effect = read
    return api


class Corrections(unittest.TestCase):
    def test_natural_exit_observation_preserves_its_order_against_cancellation(self):
        for canceled_first in (False, True):
            canceled = threading.Event()
            if canceled_first: canceled.set()
            box = Mock(id="owned", started=time.monotonic(), deadline=5)
            command = [sys.executable, "-c", "raise SystemExit(7)"]
            with tempfile.TemporaryDirectory() as temporary, patch("transport.engine_args", return_value=command):
                result = transport.execute(box, [], Path(temporary)/"output", canceled=canceled)
            self.assertEqual(result["exit_code"], 7)
            self.assertEqual(result["exit_observed_before_cancel"], not canceled_first)
            canceled.set()
            if canceled_first:
                workload.observed_failure(result)  # No failed observation predates cancellation.
            else:
                with self.assertRaises(transport.WorkloadFailure): workload.observed_failure(result)

    def test_deadline_failure_survives_cleanup_and_joins_the_real_child(self):
        children = []
        popen = subprocess.Popen
        def child(*args, **kwargs):
            value = popen(*args, **kwargs)
            children.append(value)
            return value
        box = Mock(id="owned", started=time.monotonic(), deadline=.05)
        box.close.side_effect = RuntimeError("engine cleanup unavailable")
        with tempfile.TemporaryDirectory() as temporary, \
                patch("transport.engine_args", return_value=[sys.executable, "-c", "import time;time.sleep(5)"]), \
                patch("transport.subprocess.Popen", side_effect=child):
            result = transport.execute(box, [], Path(temporary)/"output")
        self.assertEqual(result["reason"], "deadline exceeded")
        self.assertFalse(result["success"])
        self.assertIn("cleanup unavailable", result["cleanup_error"])
        self.assertTrue(children and all(p.poll() is not None for p in children))

    def test_artifact_limit_survives_cleanup_failure_and_joins_child(self):
        children = []
        popen = subprocess.Popen
        def child(*args, **kwargs):
            value = popen(*args, **kwargs)
            children.append(value)
            return value
        box = Mock(id="owned", started=time.monotonic(), deadline=10)
        box.close.side_effect = RuntimeError("engine cleanup unavailable")
        command = [sys.executable, "-c", "import sys,time;sys.stdout.write('x'*32);sys.stdout.flush();time.sleep(5)"]
        with tempfile.TemporaryDirectory() as temporary, \
                patch("transport.ARTIFACTS", {"archive": ("/fixed", 8)}), \
                patch("transport.engine_args", return_value=command), \
                patch("transport.subprocess.Popen", side_effect=child):
            with self.assertRaisesRegex(transport.WorkloadFailure, "byte budget"):
                transport.export(box, "archive", Path(temporary)/"archive")
        self.assertTrue(children and all(p.poll() is not None for p in children))

    def test_exporter_refusal_is_infrastructure_but_post_eof_deadline_is_workload(self):
        cases = [([sys.executable, "-c", "raise SystemExit(1)"],
                  RuntimeError, "infrastructure artifact export refused"),
                 ([sys.executable, "-c", "import os,time;os.close(1);os.close(2);time.sleep(5)"],
                  transport.WorkloadFailure, "artifact export deadline exceeded")]
        for command, expected, reason in cases:
            children = []
            popen = subprocess.Popen
            def child(*args, **kwargs):
                value = popen(*args, **kwargs)
                children.append(value)
                return value
            box = Mock(id="owned", started=time.monotonic(), deadline=.1)
            box.close.side_effect = RuntimeError("engine cleanup unavailable")
            with tempfile.TemporaryDirectory() as temporary, \
                    patch("transport.engine_args", return_value=command), \
                    patch("transport.subprocess.Popen", side_effect=child):
                with self.assertRaisesRegex(expected, reason) as observed:
                    transport.export(box, "archive", Path(temporary)/"archive")
                if expected is RuntimeError:
                    self.assertNotIsInstance(observed.exception, transport.WorkloadFailure)
            self.assertTrue(children and all(p.poll() is not None for p in children))

    def test_observed_limit_is_recorded_before_concurrent_cancellation_or_final_cleanup(self):
        canceled = threading.Event()
        box = Mock(proof={"seccomp_profile_sha256": "d"*64})
        box.close.side_effect = RuntimeError("engine cleanup unavailable")
        def execute(*args, **kwargs):
            canceled.set()
            return dict(success=False, reason="output exceeds byte budget")
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            source = folder/"source"
            source.write_bytes(b"opaque")
            cohort = workload.Cohort(dict(image="sha256:"+"c"*64, seccomp_sha256="d"*64),
                                     None, source, source, folder, canceled)
            with patch("workload.Tracked", return_value=box), patch("workload.execute", side_effect=execute):
                with self.assertRaises(RuntimeError): cohort.stage("clippy")
            self.assertEqual(cohort.outcomes["clippy"]["exit"], 1)

    def test_each_remote_observation_receives_only_the_original_remaining_budget(self):
        clock = [0]
        api = current_api()
        original = api.get.side_effect
        budgets = []
        def read(path, **kwargs):
            budgets.append(kwargs["timeout"])
            clock[0] += 4
            return original(path)
        api.get.side_effect = read
        self.assertTrue(dispatch.handshake(api, REQUEST, clock=lambda: clock[0]))
        self.assertEqual(budgets, [30, 26, 22])

    def test_jobs_response_after_expiry_never_admits(self):
        clock = [0]
        def slow_jobs(path, value):
            if "/jobs?" in path:
                clock[0] = 31
        self.assertFalse(dispatch.handshake(current_api(slow_jobs), REQUEST, clock=lambda: clock[0]))

    def test_blocking_remote_read_is_interrupted_and_alarm_is_restored(self):
        api = Mock()
        api.get.side_effect = lambda *a, **kw: time.sleep(2)
        before = signal.getsignal(signal.SIGALRM)
        start = time.monotonic()
        self.assertFalse(dispatch.handshake(api, REQUEST, seconds=.05))
        self.assertLess(time.monotonic()-start, .5)
        self.assertEqual(signal.getsignal(signal.SIGALRM), before)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))

    def test_current_live_consumer_can_publish_success(self):
        api = current_api()
        self.assertTrue(dispatch.publish(api, terminal()))
        self.assertEqual(api.write.call_args.args[1]["conclusion"], "success")

    def test_all_stale_request_paths_refuse_saved_success(self):
        def canceled(path, value):
            if path == "actions/runs/2": value["status"] = "completed"
        def retried(path, value):
            if path == "actions/runs/2": value["run_attempt"] = 4
        def moved_head(path, value):
            if path == "pulls/4": value["head"]["sha"] = "e"*40
        def moved_merge(path, value):
            if path == "pulls/4": value["merge_commit_sha"] = "e"*40
        def closed(path, value):
            if path == "pulls/4": value["state"] = "closed"
        def consumer_finished(path, value):
            if "/jobs?" in path: value["jobs"][1]["status"] = "completed"
        for change in (canceled, retried, moved_head, moved_merge, closed, consumer_finished):
            with self.subTest(change=change.__name__):
                api = current_api(change)
                self.assertFalse(dispatch.publish(api, terminal()))
                api.write.assert_not_called()

    def test_main_supersession_also_refuses_success(self):
        value = terminal()
        value["request"]["number"] = 0
        api = current_api()
        original = api.get.side_effect
        api.get.side_effect = lambda path: ({"object": {"sha": "e"*40}}
            if path == "git/ref/heads/main" else original(path))
        self.assertFalse(dispatch.publish(api, value))
        api.write.assert_not_called()

    def test_cancellation_during_job_inventory_is_rechecked_before_publication(self):
        canceled = [False]
        def change(path, value):
            if "/jobs?" in path: canceled[0] = True
            if path == "actions/runs/2" and canceled[0]: value["status"] = "completed"
        api = current_api(change)
        self.assertFalse(dispatch.publish(api, terminal()))
        api.write.assert_not_called()

    def test_retry_after_lost_reply_revalidates_without_rewriting_the_original_fact(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            folder = state/"2-3"
            folder.mkdir()
            api = current_api()
            api.write.side_effect = RuntimeError("lost reply")
            with self.assertRaises(RuntimeError):
                dispatch.finish(api, REQUEST, 7, dict(image="sha256:"+"c"*64,
                    policy_digest="d"*64), "passed", terminal()["report"]["stages"], folder, 9)
            original = (folder/"terminal.json").read_bytes()
            def canceled(path, value):
                if path == "actions/runs/2": value["status"] = "completed"
            retry = current_api(canceled)
            dispatch.retry_terminal(retry, state)
            retry.write.assert_not_called()
            self.assertEqual((folder/"terminal.json").read_bytes(), original)
            self.assertFalse(json.loads((folder/"published").read_text())["published"])

    def test_unreadable_liveness_retains_retry_without_publishing(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)/"2-3"
            folder.mkdir()
            dispatch.save(folder/"terminal.json", terminal())
            api = current_api()
            original = api.get.side_effect
            def read(path):
                if path == "actions/runs/2": raise RuntimeError("transport unavailable")
                return original(path)
            api.get.side_effect = read
            with self.assertRaises(RuntimeError): dispatch.retry_terminal(api, Path(temporary))
            api.write.assert_not_called()
            self.assertFalse((folder/"published").exists())
