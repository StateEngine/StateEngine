"""Controller ownership, handshake and persistent terminal outcomes."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from dispatch_binding import Request
import dispatch
from workload import counts

B = dict(repository=1, run=2, attempt=3, checkout="a"*40, head="b"*40)


class Controller(unittest.TestCase):
    def test_reservation_expires_without_starting_queued_or_skipped_work(self):
        request = Request(B, 4, 5)
        for status in ("queued", "completed"):
            clock = [0]
            def sleep(n): clock[0] += n
            with patch("dispatch.live", return_value=True), patch("dispatch.jobs", return_value=[
                    {"name": "linux-route", "conclusion": "success"},
                    {"name": "linux-box", "status": status}]):
                self.assertFalse(dispatch.handshake(Mock(), request, seconds=30,
                    clock=lambda: clock[0], sleep=sleep))
                self.assertLessEqual(clock[0], 30)

    def test_only_running_consumer_after_successful_route_arms_work(self):
        with patch("dispatch.live", return_value=True), patch("dispatch.jobs", return_value=[
                {"name": "linux-route", "conclusion": "success"},
                {"name": "linux-box", "status": "in_progress"}]):
            self.assertTrue(dispatch.handshake(Mock(), Request(B, 4, 5)))
        with patch("dispatch.live", return_value=False):
            self.assertFalse(dispatch.handshake(Mock(), Request(B, 4, 5)))

    def test_known_failure_is_durable_across_lost_publish_response(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            image = dict(image="sha256:"+"c"*64, policy_digest="d"*64)
            stages = {"clippy": dict(exit=1, tests=0, custom=0, docs=0, checks=0)}
            with patch("dispatch.publish", side_effect=RuntimeError("lost response")):
                with self.assertRaises(RuntimeError):
                    dispatch.finish(Mock(), Request(B, 4, 5), 7, image, "failed", stages, folder, 9)
            with patch("dispatch.publish") as publish:
                dispatch.finish(Mock(), Request(B, 4, 5), 7, image, "unavailable", {}, folder, 9)
                self.assertEqual(publish.call_args.args[1]["report"]["status"], "failed")

    def test_candidate_exit_and_nonzero_counts_both_required(self):
        text = "Summary [ 1s] 2 tests run: 2 passed\n"
        self.assertEqual(counts("test-2", text, 0)["exit"], 0)
        self.assertEqual(counts("test-2", text, 1)["exit"], 1)
        self.assertEqual(counts("test-2", "", 0)["exit"], 1)
        self.assertEqual(counts("test-2", text+text, 0)["exit"], 1)
