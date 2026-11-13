"""Judge the check-run failure summary against real nextest logs."""
import json
import pathlib
import re
import unittest

import box
import box_result as wire
from test_box import B, IMAGE, stages

FIX = pathlib.Path(__file__).parent / "fixtures"
STARTUP = (FIX / "nextest_startup_failures.log").read_text()
ONE = (FIX / "nextest_one_failure.log").read_text()
TESTS = [
    "se::agent_allocation_routes direct_agent_allocations_remain_distinct_and_replay_without_new_events",
    "se::claude_capture_catchup delayed_final_reply_commit_clears_failure_before_resume",
    "se::claude_capture_catchup unimpeded_capture_keeps_one_original_reply",
]


class RealLogs(unittest.TestCase):
    def test_colored_multi_failure_log_names_every_test_with_its_own_message(self):
        # Real CI runs colour the log; the reader must still find every failure.
        self.assertIn("\x1b[", STARTUP)
        found = wire.details(STARTUP)
        self.assertEqual([item.split(" at ")[0] for item in found], TESTS)
        self.assertIn("agent_allocation_routes.rs:39:5", found[0])
        self.assertIn("actual CLI refused", found[0])
        self.assertIn("claude_capture_catchup.rs:41:5", found[1])
        self.assertIn("retained capture fixture", found[1])
        self.assertNotIn("actual CLI refused", found[1])
        self.assertNotIn("actual CLI refused", found[2])

    def test_single_failure_log_is_named(self):
        found = wire.details(ONE)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith(
            "se-store::deferred_checkpoint_independent pressure_blocks_growth"))

    def test_published_lines_carry_no_machine_identity_or_paths(self):
        # A failing test may print ids and temp roots; they must not be published.
        body = "\n".join(wire.details(STARTUP))
        self.assertNotIn("MachineId", body)
        self.assertNotIn("boot_id", body)
        self.assertNotIn("/tmp/", body)
        self.assertIsNone(re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-", body))

    def test_aggregate_across_shards_stays_within_bound(self):
        # test-1 and test-2 each contribute; the combined report must still publish.
        shard = wire.details("\n".join(
            f"        FAIL [   0.0s] (1/1) se-x::t test_{n:02d}\n"
            f"    thread 'test_{n:02d}' (1) panicked at a.rs:1:1:\n    " + "m" * 250
            for n in range(20)))
        values = stages()
        values["test-1"]["exit"] = values["test-2"]["exit"] = 1
        report = wire.report(B, 7, IMAGE, "d"*64, "failed", values, shard + shard)
        self.assertLessEqual(len(json.dumps(report["failures"]).encode()), wire.FAIL_BYTES)
        self.assertIn("(further failures omitted)", report["failures"])
