"""Contract failures at the hosted result boundary, including absence and duplicate offers."""
import copy
import json
import unittest
from unittest.mock import Mock

import box
import box_result as wire

B = wire.binding(1, 2, 3, "a"*40, "b"*40)
IMAGE = "sha256:" + "c"*64


def stages():
    values = {n: dict(exit=0, tests=0, custom=0, docs=0, checks=0) for n in wire.STAGES}
    values["fmt"]["checks"] = 25
    values["archive"]["docs"] = 3
    values["test-1"].update(tests=362, custom=9)
    values["test-2"]["tests"] = 361
    return values


def check(status="queued", result="passed"):
    row = dict(id=7, name=wire.NAME, app={"id": 9}, head_sha=B["checkout"],
               external_id=wire.external_id(B), status=status)
    if status == "completed":
        values = stages()
        if result == "failed":
            values["test-2"]["exit"] = 1
        if result == "unavailable":
            values = {}
        row.update(conclusion={"passed": "success", "failed": "failure", "unavailable": "neutral"}[result],
                   output={"summary": json.dumps(wire.report(B, 7, IMAGE, "d"*64, result, values))})
    return row


class Clock:
    def __init__(self): self.now = 0
    def clock(self): return self.now
    def sleep(self, n): self.now += n


class Box(unittest.TestCase):
    def test_all_terminal_outcomes_through_hosted_reader(self):
        for result in ("passed", "failed", "unavailable"):
            api = Mock();api.checks.return_value = [check("completed", result)]
            self.assertEqual(box.wait(api, B, 9, seconds=0), result)

    def test_duplicate_foreign_stale_and_wrong_binding_never_pass(self):
        good = check("completed")
        bad = []
        for path, value in [("head_sha", "e"*40), ("external_id", "old-attempt"), ("app", {"id": 10})]:
            row = copy.deepcopy(good);row[path] = value;bad.append([row])
        bad.extend(([good, good], []))
        for rows in bad:
            api = Mock();api.checks.return_value = rows
            self.assertEqual(box.wait(api, B, 9, seconds=0), "unavailable")

    def test_observed_failure_vetoes_duplicate_fallback(self):
        api = Mock();api.checks.return_value = [check("completed", "failed"), check()]
        self.assertEqual(box.wait(api, B, 9, seconds=0), "failed")

    def test_missing_counts_and_conclusion_disagreement_cannot_pass(self):
        for change in ("zero", "missing", "conclusion"):
            row = check("completed")
            value = json.loads(row["output"]["summary"])
            if change == "zero":value["stages"]["test-2"]["tests"] = 0
            if change == "missing":del value["stages"]["archive"]
            if change == "conclusion":row["conclusion"] = "failure"
            row["output"]["summary"] = json.dumps(value)
            api = Mock();api.checks.return_value = [row]
            self.assertEqual(box.wait(api, B, 9, seconds=0), "unavailable")

    def test_busy_or_dead_controller_has_bounded_full_hosted_fallback(self):
        for rows in ([], [check("in_progress")]):
            api = Mock();api.checks.return_value = rows
            clock = Clock()
            self.assertEqual(box.route(api, B, 9, seconds=90, clock=clock.clock, sleep=clock.sleep), "hosted")
            self.assertEqual(clock.now, 90)
        api = Mock();api.checks.side_effect = RuntimeError("transport unavailable")
        clock = Clock()
        self.assertEqual(box.wait(api, B, 9, seconds=1500, clock=clock.clock, sleep=clock.sleep), "unavailable")
        self.assertEqual(clock.now, 1500)

    def test_queued_offer_never_supplies_success_without_terminal_result(self):
        api = Mock();api.checks.return_value = [check()]
        self.assertEqual(box.route(api, B, 9, seconds=0), "box")
        self.assertEqual(box.wait(api, B, 9, seconds=0), "unavailable")

    def test_forks_manual_and_disabled_use_hosted_without_query(self):
        env = dict(BOX_CI_ENABLED="true", GITHUB_EVENT_NAME="pull_request", GITHUB_REPOSITORY="StateEngine/StateEngine")
        self.assertTrue(box.eligible(env, {"pull_request": {"head": {"repo": {"full_name": env["GITHUB_REPOSITORY"], "fork": False}}}}))
        self.assertFalse(box.eligible(env, {"pull_request": {"head": {"repo": {"full_name": env["GITHUB_REPOSITORY"], "fork": True}}}}))
        self.assertFalse(box.eligible({**env, "GITHUB_EVENT_NAME": "workflow_dispatch"}, {}))
        self.assertFalse(box.eligible({**env, "BOX_CI_ENABLED": "false"}, {}))
