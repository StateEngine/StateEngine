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

    def test_failing_test_names_reach_the_reader_summary(self):
        # The exact shape nextest prints, including a progress repaint between
        # the FAIL line and the panic line, which adjacency pairing got wrong.
        log = "\n".join([
            "        FAIL [   0.013s] (2/2) se-types::probe probe_one",
            "  stdout \u2500\u2500\u2500",
            "    test probe_one ... FAILED",
            "  stderr \u2500\u2500\u2500",
            "    thread 'probe_one' (1917046) panicked at crates/x/tests/p.rs:3:5:",
            "    assertion `left == right` failed: first",
            "      left: 1",
            "     right: 2",
            "        FAIL [   0.011s] (1/2) se-types::probe probe_two",
            "    thread 'probe_two' (1917045) panicked at crates/x/tests/p.rs:7:5:",
            "    second",
            "     Summary [   0.014s] 2 tests run: 0 passed, 2 failed, 0 skipped",
        ])
        found = wire.details(log)
        self.assertEqual(found, [
            "se-types::probe probe_one at crates/x/tests/p.rs:3:5: "
            "assertion `left == right` failed: first",
            "se-types::probe probe_two at crates/x/tests/p.rs:7:5: second",
        ])
        values = stages()
        values["test-1"]["exit"] = 1
        report = wire.report(B, 7, IMAGE, "d"*64, "failed", values, found)
        row = check("completed", "failed")
        row["output"]["summary"] = wire.text(report)
        summary = row["output"]["summary"]
        self.assertTrue(summary.startswith("{"))
        self.assertIn("Failing tests:", summary)
        self.assertIn("se-types::probe probe_one at crates/x/tests/p.rs:3:5", summary)
        api = Mock(); api.checks.return_value = [row]
        self.assertEqual(box.wait(api, B, 9, seconds=0), "failed")

    def test_a_stage_that_fails_without_naming_a_test_says_so(self):
        # A kill, a full disk or a custom harness exits non-zero with no FAIL
        # line. Silence would read as clean, so the stage names itself.
        self.assertEqual(wire.details("error: linking with `cc` failed\n"), [])
        line = "test-1: failed; no test named"
        values = stages()
        values["test-1"]["exit"] = 1
        report = wire.report(B, 7, IMAGE, "d"*64, "failed", values, [line])
        summary = wire.text(report)
        self.assertIn(line, summary)
        api = Mock(); api.checks.return_value = [dict(
            check("completed", "failed"), output={"summary": summary})]
        self.assertEqual(box.wait(api, B, 9, seconds=0), "failed")

    def test_failure_detail_is_bounded_and_says_when_it_stops(self):
        many = "\n".join(f"        FAIL [   0.0s] (1/1) se-x::t test_{n:02d}" for n in range(60))
        found = wire.details(many)
        self.assertEqual(len(found), wire.FAIL_TESTS)
        self.assertEqual(found[-1], "(further failures omitted)")
        self.assertLessEqual(len(json.dumps(found).encode()), wire.FAIL_BYTES)
        # A message cut at its own bound plus name and location must still pass.
        long = ("        FAIL [   0.0s] (1/1) se-x::t t\n"
                "    thread 't' (1) panicked at a.rs:1:1:\n" + "x" * 5000)
        item = wire.details(long)[0]
        self.assertLessEqual(len(item.encode()), wire.LOCATE_BYTES)
        failed = dict(stages(), **{"test-1": dict(exit=1, tests=1, custom=9, docs=0, checks=0)})
        report = wire.report(B, 7, IMAGE, "d"*64, "failed", failed, wire.details(long))
        self.assertEqual(len(report["failures"]), 1)
        # report() bounds what it is given, so an over-long or over-count list
        # can never raise here and lose the outcome.
        self.assertEqual(len(wire.report(
            B, 7, IMAGE, "d"*64, "failed", failed, ["y"] * 60)["failures"]), wire.FAIL_TESTS)
        self.assertEqual(len(wire.report(
            B, 7, IMAGE, "d"*64, "failed", failed, ["x" * 5000])["failures"][0].encode()),
            wire.LOCATE_BYTES)
        # A newline would break the one-line-per-failure shape.
        self.assertTrue(all("\n" not in i for i in wire.report(
            B, 7, IMAGE, "d"*64, "failed", failed, ["two\nlines"])["failures"]))
