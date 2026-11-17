"""A witnessed empty stop closure is closed; anything unproven is not.

The public stop contract reports two distinct closed states for an agent:
an enumeration that ran and found nothing (`complete`), and a witnessed empty
closure when the agent never had a managed lifecycle (`already-stopped`,
`population: empty`, `enumeration: not-applicable`, witness method
`not-applicable`). The harness used to accept only the first, so a legitimate empty
agent failed cleanup. These cases pin both, and pin that absent, unreadable and
incomplete custody still fail.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness_matrix.flow import stop_closed  # noqa: E402

WITNESSED_EMPTY = {
    "result": "already-stopped",
    "population": "empty",
    "remaining": [],
    "enumeration": "not-applicable",
    "witness": {
        "state": "witnessed",
        "method": "not-applicable",
        "detail": "The complete admitted control snapshot contains no recorded managed lifecycle or live session.",
    },
}
ENUMERATED_CLOSED = {
    "result": "stopped",
    "population": "exited",
    "remaining": [],
    "enumeration": "complete",
    "witness": {"state": "witnessed", "method": "stop", "detail": "two processes stopped"},
}


class StopClosure(unittest.TestCase):
    def test_enumerated_closure_is_closed(self):
        self.assertTrue(stop_closed(ENUMERATED_CLOSED))

    def test_witnessed_empty_closure_is_closed(self):
        self.assertTrue(stop_closed(WITNESSED_EMPTY))

    def test_remaining_processes_are_not_closed(self):
        for remaining in (["pid 1"], None):
            with self.subTest(remaining=remaining):
                self.assertFalse(stop_closed({**WITNESSED_EMPTY, "remaining": remaining}))

    def test_unwitnessed_empty_is_not_closed(self):
        for state, method in (("unwitnessed", "not-applicable"),
                              ("witnessed", "enumeration"),
                              ("absent", "not-applicable")):
            with self.subTest(state=state, method=method):
                row = {**WITNESSED_EMPTY,
                       "witness": {**WITNESSED_EMPTY["witness"], "state": state, "method": method}}
                self.assertFalse(stop_closed(row))

    def test_missing_detail_is_not_closed(self):
        for detail in (None, "", "   "):
            with self.subTest(detail=detail):
                row = {**WITNESSED_EMPTY,
                       "witness": {**WITNESSED_EMPTY["witness"], "detail": detail}}
                self.assertFalse(stop_closed(row))

    def test_partial_empty_contract_is_not_closed(self):
        # Every field of the empty contract must agree; a half-reported closure is
        # an incomplete fact, not a measured empty one.
        for key, value in (("result", "stopped"),
                           ("population", "unknown"),
                           ("enumeration", "unreadable"),
                           ("enumeration", "absent")):
            with self.subTest(key=key, value=value):
                self.assertFalse(stop_closed({**WITNESSED_EMPTY, key: value}))


if __name__ == "__main__":
    unittest.main()
