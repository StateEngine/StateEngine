"""Fuzz and leak probes for the box failure summary, beyond the author's tests."""
import json
import unittest

import box_result as wire
from test_box import B, IMAGE, stages

BS = chr(92)


def publish(failed):
    values = stages()
    values["test-1"]["exit"] = values["test-2"]["exit"] = 1
    return wire.report(B, 7, IMAGE, "d"*64, "failed", values, failed)


class Fuzz(unittest.TestCase):
    def test_report_never_raises_and_stays_bounded(self):
        cases = [
            ["x" * 10**6] * 100,
            ["\u00e9" * 500] * 100,
            [b"\xff\xfe" * 100, None, 5, "a\nb", "\ud800" * 10] * 30,
            [str(n) for n in range(100)] + [str(n) for n in range(100)],
            ["(further failures omitted)"] + ["a"] * 30,
        ]
        for failed in cases:
            found = publish(failed).get("failures", [])
            self.assertLessEqual(len(found), wire.FAIL_TESTS)
            self.assertLessEqual(len(json.dumps(found).encode()), wire.FAIL_BYTES)
            self.assertTrue(all("\n" not in item for item in found))

    def test_every_published_character_survives_the_wire(self):
        found = publish(["\ud800" * 50, "ok"])["failures"]
        json.dumps(found).encode("utf-8")


class Scrub(unittest.TestCase):
    def test_home_and_mount_paths_are_not_published(self):
        windows = "C:" + BS + "Users" + BS + "someone" + BS + "x.rs"
        for private in ["/home/someone/src/x.rs", "/mnt/disk/work/x", "/var/lib/svc/state",
                        "/Users/someone/p", windows]:
            found = publish(["se::a t at x.rs:1:1: open " + private + " failed"])["failures"][0]
            self.assertNotIn("someone", found)
            self.assertNotIn("/mnt/disk", found)
            self.assertNotIn("/var/lib", found)
