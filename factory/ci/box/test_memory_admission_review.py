"""Exercise actual memory admission at the reserved allocation boundary."""
from pathlib import Path
import unittest
from unittest.mock import patch

import engine

GIB = 1024 ** 3


class MemoryAdmissionReview(unittest.TestCase):
    def capacity(self, memory, available):
        def read(path, *args, **kwargs):
            self.assertEqual(path, Path("/proc/meminfo"))
            return "MemTotal: 134217728 kB\nMemAvailable: %d kB\n" % (available // 1024)
        with patch.object(Path, "read_text", read), patch.object(engine, "command") as command:
            result = engine.capacity(memory)
            command.assert_not_called()
            return result

    def test_full_workload_starts_at_exactly_twenty_four_gib(self):
        self.assertEqual(self.capacity(18 * GIB, 24 * GIB), 24 * GIB)

    def test_one_kib_below_margin_refuses_before_allocating(self):
        with self.assertRaisesRegex(RuntimeError, "preserve 6 GiB"):
            self.capacity(18 * GIB, 24 * GIB - 1024)

    def test_smaller_allocations_keep_the_same_six_gib_margin(self):
        for memory in [GIB, 8 * GIB]:
            with self.subTest(memory=memory):
                self.assertEqual(self.capacity(memory, memory + 6 * GIB), memory + 6 * GIB)
                with self.assertRaises(RuntimeError):
                    self.capacity(memory, memory + 6 * GIB - 1024)

    def test_invalid_allocations_never_borrow_the_reserved_margin(self):
        for memory in [0, -1, 18 * GIB + 1, 24 * GIB]:
            with self.subTest(memory=memory), self.assertRaises(RuntimeError):
                self.capacity(memory, 128 * GIB)

    def test_missing_or_unreadable_memory_is_never_admission(self):
        for text in ["MemTotal: 134217728 kB\n", "MemAvailable: unknown kB\n"]:
            with self.subTest(text=text), patch.object(Path, "read_text", return_value=text):
                with self.assertRaises((StopIteration, ValueError)):
                    engine.capacity(18 * GIB)
        with patch.object(Path, "read_text", side_effect=PermissionError("unreadable memory")):
            with self.assertRaises(PermissionError):
                engine.capacity(18 * GIB)

    def test_actual_native_memory_read_has_the_same_admission_boundary(self):
        # No allocation or engine call: exercise the real OS metadata reader.
        available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                             if line.startswith("MemAvailable:"))) * 1024
        if available >= 24 * GIB:
            self.assertGreaterEqual(engine.capacity(18 * GIB), 24 * GIB)
        else:
            with self.assertRaises(RuntimeError):
                engine.capacity(18 * GIB)


if __name__ == "__main__":
    unittest.main()
