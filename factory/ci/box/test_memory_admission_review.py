"""Exercise actual memory admission at the reserved allocation boundary."""
import multiprocessing as mp
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import admission
import engine

GIB = 1024 ** 3


class MemoryAdmissionReview(unittest.TestCase):
    def capacity(self, memory, available):
        def read(path, *args, **kwargs):
            self.assertEqual(path, Path("/proc/meminfo"))
            return "MemTotal: 134217728 kB\nMemAvailable: %d kB\n" % (available // 1024)
        # Admission now charges a reservation beside live peers, which this test
        # exercises in isolation: one private directory per measurement, so each
        # figure below is judged against the margin alone.
        with tempfile.TemporaryDirectory(prefix="memory-admission-") as temporary, \
                patch.object(Path, "read_text", read), \
                patch.object(engine.admission, "folder", return_value=Path(temporary)), \
                patch.object(engine, "command") as command:
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
        # No allocation or engine call: exercise the real OS metadata reader,
        # against a private reservation directory so the charge it files is the
        # only one under test.
        available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                             if line.startswith("MemAvailable:"))) * 1024
        with tempfile.TemporaryDirectory(prefix="memory-admission-") as temporary, \
                patch.object(engine.admission, "folder", return_value=Path(temporary)):
            if available >= 24 * GIB:
                self.assertGreaterEqual(engine.capacity(18 * GIB), 24 * GIB)
            else:
                with self.assertRaises(RuntimeError):
                    engine.capacity(18 * GIB)

    def test_paired_slots_in_separate_processes_share_one_budget(self):
        # The real topology is two runner processes, each holding one container
        # charge. Both attempt admission before either retires it.
        for available, expected in ((38, ["ADMITTED", "ADMITTED"]),
                                    (30, ["ADMITTED", "hosted"]),
                                    (24, ["ADMITTED", "hosted"]),
                                    (17, ["hosted", "hosted"])):
            with self.subTest(available=available), \
                    tempfile.TemporaryDirectory(prefix="memory-admission-") as temporary:
                directory = Path(temporary) / "ledger"
                directory.mkdir(mode=0o700)
                context = mp.get_context("fork")
                barrier, results = context.Barrier(2), context.Queue()
                slots = [context.Process(target=_slot, args=(str(directory), available, barrier, results))
                         for _ in range(2)]
                for slot in slots:
                    slot.start()
                for slot in slots:
                    slot.join(10)
                    self.assertEqual(slot.exitcode, 0)
                self.assertEqual(sorted(results.get() for _ in slots), expected)
                self.assertEqual(admission.records(directory), [])


def _slot(folder, available, barrier, results):
    """One paired runner process holding one 16 GiB container charge."""
    engine.admission.folder = lambda: Path(folder)
    engine.available = lambda: available * GIB
    name = "se-ci-" + str(os.getpid()).rjust(32, "0")
    try:
        engine.capacity(16 * GIB, name)
        results.put("ADMITTED")
    except RuntimeError:
        results.put("hosted")
        name = None
    barrier.wait(timeout=5)
    admission.retire(name)


if __name__ == "__main__":
    unittest.main()
