"""Release --version child environment for scripts/release/build.py, without cargo.

The --version witness runs without an ambient search path on every supported build
host while keeping the OS root variables under whatever casing the runner provides
(hosted Windows exposes all-caps names; a lost system root is WinError 10106). These
controls pin the deterministic mappings of the filter, including the lower-case and
mixed-case parent path orderings that must never survive.
"""
import importlib.util
import unittest
from unittest import mock
from pathlib import Path

BUILD = Path(__file__).resolve().parents[2] / "scripts" / "release" / "build.py"

spec = importlib.util.spec_from_file_location("release_build_under_test", BUILD)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def filter_with(environment):
    with mock.patch.object(build.os, "environ", dict(environment)):
        return build.system_root_env()


class ReleaseVersionEnvironment(unittest.TestCase):
    def test_classic_posix_host_keeps_nothing_but_the_empty_path(self):
        result = filter_with({
            "PATH": "/usr/local/bin:/usr/bin",
            "HOME": "/root",
            "TMPDIR": "/tmp/runner",
            "GITHUB_TOKEN": "synthetic-credential",
            "AWS_SECRET_ACCESS_KEY": "synthetic-credential",
        })
        self.assertEqual(result, {"PATH": ""})

    def test_all_caps_windows_host_keeps_its_roots(self):
        result = filter_with({
            "PATH": "C:\\Program Files\\StateEngine",
            "SYSTEMROOT": "C:\\Windows",
            "WINDIR": "C:\\Windows",
            "COMSPEC": "C:\\Windows\\system32\\cmd.exe",
            "TEMP": "C:\\Users\\runner\\AppData\\Local\\Temp",
            "TMP": "C:\\Users\\runner\\AppData\\Local\\Temp",
            "GITHUB_TOKEN": "synthetic-credential",
        })
        self.assertEqual(result, {"PATH": "", "SYSTEMROOT": "C:\\Windows",
                                  "WINDIR": "C:\\Windows",
                                  "TEMP": "C:\\Users\\runner\\AppData\\Local\\Temp",
                                  "TMP": "C:\\Users\\runner\\AppData\\Local\\Temp"})

    def test_lower_case_parent_path_never_survives(self):
        result = filter_with({"path": "/ambient/bin", "SystemRoot": "os-root"})
        self.assertEqual(result, {"PATH": "", "SystemRoot": "os-root"})

    def test_mixed_case_parent_path_first_never_survives(self):
        # The c10def41aa counterexample: the ambient spelling is visited before the
        # empty PATH and must still not reach the child.
        result = filter_with({"Path": "ambient-search", "PATH": "other-search",
                              "SystemRoot": "os-root"})
        self.assertEqual(result, {"PATH": "", "SystemRoot": "os-root"})

    def test_each_root_dedupes_to_its_first_spelling(self):
        result = filter_with({"WINDIR": "C:\\Windows", "windir": "lower-windir",
                              "Path": "ambient", "path": "lower-ambient"})
        self.assertEqual(result, {"PATH": "", "WINDIR": "C:\\Windows"})

    def test_rootless_input_stays_bounded(self):
        self.assertEqual(filter_with({}), {"PATH": ""})


if __name__ == "__main__":
    unittest.main()
