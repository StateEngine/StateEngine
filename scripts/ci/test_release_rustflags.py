"""Release rustflags placement for issue 340, without invoking cargo.

Target-section rustflags in .cargo/config.toml also reach host build scripts
and proc macros when cargo runs without an explicit --target, which corrupts
the Apple no_uuid dylibs on a cold build. The flag therefore lives in
scripts/release/build.py (release builds always pass --target); these controls
pin the placement and the unchanged Apple flag list recorded in seed keys.
"""
import importlib.util
import tomllib
import unittest
from pathlib import Path

BUILD = Path(__file__).resolve().parents[2] / "scripts" / "release" / "build.py"
REPO = BUILD.parents[2]

spec = importlib.util.spec_from_file_location("release_build_under_test", BUILD)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ReleaseRustflags(unittest.TestCase):
    def test_apple_targets_get_no_uuid_without_any_config_section(self):
        for target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
            self.assertEqual(build.release_rustflags(target, {}),
                             ["-C", "link-arg=-Wl,-no_uuid"])

    def test_windows_flags_pass_through_unchanged(self):
        flags = ["-C", "target-feature=+crt-static", "-C", "link-arg=/Brepro"]
        config = {"target": {"x86_64-pc-windows-msvc": {"rustflags": flags}}}
        self.assertEqual(build.release_rustflags("x86_64-pc-windows-msvc", config), flags)

    def test_linux_flags_pass_through_unchanged(self):
        self.assertEqual(build.release_rustflags("x86_64-unknown-linux-gnu", {}), [])

    def test_existing_no_uuid_flag_is_not_doubled(self):
        flags = ["-C", "link-arg=-Wl,-no_uuid"]
        config = {"target": {"aarch64-apple-darwin": {"rustflags": flags}}}
        self.assertEqual(build.release_rustflags("aarch64-apple-darwin", config), flags)

    def test_repository_config_no_longer_carries_apple_rustflags(self):
        config = tomllib.loads((REPO / ".cargo" / "config.toml").read_text())
        self.assertNotIn("aarch64-apple-darwin", config.get("target", {}))
        self.assertNotIn("x86_64-apple-darwin", config.get("target", {}))
        self.assertEqual(build.release_rustflags("aarch64-apple-darwin", config),
                         ["-C", "link-arg=-Wl,-no_uuid"])


if __name__ == "__main__":
    unittest.main()
