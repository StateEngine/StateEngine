import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'crates/se/tests/judges')]
from provider_home import KEYS, isolate, verify


class ProviderHomeTests(unittest.TestCase):
    def test_missing_or_external_settings_are_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            fixture = Path(scratch) / 'fixture'
            fixture.mkdir()
            environment = {}
            isolate(environment, fixture, fixture)
            for key in KEYS:
                for bad in (None, str(Path(scratch) / 'outside')):
                    with self.subTest(key=key, bad=bad):
                        invalid = dict(environment)
                        if bad is None:
                            invalid.pop(key)
                        else:
                            invalid[key] = bad
                        with self.assertRaises(RuntimeError):
                            verify(invalid, fixture)

    @unittest.skipIf(os.name == 'nt', 'Directory symlinks may require administrator rights')
    def test_resolved_config_directory_must_remain_in_the_fixture(self):
        with tempfile.TemporaryDirectory() as scratch:
            fixture = Path(scratch) / 'fixture'
            fixture.mkdir()
            environment = {}
            isolate(environment, fixture, fixture)
            (fixture / 'linked').symlink_to(Path(scratch), target_is_directory=True)
            environment['CODEX_HOME'] = str(fixture / 'linked' / 'codex')
            with self.assertRaises(RuntimeError):
                verify(environment, fixture)

            codex = fixture / 'codex'
            codex.mkdir()
            (codex / 'config.toml').symlink_to(Path(scratch) / 'config.toml')
            environment['CODEX_HOME'] = str(codex)
            with self.assertRaises(RuntimeError):
                verify(environment, fixture)
