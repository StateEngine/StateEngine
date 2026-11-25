import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'crates/se/tests/judges')]
from provider_home import KEYS, isolate, provider_home_environment, run_provider_command, verify


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
                            run_provider_command(self.fail, ["never spawn"], invalid, fixture)

    def test_default_provider_directories_refuse_without_overrides(self):
        with tempfile.TemporaryDirectory() as scratch:
            profile = Path(scratch) / 'profile'
            with patch.dict(os.environ, {'HOME': str(profile), 'USERPROFILE': str(profile)}, clear=True):
                for name in ('.codex', '.claude', 'AppData/Local', 'AppData/Roaming'):
                    fixture = profile / name
                    fixture.mkdir(parents=True)
                    environment = provider_home_environment(fixture)
                    with self.subTest(name=name), self.assertRaises(RuntimeError):
                        run_provider_command(self.fail, ['never spawn'], environment, fixture)

    def test_native_launcher_confines_child_and_preserves_exit_code(self):
        launcher = ROOT / 'crates/se/tests/judges/provider_home.py'
        with tempfile.TemporaryDirectory() as scratch:
            fixture = Path(scratch) / 'fixture'
            fixture.mkdir()
            words = [sys.executable, '-c', 'import json,os,sys; '
                     f'print(json.dumps({{key: os.environ[key] for key in {KEYS!r}}})); sys.exit(23)']
            command = [sys.executable, '-B', launcher, '--fixture', fixture, '--home']
            output = subprocess.run([*command, fixture / 'user', '--', *words],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(output.returncode, 23, output.stderr)
            for key, directory in json.loads(output.stdout).items():
                with self.subTest(key=key):
                    self.assertTrue(Path(directory).resolve().is_relative_to(fixture.resolve()))
                    self.assertTrue(Path(directory).is_dir())
            refused = subprocess.run([*command, Path(scratch) / 'outside', '--', *words],
                                     capture_output=True, text=True, timeout=10)
            self.assertNotEqual(refused.returncode, 23)
            self.assertEqual(refused.stdout, '')
            self.assertFalse((Path(scratch) / 'outside').exists())

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
