"""Private journey credential cleanup follows ownership, even when setup fails."""

import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness_matrix.io import prepare_provider_home, provider_home_environment
from windows_journeys.credentials import Credentials, provision
from windows_journeys.flow import JOURNEYS, Journeys


class NativeJourneyCredentials(unittest.TestCase):
    def setUp(self):
        scratch = self.enterContext(tempfile.TemporaryDirectory())
        root = Path(scratch).resolve()
        self.home = root / 'home'
        self.home.mkdir(mode=0o700)
        self.environment = provider_home_environment(self.home)
        prepare_provider_home(self.environment, self.home)
        seed = provision('codex', {'credential': {'auth_mode': 'apikey',
                                                  'OPENAI_API_KEY': 'synthetic-journey-test-key'}}, root / 'seed')
        self.credentials = Credentials(seed, 'codex')
        self.copy = Path(self.environment['CODEX_HOME']) / 'auth.json'

    def test_existing_auth_file_is_preserved_when_exclusive_create_fails(self):
        original = b'existing synthetic fixture file\n'
        fd = os.open(self.copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(original)
        with self.assertRaises(FileExistsError):
            self.credentials.install(self.home, self.environment)
        self.credentials.close()
        self.assertTrue(self.copy.is_file())
        self.assertEqual(self.copy.read_bytes(), original)

    def test_missing_seed_does_not_keep_the_owned_auth_copy(self):
        self.credentials.install(self.home, self.environment)
        self.credentials.path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.credentials.close()
        self.assertFalse(self.copy.exists())

    @unittest.skipUnless(os.name == 'posix', 'File modes are observed on Unix')
    def test_invalid_copy_mode_refuses_before_writing_and_still_closes(self):
        previous = os.umask(0o400)
        try:
            with self.assertRaisesRegex(RuntimeError, 'Credential file must be owner-only'):
                self.credentials.install(self.home, self.environment)
        finally:
            os.umask(previous)
        size = self.copy.stat().st_size
        self.credentials.close()
        self.assertEqual(size, 0)
        self.assertFalse(self.copy.exists())

    def test_cleanup_refuses_a_replacement_at_the_owned_path(self):
        self.credentials.install(self.home, self.environment)
        replacement = self.copy.with_name('replacement.json')
        original = b'replacement synthetic fixture file\n'
        fd = os.open(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(original)
        replacement.replace(self.copy)
        with self.assertRaisesRegex(RuntimeError, 'Private credential copy identity changed'):
            self.credentials.close()
        self.assertEqual(self.copy.read_bytes(), original)

    def test_pre_init_failure_closes_the_owned_copy_without_a_process_census(self):
        def fail_before_init():
            self.credentials.install(self.home, self.environment)
            raise RuntimeError('fixture failed before init')

        def fail_census(*, retain_home):
            self.assertTrue(retain_home)
            raise RuntimeError('fixture census unavailable')

        environment = {**self.environment, 'ANTHROPIC_API_KEY': 'synthetic-journey-test-key'}
        runner = SimpleNamespace(
            phase=lambda _name, operation: operation(), install=lambda: None,
            adopt_and_work=fail_before_init, come_back=self.fail, handoff=self.fail, remove=self.fail,
            cleanup=fail_census, diagnostics=lambda: None, save=lambda: None,
            initialization_attempted=False, removed=False, foreground=None,
            commands=SimpleNamespace(environment=environment), credentials=self.credentials,
            record={'phases': {name: {'result': 'NOT RUN'} for name in JOURNEYS}},
        )
        receipt = Journeys.run(runner)
        self.assertEqual(receipt['result'], 'FAIL')
        self.assertEqual(receipt['cleanup_error'], 'fixture census unavailable')
        self.assertEqual(receipt['failure'], 'fixture failed before init')
        self.assertFalse(self.copy.exists())
        self.assertTrue(receipt['credential_closure']['private_copy_absent'])
        self.assertNotIn('ANTHROPIC_API_KEY', environment)
