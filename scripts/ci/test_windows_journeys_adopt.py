"""Verify Windows/Linux native --adopt coverage and macOS gating in journeys."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness_matrix.io import prepare_provider_home, provider_home_environment
from windows_journeys.flow import Journeys


class WindowsJourneysAdoptTests(unittest.TestCase):
    def _runner(self, root, provider):
        home = root / 'home'
        home.mkdir(mode=0o700, parents=True)
        state = home / 'state'
        state.mkdir(mode=0o700)
        environment = provider_home_environment(home)
        prepare_provider_home(environment, home)
        runner = SimpleNamespace(
            home=home,
            state=state,
            settings={'provider': provider},
            commands=SimpleNamespace(environment=environment),
        )
        runner.supports_native_adoption = lambda: Journeys.supports_native_adoption(runner)
        runner.adoption_journal = lambda: Journeys.adoption_journal(runner)
        return runner

    def test_supports_native_adoption_gates_off_macos(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            for provider in ('claude', 'codex'):
                runner = self._runner(root / provider, provider)
                with patch.object(sys, 'platform', 'win32'):
                    self.assertTrue(runner.supports_native_adoption())
                with patch.object(sys, 'platform', 'linux'):
                    self.assertTrue(runner.supports_native_adoption())
                with patch.object(sys, 'platform', 'darwin'):
                    self.assertFalse(runner.supports_native_adoption())

    def test_verify_native_adoption_accepts_codex_and_claude_inside_fixture(self):
        cases = [
            ('codex', 'CODEX_HOME', 'config.toml', 'Codex user-started session hooks', 'unknown', 'codex-adoption.json'),
            ('claude', 'CLAUDE_CONFIG_DIR', 'settings.json', 'Claude Code user-started session hooks', 'witnessed', 'claude-adoption.json'),
        ]
        for provider, env_key, filename, entry, witness_state, journal_name in cases:
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch).resolve()
                runner = self._runner(root, provider)
                settings_file = Path(runner.commands.environment[env_key]) / filename
                settings_file.write_text('# synthetic fixture settings\n', encoding='utf-8')
                (runner.state / journal_name).write_text('{}\n', encoding='utf-8')
                initialized = {
                    'integrations': [{
                        'path': str(settings_file),
                        'entry': entry,
                        'action': 'written',
                        'witness': {'state': witness_state},
                    }]
                }
                summary = Journeys.verify_native_adoption(runner, initialized)
                self.assertEqual(summary['provider'], provider)
                self.assertEqual(summary['journal'], journal_name)
                self.assertEqual(summary['witness_state'], witness_state)
                self.assertTrue(summary['settings_within_fixture'])

    def test_verify_native_adoption_refuses_escaped_settings_or_missing_journal(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            runner = self._runner(root, 'codex')
            outside = root / 'outside-config.toml'
            outside.write_text('# outside fixture\n', encoding='utf-8')
            (runner.state / 'codex-adoption.json').write_text('{}\n', encoding='utf-8')
            escaped = {
                'integrations': [{
                    'path': str(outside),
                    'entry': 'Codex user-started session hooks',
                    'action': 'written',
                    'witness': {'state': 'unknown'},
                }]
            }
            with self.assertRaisesRegex(RuntimeError, 'escaped the private CODEX_HOME fixture'):
                Journeys.verify_native_adoption(runner, escaped)

            inside = Path(runner.commands.environment['CODEX_HOME']) / 'config.toml'
            inside.write_text('# inside fixture\n', encoding='utf-8')
            (runner.state / 'codex-adoption.json').unlink()
            missing_journal = {
                'integrations': [{
                    'path': str(inside),
                    'entry': 'Codex user-started session hooks',
                    'action': 'written',
                    'witness': {'state': 'unknown'},
                }]
            }
            with self.assertRaisesRegex(RuntimeError, 'Adoption journal is absent'):
                Journeys.verify_native_adoption(runner, missing_journal)
