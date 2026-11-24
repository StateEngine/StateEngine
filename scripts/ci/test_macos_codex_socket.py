"""The macOS journey keeps the Codex control socket inside the local socket limit."""
import os
from pathlib import Path
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'journeys' / 'hosted_macos'), str(ROOT / 'scripts')]
import providers
from harness_matrix.io import provider_home_environment


class MacosCodexSocketPath(unittest.TestCase):
    def test_generated_socket_path_stays_short_with_a_long_runner_temp(self):
        # A runner temporary directory 80+ characters deep: the fixture home
        # must not grow with it.
        runner_temp = '/' + 'a' * 80 + '/work'
        fixture_home = providers.private_fixture_home()
        try:
            codex_home = provider_home_environment(fixture_home)['CODEX_HOME']
            control = os.fspath(providers.codex_control_socket(codex_home))
            layout = control[control.index(fixture_home.parent.name):]
            self.assertNotIn(runner_temp, control)
            for prefix in ('/tmp', '/private/tmp'):
                # On macOS the temporary root resolves to the second form.
                with self.subTest(prefix=prefix):
                    self.assertLessEqual(len(os.fsencode(prefix + layout)),
                                         providers.SOCKET_PATH_LIMIT - 20)
        finally:
            shutil.rmtree(fixture_home.parent, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
