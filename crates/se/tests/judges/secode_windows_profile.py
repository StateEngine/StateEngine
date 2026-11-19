"""Judge native Windows profile admission with an inert initializer."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from diagnostic_redaction_review import state_home
from secode_external import capabilities
from secode_headless_policy import probe_calls
from secode_host_guards import native_probe


def profile_path(home, project, agent):
    # The generated slot is deterministic before the first published journal.
    digest = hashlib.sha256()
    for part in (project, agent):
        raw = part.encode('ascii')
        digest.update(len(raw).to_bytes(8, 'little'))
        digest.update(raw)
    return home / 'secode-profiles' / digest.hexdigest() / 'profile'


def private_environment(root):
    keys = ('PATH', 'SystemRoot', 'WINDIR', 'COMSPEC', 'SYSTEMDRIVE', 'PATHEXT')
    result = {key: os.environ[key] for key in keys if key in os.environ}
    for key in ('HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP'):
        path = root / key.lower()
        path.mkdir()
        result[key] = str(path)
    return result


class Fixture:
    def __init__(self, se, root, native):
        state_home(root)
        self.root, self.home, self.repo = root, root / 'state', root / 'repo'
        self.env = private_environment(root)
        state_home(self.home)
        self.repo.mkdir()
        self.argv = [str(se), '--json', '--home', str(self.home)]
        self.calls = 0
        self.host = None
        self.probe = root / 'probe'
        provider = native_probe(self.probe, native, policy={'capabilities': {}, 'readback': '{}'})
        (self.probe / 'bootstrap-refuse').touch()
        (self.probe / 'bootstrap-gate').touch()
        config = self.home / 'config.toml'
        config.write_text('version = 1\n[providers.secode]\ncommand = ' +
                          json.dumps(str(provider)) +
                          '\n[profiles.default]\nsandbox = "read-only"\napproval = "never"\n',
                          encoding='utf-8')
        init = self.ok('--key', str(uuid.uuid4()), 'init', '--repo', str(self.repo),
                       '--name', 'Private profile fixture', '--agent', 'Fixture',
                       '--provider', 'secode', '--model', 'fixture/model')
        self.project, self.agent = init['project']['id'], init['agent']['id']
        self.profile = profile_path(self.home, self.project, self.agent)
        text = config.read_text(encoding='utf-8')
        setting = f"listen_port = {init['profile']['native_server_port']}"
        assert text.count(setting) == 1, text
        config.write_text(text.replace(setting, '', 1), encoding='utf-8')

    def call(self, *args):
        self.calls += 1
        result = subprocess.run([*self.argv, *args], cwd=self.repo, env=self.env,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=35)
        base = self.root / f'call-{self.calls:02}'
        base.with_suffix('.stdout').write_bytes(result.stdout)
        base.with_suffix('.stderr').write_bytes(result.stderr)
        return result

    def ok(self, *args):
        result = self.call(*args)
        assert result.returncode == 0, (args, result.returncode, result.stdout, result.stderr)
        return json.loads(result.stdout)

    def start(self):
        with (self.root / 'host.stdout').open('wb') as out, (self.root / 'host.stderr').open('wb') as err:
            self.host = subprocess.Popen([*self.argv, 'up', '--foreground'],
                                         cwd=self.repo, env=self.env, stdin=subprocess.DEVNULL,
                                         stdout=out, stderr=err)
        end = time.monotonic() + 25
        while not (self.home / 'endpoint.json').is_file():
            assert self.host.poll() is None and time.monotonic() < end, 'foreground host did not start'
            time.sleep(.025)

    def close(self):
        if self.host is None:
            return
        try:
            if (self.home / 'endpoint.json').is_file():
                result = self.ok('down')
                assert result['complete'] and result['witness']['state'] == 'witnessed', result
            assert self.host.wait(timeout=15) == 0, 'foreground host failed to close'
            assert not (self.home / 'endpoint.json').exists()
        finally:
            if self.host.poll() is None:
                # A failed fixture still owns the original foreground child handle.
                self.host.terminate()
                self.host.wait(timeout=15)

    def launch(self):
        # The inert initializer waits only until the host records its owned process.
        release = self.probe / 'bootstrap-release'
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.call, '--key', str(uuid.uuid4()), '--project', self.project,
                                  'launch', self.agent, '--task', 'Inert profile admission fixture.',
                                  '--detach')
            end = time.monotonic() + 15
            try:
                while not pending.done() and not release.exists():
                    marker = self.probe / 'bootstrap-pid'
                    if marker.is_file():
                        pid = int(marker.read_text())
                        for path in (self.home / 'secode').glob('*.json'):
                            row = json.loads(path.read_text(encoding='utf-8')).get('bootstrap')
                            checkpoint = row['checkpoint'] if row else None
                            if checkpoint and checkpoint['kind'] == 'process':
                                assert checkpoint['value']['root']['pid'] == pid, checkpoint
                                release.touch()
                    assert time.monotonic() < end, 'launch never resolved bootstrap admission'
                    time.sleep(.025)
                return pending.result()
            finally:
                release.touch()


def case(se, root, native, existing):
    fixture = Fixture(se, root, native)
    keep = fixture.profile / 'retained.txt'
    retained = b'Existing synthetic user data.\n'
    try:
        fixture.start()
        # Plant the ordinary child after host startup to reach the launch guard.
        state_home(fixture.profile.parents[1])
        state_home(fixture.profile.parent, owner_only=True)
        if existing:
            state_home(fixture.profile, owner_only=True)
            keep.write_bytes(retained)
            prior = fixture.profile.lstat()
        result = fixture.launch()
    finally:
        fixture.close()

    calls = [row for row in probe_calls(fixture.probe)
             if row.startswith(('init-profile ', 'serve-service ', 'run '))]
    assert result.returncode != 0, (result.stdout, result.stderr)
    if not existing:
        assert len(calls) == 1 and calls[0].startswith('init-profile '), (calls, result.stdout, result.stderr)
        print('Fresh profile control reached the inert initializer once')
        return

    current = fixture.profile.lstat()
    assert (prior.st_dev, prior.st_ino) == (current.st_dev, current.st_ino)
    assert list(fixture.profile.iterdir()) == [keep] and keep.read_bytes() == retained
    assert not calls, ('existing child reached a provider effect', calls)
    detail = (result.stdout + result.stderr).decode('utf-8', 'replace').casefold()
    while '\\\\' in detail:
        detail = detail.replace('\\\\', '\\')
    assert str(fixture.profile).casefold() in detail, detail
    assert any(word in detail for word in ('already exist', 'already present', 'occupied')), detail
    assert any(word in detail for word in ('move', 'rename', 'choose', 'use a fresh', 'use a different')), detail
    print('Existing private profile was preserved and refused before any initializer or credential write')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != 'win32':
        parser.error('this judge requires native Windows')
    native = json.loads(Path(__file__).with_name('secode_headless_capabilities.json').read_text(encoding='utf-8'))
    native['service']['shutdown'] = ['Ctrl+C']
    capabilities(native)
    args.output = args.output.resolve()
    state_home(args.output)
    case(args.se.resolve(strict=True), args.output / 'fresh', native, False)
    case(args.se.resolve(strict=True), args.output / 'existing', native, True)


if __name__ == '__main__':
    main()
