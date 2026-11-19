"""Exercise Windows profile custody through a disposable managed launch."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from secode_host_guards import Fixture
from diagnostic_redaction_review import state_home


class WindowsFixture(Fixture):
    def ok(self, *args):
        if args != ('up',):
            return super().ok(*args)
        command = [str(self.se), '--json', '--home', str(self.home), 'up', '--foreground']
        with (self.root / 'host.stdout').open('wb') as out, (self.root / 'host.stderr').open('wb') as err:
            self.host = subprocess.Popen(command, cwd=self.repo, env=self.env, stdin=subprocess.DEVNULL,
                                         stdout=out, stderr=err)
        deadline = time.monotonic() + 60
        while not read_json(self.home / 'endpoint.json'):
            assert self.host.poll() is None, 'foreground host exited before readiness'
            assert time.monotonic() < deadline, 'foreground host readiness timed out'
            time.sleep(.05)
        return {}

    def close(self):
        super().close()
        assert self.host.wait(timeout=30) == 0, 'foreground host did not exit cleanly'

    def call(self, *args):
        self.calls += 1
        command = [str(self.se), '--json', '--home', str(self.home), *args]
        base = self.root / f'call-{self.calls:02}'
        with base.with_suffix('.stdout').open('wb') as out, base.with_suffix('.stderr').open('wb') as err:
            result = subprocess.run(command, cwd=self.repo, env=self.env, stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=err, timeout=90)
        base.with_suffix('.exit').write_text(str(result.returncode))
        return subprocess.CompletedProcess(command, result.returncode,
                                           base.with_suffix('.stdout').read_bytes(),
                                           base.with_suffix('.stderr').read_bytes())


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, PermissionError, json.JSONDecodeError):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--capabilities', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    images = args.root / 'images'
    images.mkdir()
    cli = images / 'secode.exe'
    server = images / 'secode-server.exe'
    subprocess.run(['rustc', '--edition=2024', str(args.source), '-o', str(cli)],
                   stdin=subprocess.DEVNULL, check=True, timeout=120)
    shutil.copy2(cli, server)
    capabilities = json.loads(args.capabilities.read_text())
    capabilities['service']['shutdown'] = ['Ctrl+C']
    (images / 'capabilities.json').write_text(json.dumps(capabilities))
    f = WindowsFixture(args.se, args.root / 'case', cli, 'read-only', 'never', home_factory=state_home)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            task = pool.submit(f.call, '--key', str(uuid.uuid4()), '--project', f.project,
                               'launch', f.agent, '--task', 'Synthetic input.', '--detach')
            until = time.monotonic() + 60
            bootstrap_released = False
            service_released = False
            try:
                while not task.done():
                    for path in (f.home / 'secode').glob('*.json'):
                        journal = read_json(path)
                        if not journal:
                            continue
                        bootstrap = journal.get('bootstrap')
                        if not bootstrap_released and (images / 'bootstrap-pid').exists() and bootstrap:
                            checkpoint = bootstrap.get('checkpoint') or {}
                            if checkpoint.get('kind') == 'process':
                                assert checkpoint['value']['root']['pid'] == int((images / 'bootstrap-pid').read_text())
                                (images / 'bootstrap-release').touch()
                                bootstrap_released = True
                        service = journal.get('service')
                        if (not service_released and (images / 'service-attempted').exists()
                                and service and (service.get('checkpoint') or {}).get('kind') == 'process'):
                            assert isinstance(journal.get('profile_identity'), list) and len(journal['profile_identity']) == 24
                            assert (images / 'rename-denied').read_bytes() == b'yes'
                            profile = next((f.home / 'secode-profiles').glob('*/profile'))
                            assert (profile / 'host-policy.json').is_file()
                            (images / 'service-release').touch()
                            service_released = True
                    assert time.monotonic() < until, 'native profile qualification timed out'
                    time.sleep(.02)
                result = task.result()
                assert result.returncode != 0, 'fixture service was expected to refuse'
                assert bootstrap_released and service_released, (result.stdout, result.stderr)
            finally:
                (images / 'bootstrap-release').touch()
                (images / 'service-release').touch()
    finally:
        f.close()


if __name__ == '__main__':
    main()
