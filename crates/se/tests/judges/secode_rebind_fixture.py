"""Launch a native contract fixture, restart it, and reconcile uncertain mail."""
import argparse
import base64
import json
import shutil
import sys
import time
from pathlib import Path
from urllib import request

from secode_host_guards import Fixture
from secode_headless_policy import launch

AUTH = 'Basic ' + base64.b64encode(b'fixture:synthetic-secret').decode('ascii')


def post(endpoint, path, body):
    data = json.dumps(body).encode()
    req = request.Request(endpoint.rstrip('/') + path, data=data,
                          headers={'Authorization': AUTH, 'Content-Type': 'application/json'},
                          method='POST')
    with request.urlopen(req, timeout=10) as response:
        return json.load(response)


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def wait_value(label, fn, timeout=60):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        value = fn()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError('timed out waiting for ' + label)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    images = args.root / 'images'
    images.mkdir()
    cli = images / 'secode'
    server = images / 'secode-server'
    shutil.copy2(args.fixture, cli)
    shutil.copy2(args.fixture, server)
    cli.chmod(0o700)
    server.chmod(0o700)
    f = Fixture(args.se, args.root / 'case', cli, 'read-only', 'never')
    old_endpoint = new_endpoint = None
    try:
        launched = launch(f, images)
        assert launched.returncode == 0, (launched.stdout, launched.stderr)
        profile = wait_value('private profile', lambda: next(iter((f.home / 'secode-profiles').glob('*/profile')), None))
        old = wait_value('service registration', lambda: read_json(profile / 'fixture-registration.json'))
        old_endpoint = old['endpoint']
        old_pid = old['pid']
        assert post(old_endpoint, '/fixture/uncertain', {})['armed']
        f.ok('--project', f.project, 'msg', 'send', f.agent, 'Synthetic unresolved mail.')
        state_path = profile / 'fixture-state.json'
        initial = wait_value('uncertain notice', lambda: (state if (state := read_json(state_path)) and state.get('notices') else None))
        old_notice = initial['notices'][0]
        coords = {'home': str(f.home), 'project_id': f.project, 'agent_id': f.agent}
        assert post(old_endpoint, '/fixture/restart', coords)['started']
        replacement = wait_value('replacement process', lambda: read_json(profile / 'fixture-replacement.json'))
        new_endpoint = replacement['endpoint']
        assert replacement['pid'] != old_pid
        wait_value('rebind response and 409 window', lambda: (state if (state := read_json(state_path)) and state.get('rebound') and state.get('not_ready_count', 0) > 0 else None))
        still = read_json(state_path)
        assert len(still['notices']) == 1, 'mail was offered before the challenge became ready'
        assert post(new_endpoint, '/fixture/ready', {})['ready']
        final = wait_value('fresh notice', lambda: (state if (state := read_json(state_path)) and len(state.get('notices', [])) >= 2 else None))
        new_notice = final['notices'][1]
        assert new_notice['id'] != old_notice['id'], 'uncertain notice was replayed'
        assert new_notice['metadata']['messages'] == old_notice['metadata']['messages']
        f.close()
        assert read_json(state_path)['released'] is True
    finally:
        # The fixture owns itself and exits cooperatively; never signal by name.
        for endpoint in (new_endpoint, old_endpoint):
            if endpoint:
                try:
                    post(endpoint, '/fixture/exit', {})
                except Exception:
                    pass


if __name__ == '__main__':
    main()
