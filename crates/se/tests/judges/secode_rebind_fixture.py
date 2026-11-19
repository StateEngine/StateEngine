"""Launch a native contract fixture, restart it, and reconcile uncertain mail."""
import argparse
import base64
import json
import shutil
import subprocess
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


def initialize_with_original_pair(policy):
    mcp = policy['mcp']['stateengine']
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                       'params': {'protocolVersion': '2025-03-26', 'capabilities': {},
                                  'clientInfo': {'name': 'fixture', 'version': '1'}}}).encode()
    req = request.Request(mcp['url'], data=body,
                          headers={**mcp['headers'], 'Content-Type': 'application/json'},
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
    old_pid = new_pid = None
    replacement_process = None
    closed = False
    try:
        launched = launch(f, images)
        assert launched.returncode == 0, (launched.stdout, launched.stderr)
        profile = wait_value('private profile', lambda: next(iter((f.home / 'secode-profiles').glob('*/profile')), None))
        old = wait_value('service registration', lambda: read_json(profile / 'fixture-registration.json'))
        policy = read_json(profile / 'host-policy.json')
        assert 'result' in initialize_with_original_pair(policy), 'original pair never worked'
        old_endpoint = old['endpoint']
        old_pid = old['pid']
        assert post(old_endpoint, '/fixture/uncertain', {})['armed']
        f.ok('--project', f.project, 'msg', 'send', f.agent, 'Synthetic unresolved mail.')
        state_path = profile / 'fixture-state.json'
        initial = wait_value('uncertain notice', lambda: (state if (state := read_json(state_path)) and state.get('notices') else None))
        old_notice = initial['notices'][0]
        coords = {'home': str(f.home), 'project_id': f.project, 'agent_id': f.agent}
        assert post(old_endpoint, '/fixture/restart', coords)['started']
        replacement_process = subprocess.Popen([str(server), 'fixture-restart', '--service', str(profile)],
                                               cwd=f.repo, env=f.env, stdin=subprocess.DEVNULL,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                               start_new_session=True)
        replacement = wait_value('replacement process', lambda: read_json(profile / 'fixture-replacement.json'))
        new_endpoint = replacement['endpoint']
        new_pid = replacement['pid']
        assert new_pid != old_pid
        wait_value('rebind response and 409 window', lambda: (state if (state := read_json(state_path)) and state.get('rebound') and state.get('not_ready_count', 0) > 0 else None))
        assert post(old_endpoint, '/fixture/exit', {})['exiting']
        assert 'error' in initialize_with_original_pair(policy), 'old grants remained usable after rebind'
        still = read_json(state_path)
        assert len(still['notices']) == 1, 'mail was offered before the challenge became ready'
        assert post(new_endpoint, '/fixture/ready', {})['ready']
        final = wait_value('fresh notice', lambda: (state if (state := read_json(state_path)) and len(state.get('notices', [])) >= 2 else None))
        new_notice = final['notices'][1]
        assert new_notice['id'] != old_notice['id'], 'uncertain notice was replayed'
        assert new_notice['metadata']['messages'] == old_notice['metadata']['messages']
        assert post(new_endpoint, '/fixture/retry', {})['retrying']
        wait_value('same-key grants', lambda: (state if (state := read_json(state_path)) and state.get('same_grants') is True else None))
        f.close()
        closed = True
        assert read_json(state_path)['released'] is True
        assert replacement_process.poll() is None, 'seat release stopped the shared service'
    finally:
        failing = sys.exc_info()[0] is not None
        failures = []
        if not closed:
            try:
                down = f.call('down')
                if down.returncode:
                    failures.append('host cleanup reported incomplete')
            except Exception as error:
                failures.append('host cleanup failed: ' + str(error))
        profiles = list((f.home / 'secode-profiles').glob('*/profile'))
        if profiles:
            old = read_json(profiles[0] / 'fixture-registration.json') or {}
            replacement = read_json(profiles[0] / 'fixture-replacement.json') or {}
            old_endpoint = old_endpoint or old.get('endpoint')
            new_endpoint = new_endpoint or replacement.get('endpoint')
            old_pid = old_pid or old.get('pid')
            new_pid = new_pid or replacement.get('pid')
        # The fixture owns itself and exits cooperatively; never signal by name.
        for endpoint in (new_endpoint, old_endpoint):
            if endpoint:
                try:
                    post(endpoint, '/fixture/exit', {})
                except Exception as error:
                    print('fixture exit request did not complete:', error, file=sys.stderr)
        if replacement_process is not None:
            try:
                replacement_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                failures.append('replacement service did not exit after its fixture request')
        for pid in (old_pid, new_pid):
            if pid:
                cmdline = Path('/proc') / str(pid) / 'cmdline'
                until = time.monotonic() + 5
                while True:
                    try:
                        command = cmdline.read_bytes()
                    except FileNotFoundError:
                        break
                    if str(args.root).encode() not in command:
                        break
                    if time.monotonic() >= until:
                        failures.append('fixture process remains live: ' + str(pid))
                        break
                    time.sleep(.05)
        if failures:
            print('; '.join(failures), file=sys.stderr)
            if not failing:
                raise RuntimeError('fixture cleanup incomplete')


if __name__ == '__main__':
    main()
