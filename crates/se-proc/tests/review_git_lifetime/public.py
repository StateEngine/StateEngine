"""macOS public history refusal and source coverage through real CLI/MCP."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from control import observe, same


def present(value):
    if 'atlas' not in value and isinstance(value.get('value'), dict):
        value = value['value']
    return value


def run(args):
    assert sys.platform == 'darwin', 'native macOS control only'
    os.umask(0o077)
    args.out.mkdir(mode=0o700)
    sys.path.insert(0, str(args.source / 'crates/se/tests/judges'))
    from mail_cli import Fixture
    private = {}
    for name in ['XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'CODEX_HOME']:
        root = args.out / name.lower()
        root.mkdir(mode=0o700)
        private[name] = str(root)

    class PrivateFixture(Fixture):
        def call(self, *arguments, **options):
            self.env.update(private)
            return super().call(*arguments, **options)

    fixture = PrivateFixture(args.se, args.out / 'fixture')
    report, pins, error = {'qualified': False, 'observations': []}, [], None
    try:
        path = fixture.repo / 'visible.js'
        path.write_text('export function source_index_visible(){return 7;}\n')
        # A real nonempty Git history makes unavailable distinct from an empty repository.
        for command in [
            ['git', 'init', '-q', str(fixture.repo)],
            ['git', '-C', str(fixture.repo), 'add', 'visible.js'],
            ['git', '-C', str(fixture.repo), '-c', 'user.name=Fixture',
             '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'Add source fixture'],
        ]:
            subprocess.run(command, env=fixture.env, check=True, capture_output=True, timeout=20)
        started = fixture.ok('up')
        host = observe(started['process']['pid'])
        assert host is not None and host['status'] != 5, started
        pins.append(host)
        until = time.monotonic() + 90
        while True:
            status = fixture.ok('--project', fixture.project, 'status')
            atlas = status['atlas']
            report['observations'].append(atlas)
            coverage = (atlas.get('summary') or {}).get('coverage') or {}
            if coverage.get('indexed_files', 0) >= 1:
                break
            assert time.monotonic() < until, atlas
            time.sleep(.2)
        assert atlas['history'] == 'unavailable', atlas
        assert coverage.get('history_unavailable'), coverage
        assert 'HistoryUnavailable' in coverage['reasons'], coverage
        assert 'measured host SQL overhead' in json.dumps(coverage['history_unavailable']), coverage
        report['CLI'] = status
        fixture.launch()
        ready = json.loads((fixture.repo / 'provider-ready.json').read_text())
        for key in ['native_root_pid', 'helper_pid']:
            pin = observe(ready[key])
            assert pin is not None and pin['status'] != 5, ready
            pins.append(pin)
        reply = fixture.rpc('stateengine_status', {})
        assert not reply.get('isError'), reply
        status = present(reply['structuredContent'])
        atlas = status['atlas']
        coverage = atlas['summary']['coverage']
        report['MCP'] = status
        assert atlas['history'] == 'unavailable', atlas
        assert coverage['indexed_files'] >= 1, coverage
        assert coverage.get('history_unavailable'), coverage
        assert 'HistoryUnavailable' in coverage['reasons'], coverage
        assert 'measured host SQL overhead' in json.dumps(coverage['history_unavailable']), coverage
        # Status is the ordinary reader of the published source coverage. Do not
        # inject a SQL profile or claim that this qualifies public source queries.
        report['source_bytes'] = path.read_text()
        report['qualified'] = True
    except Exception as failure:
        error = repr(failure)
        report['failure'] = error
    finally:
        try:
            fixture.close()
            assert not (fixture.home / 'endpoint.json').exists()
            with (fixture.home / 'runtime.lock').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            states = [{'receipt': pin, 'current': observe(pin['pid'])} for pin in pins]
            report['outside'] = states
            assert all(not same(x['receipt'], x['current']) or x['current']['status'] == 5 for x in states), states
            report['shutdown_witnessed_and_runtime_lease_free'] = True
        except Exception as failure:
            report['qualified'] = False
            report['closure_failure'] = repr(failure)
        (args.out / 'public-report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert report['qualified'] and error is None, report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    run(parser.parse_args())
