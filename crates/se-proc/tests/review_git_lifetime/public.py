"""macOS public defaults remain explicitly unavailable through real CLI/MCP."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

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
        status = fixture.ok('--project', fixture.project, 'status')
        atlas = status['atlas']
        report['observations'].append(atlas)
        assert atlas['history'] == 'unavailable', atlas
        assert atlas['state'] == 'unavailable', atlas
        assert atlas['reason'] == 'No Atlas controller is installed in this host.', atlas
        assert atlas.get('summary') is None, atlas
        report['CLI'] = status
        refused = fixture.call('--project', fixture.project, 'atlas', 'find', 'source_index_visible')
        assert refused.returncode != 0, 'uninstalled source query reported success'
        assert len(refused.stdout) + len(refused.stderr) <= 65536, 'refusal exceeds evidence bound'
        report['CLI_source_query_refusal'] = {
            'exit': refused.returncode, 'stdout': refused.stdout.decode(),
            'stderr': refused.stderr.decode()}
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
        report['MCP'] = status
        assert atlas == report['CLI']['atlas'], (atlas, report['CLI']['atlas'])
        assert atlas['history'] == 'unavailable', atlas
        assert atlas['state'] == 'unavailable', atlas
        assert atlas.get('summary') is None, atlas
        assert not (fixture.home / 'atlas').exists(), 'uninstalled controller created a cache'
        report['controller_absent'] = True
        report['cache_absent'] = True
        report['source_index_qualified'] = False
        report['source_index_limitation'] = (
            'Public macOS defaults install no Atlas controller; indexed source '
            'coverage and source queries cannot be qualified by this check.')
        report['source_bytes'] = path.read_text()
        report['unchanged_public_unavailability_qualified'] = True
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
