"""Public Atlas status/config/help consumer with private state and a native protocol fixture.
Run with --se BINARY --output NEW_DIRECTORY. Native owner execution requires Linux.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).with_name('judges')))
from mail_cli import Fixture


def run(args):
    args.output.mkdir(parents=True, exist_ok=False)
    private = {}
    for key in ['XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'CODEX_HOME']:
        directory = args.output / key.lower()
        directory.mkdir(mode=0o700)
        private[key] = str(directory)

    class IsolatedFixture(Fixture):
        def call(self, *arguments, **options):
            self.env.update(private)
            return super().call(*arguments, **options)

    f = IsolatedFixture(args.se, args.output / 'fixture')
    checks = []
    def passed(label):
        checks.append(label)
        print(f'ok {len(checks)} - {label}', flush=True)

    try:
        help_call = subprocess.run([str(f.se), 'atlas'], env=f.env, capture_output=True, timeout=15)
        (args.output / 'atlas-help.stdout').write_bytes(help_call.stdout)
        assert help_call.returncode == 0, (help_call.stdout, help_call.stderr)
        assert all(word in help_call.stdout for word in [b'find', b'refs', b'impact', b'changes', b'outline'])
        passed('bare atlas lists the five existing read commands without opening a host')
        config = f.home / 'config.toml'
        before = config.read_bytes()
        for verb, values in [('get', []), ('set', ['true'])]:
            refused = f.call('--project', f.project, 'config', verb, 'atlas.enabled', *values)
            assert refused.returncode != 0
            value = json.loads(refused.stdout)
            assert 'atlas.enabled' in value['message'] and '[redacted]' not in value['message']
            assert 'config.toml' in value['remedy']['text'] and 'se atlas' in value['remedy']['text']
            assert config.read_bytes() == before
        passed('unsupported config get/set names the Atlas key and real file/restart path without writing')
        config.write_text(before.decode().replace('[atlas]\nenabled = true', '[atlas]\nenabled = false'))
        disabled = f.ok('--project', f.project, 'status')
        assert disabled['atlas']['state'] == 'disabled', disabled['atlas']
        assert not (f.home / 'atlas').exists(), 'status created an Atlas cache'
        passed('disabled direct status is honest and creates no Atlas cache')
        (f.repo / 'good.js').write_text('export function atlas_status_visible(){return 1;}\n')
        # Above the measured parser-size qualification: a real deferred file,
        # rather than an injected status DTO, must remain visible in the summary.
        (f.repo / 'large.js').write_text('export const large = 1;\n' + '// padding\n' * 300)
        config.write_bytes(before)
        started = f.ok('up')
        host_pid = started['process']['pid']
        host_birth = Path(f'/proc/{host_pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
        f.processes.append((host_pid, host_birth))
        states = []
        until = time.monotonic() + 90
        while True:
            status = f.ok('--project', f.project, 'status')
            atlas = status['atlas']
            states.append(atlas)
            (args.output / 'observed-status.json').write_text(json.dumps(states, indent=2))
            assert atlas['state'] != 'not-built', atlas
            summary = atlas.get('summary')
            if summary and summary['coverage']['indexed_files'] and summary['coverage']['deferred_files']:
                break
            assert time.monotonic() < until, atlas
            time.sleep(.2)
        assert atlas['state'] in ['partial', 'updating'], atlas
        found_call = f.call('--project', f.project, 'atlas', 'find', 'atlas_status_visible')
        assert found_call.returncode in [0, 2], (found_call.stdout, found_call.stderr)
        found = json.loads(found_call.stdout)
        (args.output / 'find.json').write_text(json.dumps(found, indent=2))
        assert 'atlas_status_visible' in json.dumps(found), found
        plain = subprocess.run([str(f.se), '--home', str(f.home), '--project', f.project, 'status'],
                               env=f.env, capture_output=True, timeout=30)
        (args.output / 'plain-status.stdout').write_bytes(plain.stdout)
        assert plain.returncode == 0 and b'Atlas files:' in plain.stdout and b'deferred' in plain.stdout
        assert b'not-built' not in plain.stdout
        passed('live CLI Atlas answer and partial file counts agree in JSON and plain status')
        f.launch()
        status = f.rpc('stateengine_status', {})
        assert not status.get('isError'), status
        status = status['structuredContent']
        if 'atlas' not in status and 'value' in status:
            status = status['value']
        assert status['atlas']['state'] != 'not-built', status['atlas']
        assert status['atlas']['summary']['coverage']['deferred_files'] >= 1
        passed('session-authenticated MCP status reads the same live Atlas coverage')
    finally:
        f.close()
    assert not (f.home / 'endpoint.json').exists()
    (args.output / 'outside.json').write_text(json.dumps(dict(endpoint_present=False, closed_births=f.processes), indent=2))
    passed('authenticated shutdown and outside provider birth checks close the fixture')
    (args.output / 'checks.json').write_text(json.dumps(dict(passed=len(checks), failed=0, checks=checks), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
