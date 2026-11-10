"""Linux native force replacement with a responsive stale-execution API fixture.

Run explicitly with a locally built provider package. The local synthetic HTTP
provider does no paid work. A failed successor remains a failure even if native
retirement succeeds; observations and cleanup results are retained separately.
"""
import argparse
import json
import subprocess
import time
import traceback
from pathlib import Path
import secode_managed as sm

class Consumer(sm.Consumer):
    def call(self, *args):
        end = time.monotonic() + 70
        while True:
            result = super().call(*args)
            try:
                code = json.loads(result.stdout).get('code')
            except (ValueError, TypeError):
                code = None
            if (code != 'deadline-exceeded' or b'local IPC' not in result.stdout
                    or '--key' not in args or time.monotonic() >= end):
                return result
            time.sleep(0.1)


def observe(result):
    return {'exit': result.returncode, 'stdout': result.stdout.decode(),
            'stderr': result.stderr.decode()}


def run(args):
    sm.HOST = args.se.resolve()
    sm.PROVIDER = args.provider.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    library = args.output / 'stale-active.so'
    subprocess.run(['cc', '-shared', '-fPIC',
                    str(Path(__file__).with_name('force_stale_active.c')),
                    '-ldl', '-o', str(library)],
                   capture_output=True, check=True, timeout=30)
    root = args.output / 'service'
    fixture = None
    rows = {}
    try:
        fixture = Consumer(root, preload=library)
        first = fixture.launch('Owned original finite input.')
        old_service = dict(fixture.service_identity)
        old_client = sm.identity(first['process']['pid'])
        rows.update(first=first, original_service=old_service, original_client=old_client)
        if args.plain_only:
            result = fixture.call('--project', fixture.project, 'launch', fixture.agent)
            rows['plain'] = observe(result)
            rows['old_client_preserved'] = not sm.closed(old_client)
            body = json.loads(result.stdout)
            assert result.returncode != 0 and body.get('code') == 'launch-confirmation-required', rows
            assert str(old_client['pid']) in result.stdout.decode() and '--force' in result.stdout.decode(), rows
            assert rows['old_client_preserved'], rows
            print('PASS busy native protocol: inventory and force remedy; old client preserved', flush=True)
        else:
            sm.until(lambda: any(v.get('type') == 'assistant' and v.get('finish') == 'stop'
                                 for v in fixture.messages()), 'finite original completion')
            rows['actual_active_before'] = fixture.observer.request('GET', '/api/session/active')
            marker = root / 'drop-reader'
            marker.write_text(fixture.sid)
            result = fixture.call('--key', 'force-stale-execution', '--project', fixture.project,
                                  'launch', fixture.agent, '--detach', '--force',
                                  '--task', 'Owned replacement finite input.')
            rows['forced'] = observe(result)
            marker.unlink(missing_ok=True)
            receipt = root / 'drop-reader.hits'
            rows['injections'] = receipt.read_text().splitlines() if receipt.exists() else []
            rows['old_service_closed'] = sm.closed(old_service)
            rows['old_client_closed'] = sm.closed(old_client)
            assert rows['injections'], 'stale response mutation did not execute'
            assert result.returncode == 0, rows['forced']
            launched = json.loads(result.stdout)
            assert launched['state'] == 'running', launched
            assert launched['conversation_id'] != first['conversation_id'], launched
            assert launched['session_id'] != first['session_id'], launched
            assert rows['old_service_closed'] and rows['old_client_closed'], rows
            fixture.service_identity = None
            fixture.bind()
            rows['new_service'] = fixture.service_identity
            print('PASS stale flag: old service/client closed; new session/conversation/service', flush=True)
    except BaseException:
        rows['failure'] = traceback.format_exc()
    finally:
        (root / 'drop-reader').unlink(missing_ok=True)
        if fixture:
            try:
                # Optional binding diagnostics must never prevent normal cleanup.
                if 'new_service' not in rows:
                    fixture.service_identity = None
                fixture.close()
                for name in ('original_client', 'original_service', 'new_service'):
                    if name in rows:
                        assert sm.closed(rows[name]), 'owned native process survives: ' + name
                rows['closure'] = 'joined'
            except BaseException:
                rows['cleanup_failure'] = traceback.format_exc()
        (args.output / 'observations.json').write_text(json.dumps(rows, indent=2))
    print(json.dumps({k: v for k, v in rows.items() if k != 'injections'}), flush=True)
    return 0 if 'failure' not in rows and 'cleanup_failure' not in rows else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--provider', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--plain-only', action='store_true')
    raise SystemExit(run(parser.parse_args()))


if __name__ == '__main__':
    main()
