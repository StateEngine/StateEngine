"""Independent public CLI/MCP fresh and explicit-resume consumer.

Native provider protocol double; private homes; no account or direct store writes.
The shared fixture compiles its native launcher only on the selected native runner.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from agent_create_cli import owner_grant
from fixture_paths import private_runtime_directory
from mail_cli import Fixture


def private_bytes(pid):
    try:
        rows = Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines()
        fields = dict(line.split(':', 1) for line in rows if ':' in line)
        names = ('Private_Clean', 'Private_Dirty', 'Private_Hugetlb')
        if not all(name in fields for name in names):
            return {'state': 'unavailable', 'reason': 'private memory fields absent'}
        return {'state': 'present', 'bytes': sum(int(fields[name].split()[0]) * 1024 for name in names)}
    except (OSError, ValueError) as error:
        return {'state': 'unavailable', 'reason': str(error)}


def run(args):
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    runtime = private_runtime_directory()
    f = None
    result = {'checks': [], 'launches': [], 'closure': None, 'failures': []}
    def check(text):
        result['checks'].append(text)
        print(f'ok {len(result["checks"])} - {text}', flush=True)
    try:
        f = Fixture(args.se, args.output / 'fixture',
                    provider_helper=Path(__file__).with_name('fresh_conversation_provider.py'))
        wrapper = f.root / 'provider.rs'
        wrapper.write_text(wrapper.read_text().replace('2.1.287', '2.1.318'))
        subprocess.run(['rustc', '--edition=2024', str(wrapper), '-o', str(f.root / 'provider')],
                       capture_output=True, check=True, timeout=60)
        f.env = {'PATH': os.environ['PATH'], 'HOME': str(f.root / 'owner'),
                 'USERPROFILE': str(f.root / 'owner'), 'LANG': 'C.UTF-8',
                 'XDG_RUNTIME_DIR': str(runtime)}
        for name in ('XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME'):
            path = f.root / name.lower()
            path.mkdir()
            f.env[name] = str(path)
        f.ok('up')

        def observe(receipt):
            deadline = time.monotonic() + 25
            while True:
                path = f.repo / 'launch-observed.jsonl'
                text = path.read_text() if path.exists() else ''
                complete = text[:text.rfind('\n') + 1]
                for line in complete.splitlines():
                    row = json.loads(line)
                    if row['environment'].get('SE_SESSION') == receipt['session_id']:
                        assert row['conversation'] == receipt['conversation_id']
                        assert row['native_root_pid'] == receipt['process']['pid']
                        for pid in (row['native_root_pid'], row['helper_pid']):
                            fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
                            f.processes.append((pid, fields[19]))
                        return row
                assert time.monotonic() < deadline, 'no provider observation for exact session'
                time.sleep(.025)

        def launch(agent, door='cli', resume=None, plain=False):
            key = str(uuid.uuid4())
            argv = ['--project', f.project, '--key', key, 'launch', agent,
                    '--detach', '--task', 'Independent conversation selection check']
            if resume is True:
                argv.append('--resume')
            elif isinstance(resume, str):
                argv.append('--resume=' + resume)
            start = time.monotonic_ns()
            text = None
            if door == 'mcp':
                payload = {'target_agent_id': agent, 'detach': True,
                           'task': 'Independent conversation selection check', 'idempotency_key': key}
                if resume is not None:
                    payload['resume'] = resume
                reply = f.rpc('stateengine_agent_launch', payload)
                assert not reply.get('isError'), reply
                receipt = reply['structuredContent']
            elif plain:
                reply = subprocess.run([str(f.se), '--home', str(f.home), *argv],
                    cwd=f.repo, env=f.env, capture_output=True, text=True, timeout=90)
                text = reply.stdout
                (args.output / ('plain-' + key + '.txt')).write_text(reply.stdout + reply.stderr)
                assert reply.returncode == 0, reply.stderr
                launch_returned = time.monotonic_ns()
                receipt = f.ok(*argv)
            else:
                receipt = f.ok(*argv)
            elapsed = (launch_returned if door == 'cli' and plain else time.monotonic_ns()) - start
            assert receipt['state'] == 'running', receipt
            row = observe(receipt)
            if not args.baseline:
                assert receipt['resumed'] is (resume is not None), receipt
                assert receipt['mail_notifications'] == {'state': 'present', 'value': True}, receipt
            assert receipt['provider'] == 'claude', receipt
            result['launches'].append({'door': door, 'selection': resume, 'receipt': receipt,
                'elapsed_ns': elapsed, 'provider_private_memory': private_bytes(receipt['process']['pid']),
                'provider_observation': row, 'plain': text})
            return receipt, row, text

        parent, _, _ = launch(f.agent)
        f.session = parent['session_id']
        owner_grant(f, True)
        for door in (('cli',) if args.baseline else ('cli', 'mcp')):
            child = f.ok('--project', f.project, 'agent', 'add', 'Fresh ' + door,
                         '--provider', 'claude', '--model', 'claude-sonnet-5-5',
                         recipient=True)['agent']['id']
            marker = 'durable-state-' + uuid.uuid4().hex
            f.ok('--project', f.project, 'working-state', 'set', marker,
                 '--agent', child, '--expect', 'absent')
            sent = f.mail('send', child, 'unread-context-' + marker, '--no-wake')
            first, row, text = launch(child, door, plain=door == 'cli')
            assert row['flag'] == '--session-id'
            assert marker in json.dumps(row['working_state']), row
            assert sent['message_id'] in json.dumps(row['unread_mail']), row
            stopped = f.ok('--project', f.project, 'stop', child)
            assert stopped['complete'] and stopped['population'] == 'empty', stopped
            second, row, text = launch(child, door, plain=door == 'cli')
            assert second['conversation_id'] != first['conversation_id'], 'plain launches reused saved conversation'
            assert marker in json.dumps(row['working_state'])
            assert sent['message_id'] in json.dumps(row['unread_mail'])
            assert row['flag'] == '--session-id'
            if text is not None:
                assert 'fresh' in text.lower() and second['conversation_id'] in text, text
            check(door + ': two plain launches have distinct conversations and retain working state/unread mail')
            f.ok('--project', f.project, 'stop', child)
            latest, row, text = launch(child, door, resume=True, plain=door == 'cli')
            assert latest['conversation_id'] == second['conversation_id'] and row['flag'] == '--resume'
            if text is not None:
                assert 'resumed' in text.lower() and latest['conversation_id'] in text, text
            check(door + ': explicit latest resume selects and reports the second conversation')
            f.ok('--project', f.project, 'stop', child)
            named, row, _ = launch(child, door, resume=first['session_id'])
            assert named['conversation_id'] == first['conversation_id'] and row['flag'] == '--resume'
            check(door + ': explicit session resume selects the older first conversation')
            f.ok('--project', f.project, 'stop', child)
            refused = f.call('--project', f.project, 'launch', child, '--detach',
                             '--resume=' + parent['session_id'])
            assert refused.returncode != 0, 'another agent session was accepted'
            check(door + ': another agent session cannot be selected')
    except Exception as error:
        result['failures'].append(f'{type(error).__name__}: {error}')
    finally:
        if f is not None:
            try:
                f.close()
                result['closure'] = {'witnessed': True, 'known_provider_identities': f.processes,
                                     'endpoint_absent': not (f.home / 'endpoint.json').exists()}
            except Exception as error:
                result['failures'].append('closure: ' + str(error))
        # The runtime directory is owned by this judge and has no user data.
        if runtime.exists():
            for child in runtime.iterdir():
                if child.is_dir() and not child.is_symlink() and not any(child.iterdir()):
                    child.rmdir()
            if not any(runtime.iterdir()):
                runtime.rmdir()
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    if result['failures']:
        raise AssertionError(result['failures'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', action='store_true', help='Observe the prior default without requiring newly added receipt fields')
    run(parser.parse_args())
