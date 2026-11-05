"""Bug: d88e8492 — a query on the third project never requests Atlas admission.

Protects: installed CLI reads rotate two native Atlas roots across three real
Git projects, preserve evicted disk caches, and explain pending indexing.
Status alone must not request admission. No agents or provider calls are used.
Linux native only; the bounded preparation wait is not a latency qualification.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import traceback


def process(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
        return {'state': fields[0], 'birth': fields[19]}
    except FileNotFoundError:
        return {'state': 'absent', 'birth': None}


def run(args):
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    args.runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    owner, home = args.output / 'owner', args.output / 'state'
    owner.mkdir()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('SE_', 'STATEENGINE_', 'CLAUDE', 'CODEX'))}
    env.update(HOME=str(owner), USERPROFILE=str(owner),
               TMPDIR=str(args.runtime_root), XDG_RUNTIME_DIR=str(args.runtime_root))
    for key in ['XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME']:
        path = owner / key.lower()
        path.mkdir()
        env[key] = str(path)
    image_hash = hashlib.sha256(args.se.read_bytes()).hexdigest()
    result = {'image': str(args.se), 'sha256': image_hash, 'checks': {}, 'calls': []}
    projects, calls = {}, 0
    host = None

    def call(*arguments):
        nonlocal calls
        calls += 1
        argv = [str(args.se), '--home', str(home), '--json', *arguments]
        reply = subprocess.run(argv, env=env, capture_output=True, timeout=60)
        prefix = args.output / f'call-{calls:03}'
        prefix.with_suffix('.stdout').write_bytes(reply.stdout)
        prefix.with_suffix('.stderr').write_bytes(reply.stderr)
        result['calls'].append({'argv': argv, 'exit': reply.returncode,
                                'log': str(prefix)})
        try:
            body = json.loads(reply.stdout)
        except ValueError:
            body = {'stdout': reply.stdout.decode(errors='replace'),
                    'stderr': reply.stderr.decode(errors='replace')}
        return reply.returncode, body

    def ok(*arguments):
        code, body = call(*arguments)
        assert code == 0, (arguments, code, body)
        return body

    def statuses():
        answers = {label: ok('--project', project, 'status')['atlas']
                   for label, project in projects.items()}
        roots = [a.get('summary', {}).get('root') for a in answers.values()]
        assert sum(root is not None for root in roots) <= 2, answers
        return answers

    def current(answer):
        return answer.get('state') == 'current'

    def query(label):
        return call('--project', projects[label], 'atlas', 'find',
                    f'{label.lower()}_three_project_token', '--kind', 'symbol',
                    '--mode', 'exact', '--in', 'ordinary.py', '--budget', '8192')

    def has_symbol(answer, label):
        if 'data' not in answer:
            answer = answer.get('value', {})
        data = answer.get('data', {})
        if data.get('state') != 'present':
            return False
        hits = data['value']['page']['items']
        return any(hit.get('target', {}).get('Code', {}).get('name') ==
                   f'{label.lower()}_three_project_token' and
                   hit['target']['Code']['pointer']['freshness'] == 'Current'
                   for hit in hits)

    def await_symbol(label):
        deadline = time.monotonic() + args.wait_seconds
        while True:
            code, body = query(label)
            state = statuses()
            if code == 0 and has_symbol(body, label) and current(state[label]):
                return state
            assert time.monotonic() < deadline, ('query never became current', label, body, state)
            time.sleep(.2)

    def cache_files(label, state):
        root = state[label]['summary']['root']
        directory = home / 'atlas' / projects[label] / root
        files = {str(path.relative_to(directory)) for path in directory.rglob('*')
                 if path.is_file() and path.name != 'writer.lock'}
        assert files, ('no disk cache to preserve', directory)
        return directory, files

    def request_inactive(label):
        code, body = query(label)
        if has_symbol(body, label):
            return
        text = json.dumps(body).lower()
        assert 'index' in text and any(word in text for word in ['start', 'prepar', 'queue']), (
            'first query must explain indexing is starting', code, body)
        assert 'retry' in text and re.search(r'\d+\s*(?:ms|millisecond|second|sec|s\b)', text), (
            'pending query must say when to retry', body)
        atlas = statuses()[label]
        assert atlas['state'] in ['preparing', 'updating', 'current', 'starting', 'queued'], (
            'status must agree that indexing was requested', atlas)

    try:
        for label in ['Alpha', 'Beta', 'Gamma']:
            repo = args.output / label
            repo.mkdir()
            (repo / 'ordinary.py').write_text(
                f'def {label.lower()}_three_project_token():\n    return "{label} searchable"\n')
            subprocess.run(['git', 'init', '-q', str(repo)], env=env, check=True)
            subprocess.run(['git', '-C', str(repo), 'add', '--', 'ordinary.py'], env=env, check=True)
            subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Atlas judge', '-c',
                            'user.email=atlas-judge@example.invalid', 'commit', '-q', '-F', '-',
                            '--', 'ordinary.py'], input=b'Create ordinary searchable code.\n',
                           env=env, check=True)
            init = ok('init', '--repo', str(repo), '--name', label, '--provider', 'codex')
            projects[label] = init['project']['id']
        started = ok('up')
        host = {'pid': started['process']['pid'], 'endpoint': started['endpoint']}
        host.update(process(host['pid']))
        assert host['state'] not in ['absent', 'Z'], host
        result['host'] = host
        deadline = time.monotonic() + args.wait_seconds
        while True:
            initial = statuses()
            active = [label for label, answer in initial.items() if current(answer)]
            if len(active) == 2:
                break
            assert time.monotonic() < deadline, ('initial two roots not ready', initial)
            time.sleep(.2)
        inactive = next(label for label in projects if label not in active)
        retained, evicted = active
        result['initial'] = initial
        for _ in range(3):
            time.sleep(.2)
            observed = statuses()
            assert observed[inactive]['state'] == 'unavailable', observed
            assert all(current(observed[label]) for label in active), observed
        result['checks']['status-is-observational'] = 'passed'

        await_symbol(retained)  # Make this project the most recently queried root.
        directory, files = cache_files(evicted, initial)
        request_inactive(inactive)
        rotated = await_symbol(inactive)
        assert current(rotated[retained]) and rotated[evicted]['state'] == 'unavailable', rotated
        assert directory.is_dir() and all((directory / path).is_file() for path in files), directory
        result['checks']['query-admits-third-and-evicts-lru'] = 'passed'
        result['rotated'] = rotated

        directory, files = cache_files(retained, rotated)
        request_inactive(evicted)
        returned = await_symbol(evicted)
        assert current(returned[inactive]) and returned[retained]['state'] == 'unavailable', returned
        assert directory.is_dir() and all((directory / path).is_file() for path in files), directory
        result['checks']['read-only-return-preserves-cache-and-two-root-limit'] = 'passed'
        result['returned'] = returned
    except Exception:
        result['failure'] = traceback.format_exc()
    finally:
        if host is not None:
            try:
                stopped = ok('down')
                assert stopped['complete'], stopped
                observed = process(host['pid'])
                assert (observed['state'] in ['absent', 'Z'] or
                        observed['birth'] != host['birth']), observed
                assert not Path(host['endpoint']).exists(), host
                with (home / 'runtime.lock').open('rb') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result['shutdown'] = {'complete': True, 'outside': observed,
                                      'endpoint_absent': True, 'lease_available': True}
            except Exception:
                result['shutdown_failure'] = traceback.format_exc()
        assert hashlib.sha256(args.se.read_bytes()).hexdigest() == image_hash
        result['counts'] = {'passed': len(result['checks']),
                            'failed': int('failure' in result) + int('shutdown_failure' in result),
                            'unreached': 3 - len(result['checks']) - int('failure' in result)}
        (args.output / 'result.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result['counts']))
    return int(bool(result.get('failure') or result.get('shutdown_failure')))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument('--output', type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument('--runtime-root', type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument('--wait-seconds', type=float, default=45)
    raise SystemExit(run(parser.parse_args()))
