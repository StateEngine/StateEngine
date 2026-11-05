"""Bug: d88e8492 — registered projects beyond the two live roots cannot use Atlas.

Protects unlimited-project indexing: eight real Git repositories remain
queryable, idle disk indexes survive live-resource recycling, and unwatched
edits never produce silently stale Current pointers. Linux native only.
Use --codex /absolute/stock/codex for B4's one-session after-task measurement.
--behavior-only retains memory diagnostics but cannot qualify B4.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).with_name('judges')))
from atlas_memory import MemoryMonitor, process


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
    result = {'image': str(args.se), 'sha256': image_hash, 'checks': {}, 'calls': [],
              'rule': 'unlimited disk indexes; bounded recycled live resources',
              'project_count': args.project_count, 'b4': {'qualified': False}}
    projects, calls = {}, 0
    host = task = monitor = None
    labels = [f'Project{i:02}' for i in range(args.project_count)]

    def call(*arguments):
        nonlocal calls
        calls += 1
        argv = [str(args.se), '--home', str(home), '--json', *arguments]
        reply = subprocess.run(argv, env=env, capture_output=True, timeout=60)
        prefix = args.output / f'call-{calls:03}'
        prefix.with_suffix('.stdout').write_bytes(reply.stdout)
        prefix.with_suffix('.stderr').write_bytes(reply.stderr)
        result['calls'].append({'argv': argv, 'exit': reply.returncode, 'log': str(prefix)})
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

    def atlas_status(label):
        return ok('--project', projects[label]['project'], 'status')['atlas']

    def query(label, name=None, outline=False):
        words = ['--project', projects[label]['project'], 'atlas']
        if outline:
            words += ['outline', 'ordinary.py', '--budget', '8192']
        else:
            words += ['find', name or projects[label]['symbol'], '--kind', 'symbol',
                      '--mode', 'exact', '--in', 'ordinary.py', '--budget', '8192']
        return call(*words)

    def payload(answer):
        if 'data' not in answer:
            answer = answer.get('value', {})
        data = answer.get('data', {})
        return data.get('value') if data.get('state') == 'present' else None

    def symbol(answer, name):
        data = payload(answer)
        if data is None:
            return None
        matches = [hit['target']['Code']['pointer'] for hit in data['page']['items']
                   if hit.get('target', {}).get('Code', {}).get('name') == name]
        assert len(matches) <= 1, answer
        return matches[0] if matches else None

    def content_hash(pointer):
        value = pointer['content_hash']
        return bytes(value).hex() if isinstance(value, list) else value

    def traverse(label, name=None):
        name = name or projects[label]['symbol']
        deadline = time.monotonic() + args.wait_seconds
        while True:
            code, body = query(label, name)
            pointer = symbol(body, name)
            if pointer and pointer['freshness'] == 'Current':
                source = (projects[label]['repo'] / 'ordinary.py').read_bytes()
                span = pointer['span']
                assert ('def ' + name).encode() in source[span['start_byte']:span['end_byte']], body
                if name == 'idle_project_new_symbol':
                    assert content_hash(pointer) != projects[label]['initial_content_hash'], (
                        'newly parsed declaration retained the old file revision', body)
                else:
                    projects[label].setdefault('initial_content_hash', content_hash(pointer))
                return pointer
            if code not in [0, 2, 4]:
                # A truthful queued response may use the ordinary typed retry.
                assert body.get('retry', {}).get('kind') == 'after', (
                    'query refused instead of admitting registered project', label, code, body)
            text = json.dumps(body).lower()
            assert any(word in text for word in ['index', 'prepar', 'queue', 'updating', 'progress']), (
                'pending query has no indexing/progress explanation', body)
            assert time.monotonic() < deadline, ('indexing did not reach queried source', label, body)
            time.sleep(.2)

    def check(label, action):
        try:
            action()
            result['checks'][label] = {'state': 'passed'}
        except Exception:
            result['checks'][label] = {'state': 'failed', 'detail': traceback.format_exc()}

    def disk_cache(label):
        project = projects[label]['project']
        files = [path for path in (home / 'atlas').rglob('*')
                 if path.is_file() and project in path.parts
                 and path.suffix in ['.db', '.sqlite', '.sqlite3']]
        assert files, ('no retained per-project disk index', project)
        return files

    try:
        for i, label in enumerate(labels):
            repo = args.output / label
            repo.mkdir()
            name = f'project_{i:02}_atlas_token'
            (repo / 'ordinary.py').write_text(f'def {name}():\n    return "{label} searchable"\n')
            subprocess.run(['git', 'init', '-q', str(repo)], env=env, check=True)
            subprocess.run(['git', '-C', str(repo), 'add', '--', 'ordinary.py'], env=env, check=True)
            subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Atlas judge', '-c',
                            'user.email=atlas-judge@example.invalid', 'commit', '-q', '-F', '-',
                            '--', 'ordinary.py'], input=b'Create ordinary searchable code.\n',
                           env=env, check=True)
            init = ok('init', '--repo', str(repo), '--name', label, '--provider', 'codex')
            projects[label] = {'repo': repo, 'symbol': name,
                               'project': init['project']['id'], 'agent': init['agent']['id']}
        started = ok('up')
        host = {'pid': started['process']['pid'], 'endpoint': started['endpoint']}
        host.update(process(host['pid']))
        assert host['state'] not in ['absent', 'Z'], host
        result['host'] = host
        monitor = MemoryMonitor(args.se, host['pid'], args.output / 'memory-samples.json')
        monitor.start()
        monitor.stage = 'cold-indexing'
        result['initial_status'] = {label: atlas_status(label) for label in labels}
        for label in labels:
            check('traverse/' + label, lambda label=label: traverse(label))
        all_indexed = all(row['state'] == 'passed' for row in result['checks'].values())
        if all_indexed:
            caches = {label: disk_cache(label) for label in labels}
            monitor.stage = 'recycled-live-resources'

            def idle_read():
                idle = labels[0]
                # Keep the first project idle while every other project is used.
                for _ in range(2):
                    for label in labels[1:]:
                        traverse(label)
                traverse(idle)
                assert all(path.is_file() for path in caches[idle]), caches[idle]
                source = projects[idle]['repo'] / 'ordinary.py'
                added = 'idle_project_new_symbol'
                with source.open('a') as writer:
                    writer.write(f'\ndef {added}():\n    return "unwatched working-tree edit"\n')
                    writer.flush()
                    os.fsync(writer.fileno())
                _, first = query(idle, outline=True)
                view = payload(first)
                if view and view['file']['freshness'] == 'Current':
                    assert content_hash(view['file']) != projects[idle]['initial_content_hash'], (
                        'idle working-tree edit returned silently stale Current', first)
                traverse(idle, added)
                result['idle_status'] = atlas_status(idle)

            check('idle-project-cache-and-freshness', idle_read)
        if not args.behavior_only:
            from atlas_codex_task import CodexTask
            monitor.stage = 'real-agent-task'
            task = CodexTask(args.codex, args.se, home, owner, env, args.output)
            task.start(projects[labels[0]], ok)
            monitor.provider = task.provider
            result['task'] = task.verify(projects[labels[0]], ok, args.wait_seconds)
            deadline = time.monotonic() + args.wait_seconds
            while atlas_status(labels[0])['state'] == 'preparing':
                assert time.monotonic() < deadline, 'task project did not leave cold indexing'
                time.sleep(.2)
            monitor.stage = 'settled-one-session'
            time.sleep(args.settle_seconds)
            budget = monitor.budget()
            budget['all_projects_traversed'] = all_indexed
            budget['qualified'] &= all_indexed
            result['b4'] = budget

            def memory_bound():
                assert budget['complete'], budget
                assert budget['settled_max_bytes'] <= 64_000_000, budget

            check('B4-after-task-one-session', memory_bound)
        if args.behavior_only:
            result['b4']['reason'] = 'behavior-only diagnostic; no real live agent/task precondition'
    except Exception:
        result['setup_or_task_failure'] = traceback.format_exc()
    finally:
        if monitor:
            monitor.stop()
            result['memory'] = monitor.budget()
            result['memory']['all_projects_traversed'] = bool(locals().get('all_indexed', False))
            result['memory']['qualified'] &= result['memory']['all_projects_traversed']
        if host:
            try:
                stopped = ok('down')
                assert stopped['complete'], stopped
                observed = process(host['pid'])
                assert (observed['state'] in ['absent', 'Z'] or
                        observed['birth'] != host['birth']), observed
                assert not Path(host['endpoint']).exists(), host
                if task and task.provider:
                    original = task.provider
                    now = process(original['pid'])
                    assert now['state'] in ['absent', 'Z'] or now['birth'] != original['birth'], now
                if task and task.native:
                    original = task.native
                    now = process(original['pid'])
                    assert now['state'] in ['absent', 'Z'] or now['birth'] != original['birth'], now
                with (home / 'runtime.lock').open('rb') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                observed_births = {}
                if monitor:
                    for sample in monitor.samples:
                        for row in sample['processes']:
                            observed_births[(row['pid'], row['birth'])] = row
                for (pid, birth), row in observed_births.items():
                    now = process(pid)
                    assert now['state'] in ['absent', 'Z'] or now['birth'] != birth, (row, now)
                result['shutdown'] = {'complete': True, 'outside': observed,
                                      'observed_births_closed': len(observed_births),
                                      'endpoint_absent': True, 'lease_available': True}
            except Exception:
                result['shutdown_failure'] = traceback.format_exc()
        if task:
            task.close()
        assert hashlib.sha256(args.se.read_bytes()).hexdigest() == image_hash
        result['counts'] = {
            'passed': sum(row['state'] == 'passed' for row in result['checks'].values()),
            'failed': sum(row['state'] == 'failed' for row in result['checks'].values())
                      + int('setup_or_task_failure' in result) + int('shutdown_failure' in result),
            'unreached': args.project_count + 2 - len(result['checks'])}
        (args.output / 'result.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result['counts']))
    return int(result['counts']['failed'] > 0 or
               (not args.behavior_only and result['counts']['unreached'] > 0))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['se', 'output', 'runtime-root']:
        parser.add_argument('--' + name, type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument('--project-count', type=int, default=8)
    parser.add_argument('--wait-seconds', type=float, default=60)
    parser.add_argument('--settle-seconds', type=float, default=3)
    parser.add_argument('--codex', type=lambda p: Path(p).resolve())
    parser.add_argument('--behavior-only', action='store_true')
    args = parser.parse_args()
    if args.project_count < 8:
        parser.error('the unlimited-project regression requires at least eight repositories')
    if not args.behavior_only and args.codex is None:
        parser.error('--codex is required for the real-agent B4 precondition; otherwise use --behavior-only')
    raise SystemExit(run(args))
