"""Verify watched basis, loss of root coverage, and independent Git facts."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def main(image, output):
    output.mkdir(parents=True, exist_ok=False)
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(('GIT_', 'SE_', 'STATEENGINE_', 'CODEX_',
                                         'CLAUDE', 'OPENAI_', 'ANTHROPIC_'))
           and key.upper() != 'XDG_CONFIG_HOME'}
    report = {'os': os.name, 'kernel': os.uname().sysname,
              'run_id': os.getenv('GITHUB_RUN_ID'), 'checks': {}, 'observed': {}}
    log, errors = output / 'host.stdout', output / 'host.stderr'

    def save():
        (output / 'review.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    with tempfile.TemporaryDirectory(prefix='macos-watch-review-') as work:
        root = Path(work).resolve()
        repo, state = root / 'repo', root / 'state'
        replacement = root / 'replacement'

        def command(args, overrides=None):
            process = subprocess.run([str(arg) for arg in args], cwd=root,
                                     env={**env, **(overrides or {})}, stdin=subprocess.DEVNULL,
                                     capture_output=True, timeout=30, text=True, encoding='utf-8')
            assert process.returncode == 0, (args, process.stdout, process.stderr)
            return process.stdout

        def git(path, *args):
            return command(['git', '--no-optional-locks', '-C', path, *args]).strip()

        def seed(path, count, branch):
            path.mkdir()
            git(path, 'init', '-q', '-b', branch)
            git(path, 'config', 'core.ignorecase', 'true')
            git(path, 'config', 'user.name', 'Watcher fixture')
            git(path, 'config', 'user.email', 'fixture@example.invalid')
            (path / 'tracked.txt').write_text(f'{branch}\n', encoding='utf-8')
            git(path, 'add', '--', 'tracked.txt')
            git(path, 'commit', '-qm', 'initial')
            for _ in range(count - 1):
                git(path, 'commit', '--allow-empty', '-qm', 'history')

        def cli(*args, overrides=None):
            return command([image, '--home', state, *args], overrides)

        def status(*flags, overrides=None):
            body = json.loads(cli('--json', '--project', project, 'status', *flags, overrides=overrides))
            return {'git': body.get('project', {}).get('value', {}).get('git') or {},
                    'pending': [item for item in body.get('pending', [])
                                if item['what'].startswith('repository')]}

        def watched(row):
            return row['git'].get('observation', {}).get('basis') == 'watched'

        def wait_for(predicate, seconds=36):
            until = time.monotonic() + seconds
            while True:
                observation = status()
                if predicate(observation) or time.monotonic() >= until:
                    return observation
                time.sleep(.15)

        seed(repo, 9, 'primary')
        seed(replacement, 3, 'replacement')
        alternate_head = git(replacement, 'rev-parse', 'HEAD')
        alternate_count = int(git(replacement, 'rev-list', '--count', 'HEAD'))
        identity = json.loads(cli('--json', 'init', '--repo', repo, '--name', 'Watch review'))
        project = identity['project']['id']
        up = [str(image), '--home', str(state), '--json', 'up', '--foreground']
        with log.open('wb') as stdout, errors.open('wb') as stderr:
            child = subprocess.Popen(up, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        ready = False
        try:
            until = time.monotonic() + 30
            while time.monotonic() < until and child.poll() is None:
                lines = log.read_bytes().splitlines()
                if lines and lines[0].endswith(b'}'):
                    assert json.loads(lines[0])['process']['pid'] == child.pid
                    ready = True
                    break
                time.sleep(.05)
            assert ready, errors.read_text(errors='replace')
            first = wait_for(watched)
            report['observed']['initial'] = first
            assert watched(first), first
            assert first['git']['commits'] == int(git(repo, 'rev-list', '--count', 'HEAD')) == 9
            assert not first['git']['uncommitted']

            time.sleep(5)
            idle = status()
            plain = cli('--project', project, 'status')
            report['observed']['idle'] = idle
            report['observed']['idle_label'] = next(line for line in plain.splitlines() if 'last reconciled' in line)
            assert watched(idle) and idle['git']['observation']['age_seconds'] >= 4, idle
            assert idle['git']['observation']['reconciled_at'] == first['git']['observation']['reconciled_at'], idle
            label = report['observed']['idle_label'].lower()
            assert 'watched' in label and re.search(r'\(\d+s ago\)', label) and 'proven' not in label, label
            report['checks']['idle_basis_and_age'] = True

            path = repo / 'tracked.txt'
            original = path.read_bytes()
            with path.open('ab', buffering=0) as writer:
                writer.write(b'live edit\n')
                forced = status('--fresh')
                report['observed']['fresh_open_writer'] = forced
                assert not watched(forced) and forced['git']['uncommitted'] is True, forced
                os.fsync(writer.fileno())
                dirty = wait_for(lambda row: watched(row) and row['git'].get('uncommitted') is True)
                report['observed']['watched_open_writer'] = dirty
                assert watched(dirty) and dirty['git']['uncommitted'] and not writer.closed, dirty
            path.write_bytes(original)
            clean = wait_for(lambda row: watched(row) and row['git'].get('uncommitted') is False)
            assert watched(clean) and clean['git']['uncommitted'] is False, clean
            report['checks']['fresh_and_incremental_edit'] = True

            untracked = repo / 'untracked.txt'
            untracked.write_text('untracked control\n', encoding='utf-8')
            dirty = wait_for(lambda row: watched(row) and row['git'].get('uncommitted') is True)
            assert watched(dirty) and dirty['git']['uncommitted'], dirty
            override = {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'status.showUntrackedFiles',
                        'GIT_CONFIG_VALUE_0': 'no'}
            fresh = status(overrides=override)
            report['observed']['environment_fallback'] = fresh
            assert not watched(fresh) and fresh['git']['uncommitted'] is False, fresh
            untracked.unlink()
            report['checks']['environment_fallback'] = True

            git(repo, 'commit', '--allow-empty', '-qm', 'advance HEAD')
            expected_head = git(repo, 'rev-parse', 'HEAD')
            expected_count = int(git(repo, 'rev-list', '--count', 'HEAD'))
            advanced = wait_for(lambda row: watched(row) and row['git'].get('head') == expected_head)
            report['observed']['advanced'] = advanced
            assert watched(advanced) and advanced['git']['head'] == expected_head, advanced
            assert advanced['git']['commits'] == expected_count == 10, advanced
            report['checks']['cached_head_count'] = True

            repo.rename(root / 'old-root')
            lost = status()
            report['observed']['root_absent'] = lost
            assert not watched(lost), lost
            assert lost['git'].get('head') != expected_head, lost
            replacement.rename(repo)
            forced = status('--fresh')
            report['observed']['replacement_fresh'] = forced
            assert not watched(forced) and forced['git']['head'] == alternate_head, forced
            after = wait_for(lambda row: watched(row) and row['git'].get('head') == alternate_head)
            report['observed']['replacement_watched'] = after
            assert watched(after) and after['git']['head'] == alternate_head, after
            assert after['git']['commits'] == alternate_count == 3 and not after['git']['uncommitted'], after
            report['checks']['root_replacement_and_rearm'] = True
        finally:
            try:
                if ready:
                    stopped = json.loads(cli('--json', 'down'))
                    assert stopped['complete'] and stopped['witness']['state'] == 'witnessed', stopped
                    assert child.wait(timeout=25) == 0
                    assert not (state / 'endpoint.json').exists()
                    report['checks']['cleanup'] = True
            finally:
                if child.poll() is None:
                    assert child.args == up
                    child.terminate()
                    child.wait(timeout=10)
                save()


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2]).resolve())
