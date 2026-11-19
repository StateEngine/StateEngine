"""Measure watched status and idle resource use on a native macOS host."""
import argparse
import json
import math
import os
from pathlib import Path
import subprocess
import time


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(fraction * len(values)) - 1)]


def host_stats(pid):
    completed = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'time=', '-o', 'rss='],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    fields = completed.stdout.decode().split()
    if len(fields) != 2:
        raise RuntimeError('native process accounting was unavailable')
    parts = [float(part) for part in fields[0].split(':')]
    seconds = 0.0
    for part in parts:
        seconds = seconds * 60 + part
    return {'cpu_seconds': seconds, 'resident_bytes': int(fields[1]) * 1024}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.uname().sysname != 'Darwin':
        raise RuntimeError('Native macOS is required')
    image = args.se.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    repository = output / 'repository'
    repository.mkdir()
    home = output / 'home'
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(('GIT_', 'SE_', 'STATEENGINE_', 'CLAUDE', 'CODEX_', 'OPENAI_', 'ANTHROPIC_'))}
    result = {'schema': 'status-watch-measurement/v1', 'result': 'incomplete'}
    child = None
    last_ms = 0.0
    def run(argv, cwd=repository, timeout=90):
        nonlocal last_ms
        started = time.perf_counter_ns()
        completed = subprocess.run([str(value) for value in argv], cwd=cwd, env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=timeout)
        last_ms = (time.perf_counter_ns() - started) / 1_000_000
        if completed.returncode:
            raise RuntimeError(f'command failed ({completed.returncode}): {completed.stderr.decode(errors="replace")[-2000:]}')
        return completed.stdout
    def se(*argv):
        return run([image, '--home', home, '--json', *argv])
    def status(*argv):
        value = json.loads(se('status', *argv))
        return last_ms, value
    try:
        source = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
        shallow = run(['git', '-C', source, 'rev-parse', '--is-shallow-repository'], cwd=output).strip() == b'true'
        if shallow:
            run(['git', '-C', source, 'fetch', '--unshallow', '--no-tags', 'origin'], cwd=output, timeout=300)
        run(['git', 'clone', '--no-hardlinks', '--no-checkout', source, repository], cwd=output, timeout=300)
        run(['git', 'checkout', '-q', 'HEAD'])
        result['tracked_files'] = len(run(['git', 'ls-files', '-z']).split(b'\0')) - 1
        result['git_count_control'] = int(run(['git', 'rev-list', '--count', 'HEAD']).strip())
        se('init', '--repo', repository, '--name', 'Measurement')
        with (output / 'host.stdout').open('wb') as stdout, (output / 'host.stderr').open('wb') as stderr:
            child = subprocess.Popen([str(image), '--home', str(home), '--json', 'up', '--foreground'],
                                     cwd=repository, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        startup = None
        until = time.monotonic() + 90
        while time.monotonic() < until:
            lines = (output / 'host.stdout').read_bytes().splitlines()
            if lines:
                startup = json.loads(lines[0])
                break
            if child.poll() is not None:
                raise RuntimeError('foreground host exited before readiness')
            time.sleep(.05)
        if not startup or startup['process']['pid'] != child.pid:
            raise RuntimeError('foreground host readiness or identity was unavailable')
        watched = None
        for _ in range(160):
            _, value = status()
            git = value.get('project', {}).get('value', {}).get('git') or {}
            if git.get('observation', {}).get('basis') == 'watched':
                watched = git
                break
            time.sleep(.25)
        result['initial_response'] = value
        result['initial_watched'] = watched
        samples = []
        count = 0
        for _ in range(200):
            elapsed, value = status()
            samples.append(elapsed)
            git = value.get('project', {}).get('value', {}).get('git') or {}
            count += git.get('observation', {}).get('basis') == 'watched'
        result['status'] = {'samples': len(samples), 'p50_ms': percentile(samples, .5),
                            'p95_ms': percentile(samples, .95), 'watched_count': count}
        fresh = [status('--fresh')[0] for _ in range(20)]
        result['fresh'] = {'samples': len(fresh), 'p50_ms': percentile(fresh, .5), 'p95_ms': percentile(fresh, .95)}
        before = host_stats(child.pid)
        started = time.monotonic()
        samples = []
        for _ in range(15):
            time.sleep(5)
            samples.append({'seconds': time.monotonic() - started, **host_stats(child.pid)})
        after = host_stats(child.pid)
        result['idle'] = {'seconds': time.monotonic() - started, 'cpu_seconds': after['cpu_seconds'] - before['cpu_seconds'],
                          'before': before, 'after': after, 'samples': samples}
        path = repository / 'crates' / 'se-core' / 'src' / 'lib.rs'
        with path.open('ab') as writer:
            writer.write(b'\n// measurement\n')
            writer.flush()
            seen = []
            for _ in range(20):
                _, value = status()
                git = value.get('project', {}).get('value', {}).get('git') or {}
                seen.append({'dirty': git.get('uncommitted'), 'observation': git.get('observation')})
                if git.get('uncommitted') is True and git.get('observation', {}).get('basis') == 'watched':
                    break
                time.sleep(.25)
            result['open_writer'] = seen
            result['git_during_write'] = run(['git', 'status', '--porcelain=v1', '--', path]).decode(errors='replace')
            _, value = status('--fresh')
            result['fresh_during_write'] = value.get('project', {}).get('value', {}).get('git')
        result['git_after_close'] = run(['git', 'status', '--porcelain=v1', '--', path]).decode(errors='replace')
        _, value = status('--fresh')
        result['fresh_after_close'] = value.get('project', {}).get('value', {}).get('git')
        if not count:
            result['result'] = 'watch_unavailable'
        elif result['git_count_control'] <= 1 or not watched or watched.get('commits') != result['git_count_control']:
            result['result'] = 'history_unproven'
        else:
            result['result'] = 'measured'
    except Exception as error:
        result['error'] = str(error) or type(error).__name__
    finally:
        if child is not None and child.poll() is None:
            try:
                se('down')
                result['host_exit'] = child.wait(timeout=30)
            except Exception as error:
                result['cleanup_error'] = str(error)
                child.terminate()
                child.wait(timeout=30)
        (output / 'results.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result), flush=True)
    return 0 if result['result'] == 'measured' and 'cleanup_error' not in result else 1


if __name__ == '__main__':
    raise SystemExit(main())
