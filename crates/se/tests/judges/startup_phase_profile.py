"""Development diagnosis using existing opt-in startup logs; no provider launch."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

import psutil


def execute(command, env, cwd, timeout):
    child = subprocess.Popen(command, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if child.poll() is None:
            actual = psutil.Process(child.pid).cmdline()
            if actual != command:
                raise RuntimeError(('timed-out command changed; retained without signal', child.pid, actual))
            child.kill()
        child.communicate(timeout=10)
        raise
    return subprocess.CompletedProcess(command, child.returncode, out, err)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix='se-startup-profile-'))
    home, repo, owner = root/'state', root/'repo', root/'owner'
    repo.mkdir()
    owner.mkdir(mode=0o700)
    image = root/('se.exe' if os.name == 'nt' else 'se')
    shutil.copyfile(args.se.resolve(strict=True), image)
    image.chmod(0o700)
    denied = ('SE_', 'STATEENGINE_', 'SECODE_', 'CODEX_', 'CLAUDE', 'OPENAI_',
              'ANTHROPIC_', 'GH_', 'GITHUB_', 'ACTIONS_', 'RUNNER_')
    env = {k: v for k, v in os.environ.items() if not k.startswith(denied)}
    env.update(HOME=str(owner), USERPROFILE=str(owner), SE_STARTUP_LOG='1')
    report = {'schema': 'se.startup-profile/v1', 'complete': False, 'root': str(root),
              'calls': [], 'phases': [], 'pins': [], 'removed': False,
              'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
              'limitations': ['diagnostic logging enabled; not a budget acceptance run',
                              'fresh initialized home, OS cache coldness unverified',
                              'no provider launch or real credentials']}
    live = False

    def save():
        (output/'result.json').write_text(json.dumps(report, indent=2)+'\n')

    def call(*argv):
        command = [str(image), '--json', '--home', str(home), *map(str, argv)]
        started = time.perf_counter_ns()
        value = execute(command, env, repo, 45)
        elapsed = (time.perf_counter_ns()-started)/1_000_000
        stem = output/f'call-{len(report["calls"])+1:02}'
        stem.with_suffix('.stdout').write_bytes(value.stdout)
        stem.with_suffix('.stderr').write_bytes(value.stderr)
        report['calls'].append({'argv': list(argv), 'elapsed_ms': elapsed, 'exit': value.returncode})
        save()
        assert value.returncode == 0, (argv, value.stderr.decode(errors='replace'))
        return json.loads(value.stdout)

    try:
        execute(['git', 'init', '--quiet', str(repo)], env, repo, 15).check_returncode()
        call('--key', str(uuid.uuid4()), 'init', '--repo', str(repo), '--name', 'Startup',
             '--agent', 'Probe', '--provider', 'claude', '--model', 'claude-sonnet-5-5')
        for phase in ('fresh', 'warm'):
            # Even a failed up can leave startup custody; retain the home unless down proves closure.
            live = True
            old_logs = {entry.name for entry in home.glob('runtime-startup-*.log')}
            ready = call('up')
            assert ready['state'] == 'running'
            pid = ready['process']['pid']
            process = psutil.Process(pid)
            pin = {'pid': pid, 'birth': process.create_time(), 'image': process.exe(),
                   'argv': process.cmdline(), 'phase': phase}
            assert Path(pin['image']).resolve(strict=True) == image.resolve(strict=True)
            assert any('--stateengine-private-runtime-bootstrap' == a for a in pin['argv'])
            report['pins'].append(pin)
            logs = output/phase
            logs.mkdir()
            for entry in sorted(home.glob('runtime-startup-*.log')):
                if entry.name in old_logs:
                    continue
                assert entry.is_file() and not entry.is_symlink()
                shutil.copyfile(entry, logs/entry.name)
                report['phases'].append({'cohort': phase, 'file': entry.name,
                                         'text': entry.read_text()})
            assert list(logs.iterdir()), 'opt-in startup timing logs absent'
            stopped = call('down')
            assert stopped['complete'] and stopped['witness']['state'] == 'witnessed'
            try:
                remaining = psutil.Process(pid)
                assert remaining.create_time() != pin['birth'], 'original host remains'
            except psutil.NoSuchProcess:
                pass
            assert not (home/'endpoint.json').exists()
            live = False
            report['pins'][-1]['outside_absent'] = True
            save()
        report['complete'] = True
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        if live:
            try:
                report['cleanup'] = call('down')
            except BaseException as error:
                report['cleanup_error'] = repr(error)
        if report['complete']:
            shutil.rmtree(root)
            report['removed'] = True
        save()


if __name__ == '__main__':
    main()
