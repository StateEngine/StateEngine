"""Shared fixtures, exact-child timing and paired statistics for CLI observations.

The first timed call is separate from 200 warm calls per image and condition.
All output validation and process censuses happen outside the measured interval.
Absolute hosted latency does not qualify a different machine's latency budget.
"""
import math
import os
from pathlib import Path
import random
import shutil
import statistics
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness_matrix.flow import Smoke
from harness_matrix.io import require, save

ROUNDS = 200


def load():
    return dict(unix=time.time(), load_average=list(os.getloadavg()),
                cpu_count=os.cpu_count(), io_pressure=Path('/proc/pressure/io').read_text())


def percentile(values, quantile):
    ordered = sorted(values)
    return ordered[math.ceil(quantile * len(ordered)) - 1]


def timed(smoke, arguments):
    argv = list(map(str, [smoke.binary, *arguments, '--home', smoke.state,
                          '--project', smoke.project, '--json']))
    wall_started = time.time_ns()
    started = time.perf_counter_ns()
    child = subprocess.Popen(argv, cwd=smoke.repository, env=smoke.commands.environment,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = None
    try:
        stdout, stderr = child.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        error = 'Public command exceeded 30 seconds'
        current = Path(f'/proc/{child.pid}/cmdline').read_bytes().split(b'\0')[:-1]
        require(current == [os.fsencode(arg) for arg in argv], 'Timed-out command identity differs')
        child.kill()
        stdout, stderr = child.communicate(timeout=5)
    elapsed = (time.perf_counter_ns() - started) / 1e6
    wall_ended = time.time_ns()
    require(abs((wall_ended - wall_started) / 1e6 - elapsed) < 5,
            'Wall clock shifted relative to the monotonic command timer')
    return dict(ms=elapsed, wall_started_ns=wall_started, wall_ended_ns=wall_ended,
                exit=child.returncode, error=error, argv=argv,
                stdout=stdout.decode('utf-8'), stderr=stderr.decode('utf-8'))

def prepare(directory, image, provider, dirty, smokes, side):
    directory.mkdir(mode=0o700)
    smoke = Smoke(directory, None, {'id': provider, 'driver': 'native'},
                  {'provider': provider}, {'PATH': os.environ['PATH']})
    smokes[side] = smoke
    smoke.state = smoke.home / 'stateengine-state'
    smoke.commands.environment['SE_HOME'] = str(smoke.state)
    if side == 'head':
        trace = directory / 'host-phases.log'
        with trace.open('x'):
            pass
        trace.chmod(0o600)
        smoke.commands.environment['SE_HOST_PHASE_PROFILE'] = str(trace.resolve())
    smoke.binary.parent.mkdir(parents=True)
    shutil.copyfile(image['image'], smoke.binary)
    smoke.binary.chmod(0o500)

    def git(args, body=None):
        subprocess.run(['git', '-C', str(smoke.repository), '-c', 'user.name=Measurement',
                        '-c', 'user.email=measurement@example.invalid', *args],
                       input=body, env=smoke.commands.environment, capture_output=True, check=True)

    git(['init', '--initial-branch=feature/measurement'])
    for text in ('first\n', 'second\n'):
        (smoke.repository / 'user.txt').write_text(text)
        git(['add', '--', 'user.txt'])
        git(['commit', '-F', '-', '--', 'user.txt'], b'Preserve measurement work.\n')
    if dirty:
        (smoke.repository / 'user.txt').write_text('uncommitted user work\n')
        (smoke.repository / 'untracked.txt').write_text('untracked user work\n')
    selection = ['--harness', 'probe'] if provider == 'acp' else ['--provider', provider]
    if provider == 'acp':
        smoke.state.mkdir(mode=0o700)
        (smoke.state / 'config.toml').write_text(
            'version = 1\n[harnesses.probe]\ndriver = "acp-stdio"\n'
            'command = "/bin/true"\narguments = ["acp"]\n'
            '[harnesses.probe.permissions.default]\narguments = []\nmode = ""\n'
            '[harnesses.probe.permissions.default.environment]\n')
        (smoke.state / 'config.toml').chmod(0o600)
    smoke.initialization_attempted = True
    profile = smoke.call(['init', '--repo', smoke.repository, '--agent', 'reader-00', *selection],
                         'init', terminal=True, project=False)['profile']
    smoke.project, smoke.agent, smoke.owner = (profile[key] for key in ('project', 'agent_id', 'human_id'))
    started = smoke.call(['up'], 'up', project=False)
    smoke.commands.observer.observe(started['process']['pid'])
    return smoke, started['process']['pid']


def summaries(pairs):
    result = {}
    for side in ('base', 'head'):
        values = [row['samples'][side]['ms'] for row in pairs[1:]]
        result[side] = dict(first_ms=pairs[0]['samples'][side]['ms'], warm_count=len(values),
                            p50_ms=percentile(values, .5), p95_ms=percentile(values, .95),
                            max_ms=max(values), blocks=[])
        for start in range(0, len(values), 50):
            block = values[start:start + 50]
            result[side]['blocks'].append(dict(count=len(block), p95_ms=percentile(block, .95)))
    deltas = [row['samples']['base']['ms'] - row['samples']['head']['ms'] for row in pairs[1:]]
    rng = random.Random(0)
    bootstrap = [statistics.median(rng.choices(deltas, k=len(deltas))) for _ in range(2000)]
    result['comparison'] = dict(
        median_paired_saved_ms=statistics.median(deltas),
        median_paired_bootstrap_95_percent_interval_ms=[percentile(bootstrap, .025),
                                                      percentile(bootstrap, .975)],
        p95_saved_ms=result['base']['p95_ms'] - result['head']['p95_ms'])
    return result
