"""Observe public startup and the existing opt-in native verification phase."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness_matrix.flow import Smoke
from harness_matrix.io import census, require, save


def prepare(directory, image, smokes):
    directory.mkdir(mode=0o700)
    inherited = dict(os.environ)
    for key in ('SystemRoot', 'windir', 'ComSpec', 'PATHEXT'):
        if key in os.environ:
            inherited[key] = os.environ[key]
    smoke = Smoke(directory, None, {'id': 'claude', 'driver': 'native'}, {'provider': 'claude'},
                  inherited)
    smokes.append(smoke)  # Partial initialization must still receive closure checks.
    smoke.state = smoke.home / 'stateengine-state'
    smoke.commands.environment['SE_HOME'] = str(smoke.state)
    smoke.binary.parent.mkdir(parents=True)
    shutil.copyfile(image['image'], smoke.binary)
    smoke.binary.chmod(0o500)
    with smoke.binary.open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == image['sha256'],
                'Private image differs from verified extracted package')
    subprocess.run(['git', 'init', '--initial-branch=measurement', str(smoke.repository)],
                   env=smoke.commands.environment, capture_output=True, check=True)
    smoke.initialization_attempted = True
    profile = smoke.call(['init', '--repo', smoke.repository, '--name', 'Startup Observation', '--agent', 'main', '--provider', 'claude'],
                         'init', terminal=False, project=False)['profile']
    smoke.project, smoke.agent, smoke.owner = (profile[k] for k in ('project', 'agent_id', 'human_id'))
    require(smoke.commands.observer.observe() == [], 'Initialization left a live process')
    return smoke


def timed(smoke, traced):
    argv = [str(smoke.binary), 'up', '--home', str(smoke.state), '--json', '--no-color']
    env = dict(smoke.commands.environment)
    if traced:
        env['SE_STARTUP_LOG'] = '1'
    if os.environ.get('STARTUP_SYSCALL_TRACE') == '1':
        require(sys.platform == 'linux', 'Syscall diagnostics require Linux')
        from syscalls import capture
        return capture(smoke, argv, env)
    started = time.perf_counter_ns()
    child = subprocess.Popen(argv, cwd=smoke.repository, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = child.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        current = next((r for r in census() if r['pid'] == child.pid), None)
        require(current and str(smoke.binary).casefold() in current['command'].casefold(),
                'Timed-out owned command identity is unreadable or changed')
        child.kill()
        stdout, stderr = child.communicate(timeout=5)
        raise RuntimeError('Public up exceeded 30 seconds: ' + stderr.decode(errors='replace'))
    elapsed = (time.perf_counter_ns() - started) / 1e6
    result = dict(ms=elapsed, exit=child.returncode,
                  stdout=stdout.decode(), stderr=stderr.decode(), traced=traced)
    save(smoke.output / 'last-up.json', result)
    require(child.returncode == 0, 'Public up failed: ' + result['stderr'])
    return result


def stop(smoke, label):
    stopped = smoke.call(['down'], label, project=False)
    require(stopped.get('complete') is True and stopped.get('witness', {}).get('state') == 'witnessed'
            and isinstance(stopped.get('stops'), list)
            and all(row.get('complete') is True for row in stopped['stops']),
            'Down has no complete witnessed closure')
    if os.environ.get('STARTUP_SYSCALL_TRACE') == '1':
        from syscalls import join
        join(smoke)
    outside = smoke.commands.observer.observe()
    require(outside == [], 'Runtime survived witnessed down')
    return dict(down=stopped, outside=outside)


def sample(smoke, traced, number):
    require(smoke.commands.observer.observe() == [], 'A previous runtime is still live')
    before = {p.name for p in smoke.state.glob('runtime-startup-*.log')}
    record = timed(smoke, traced)
    started = json.loads(record['stdout'])
    require(started.get('state') == 'running', 'Up did not report running')
    pid = started['process']['pid']
    processes = smoke.commands.observer.observe(pid)
    record['outside_process'] = next(row for row in processes if row['pid'] == pid)
    public = smoke.call(['status'], 'status')
    require(public['runtime']['process']['pid'] == pid, 'Status rediscovered another runtime')
    record['public_status'] = public['runtime']
    record['memory'] = public['runtime'].get('resources')
    require(isinstance(record['memory'], dict), 'Public host resource snapshot is absent')
    if traced:
        logs = []
        record['startup_logs'] = []
        for path in smoke.state.glob('runtime-startup-*.log'):
            if path.name not in before:
                text = path.read_text()
                retained = smoke.output / f'trace-{number}-{path.name}'
                retained.write_text(text)
                phases = {stage: float(ms) for ms, stage in re.findall(r'^([0-9.]+) ms: (.+)$', text, re.M)}
                record['startup_logs'].append(dict(path=retained.name, phases=phases))
                first = phases.get('Native host executable verification started')
                last = phases.get('Native host executable verification finished')
                if first is not None and last is not None:
                    require(last >= first, 'Native verification clock moved backward')
                    logs.append(dict(path=retained.name, phases=phases, verification_ms=last-first))
        require(len(logs) == 1, 'Expected exactly one new complete native verification trace')
        record['native_verification'] = logs[0]
    record['closure'] = stop(smoke, 'down')
    return record


def summary(rows):
    values = sorted(rows)
    require(bool(values), 'No observations')
    return dict(count=len(values), p50_ms=statistics.median(values),
                p95_ms=values[math.ceil(.95*len(values))-1], max_ms=max(values))


def main(output):
    image = json.loads((output / 'image.json').read_text())
    smokes = []
    receipt = dict(result='NOT RUN', image=image, samples=[], cleanup=[],
        qualification='startup-only observation; cached file pages, not cold disk; no provider launched',
        timing='unlogged public up wall clock; logged diagnostic cohort kept separate',
        verification='existing phase includes native self observation, complete image hashing and peer verification; upper bound on hashing alone',
        memory='host-only RSS/HWM snapshot after up; not continuous or a provider tree peak')
    failure = None
    try:
        diagnostic = os.environ.get('STARTUP_DIAGNOSTIC_ONLY') == '1'
        receipt['syscall_diagnostic'] = os.environ.get('STARTUP_SYSCALL_TRACE') == '1'
        if receipt['syscall_diagnostic']:
            receipt['qualification'] += '; syscall tracing changes timings; localization only, not budget evidence'
        for traced in ((True,) if diagnostic else (False, True)):
            fresh_count, restart_count = (0, 101) if diagnostic else (10, 21) if traced else (10, 101)
            for index in range(fresh_count):
                smoke = prepare(output / f'fresh-{traced}-{index}', image, smokes)
                row = dict(condition='fresh', index=index, traced=traced)
                receipt['samples'].append(row)
                row['observation'] = sample(smoke, traced, index)
                save(output / 'observation.json', receipt)
            smoke = prepare(output / f'restart-{traced}', image, smokes)
            for index in range(restart_count):
                row = dict(condition='restart', index=index, traced=traced)
                receipt['samples'].append(row)
                row['observation'] = sample(smoke, traced, index)
                save(output / 'observation.json', receipt)
        receipt['summary'] = {}
        for condition in ('fresh', 'restart'):
            for traced in (False, True):
                rows = [r['observation'] for r in receipt['samples'] if r['condition'] == condition
                        and r['traced'] == traced and (condition != 'restart' or r['index'] > 0)]
                if not rows:
                    continue
                value = dict(wall=summary(r['ms'] for r in rows))
                if traced:
                    value['native_verification'] = summary(r['native_verification']['verification_ms'] for r in rows)
                    value['median_fraction_of_traced_wall'] = statistics.median(
                        r['native_verification']['verification_ms']/r['ms'] for r in rows)
                receipt['summary'][f'{condition}-traced-{traced}'] = value
    except BaseException as error:
        failure = str(error) or type(error).__name__
    finally:
        # This startup-only fixture never creates a provider. Public down plus
        # an outside empty census closes its complete process population; do not
        # invoke the general smoke cleanup's unrelated provider-stop predicate.
        for smoke in smokes:
            try:
                closure = stop(smoke, 'final-down') if smoke.initialization_attempted else {
                    'outside': smoke.commands.observer.observe()}
                require(closure['outside'] == [], 'Final outside census is not empty')
                receipt['cleanup'].append(dict(home=str(smoke.home), **closure))
            except Exception as error:
                receipt['cleanup'].append(dict(home=str(smoke.home), failure=str(error)))
                failure = failure or 'Final fixture closure failed'
        receipt['result'] = 'FAIL' if failure else 'OBSERVED'
        if failure:
            receipt['failure'] = failure
        save(output / 'observation.json', receipt)
    require(failure is None, failure)
    print(json.dumps(receipt['summary']), flush=True)


if __name__ == '__main__':
    main(Path(sys.argv[1]))
