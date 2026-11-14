"""Author observation of public status fields on frozen native host images.

A configured agent is never launched. This proves field transport, not an idle
one-session budget or provider journey. Independent review still owns controls.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

from support import prepare, require, save
from observe import close, status


def samples(smoke, pid, side):
    values, bounds = [], []
    for index in range(2):
        started = datetime.now(timezone.utc)
        value = smoke.call(['status'], f'public-resource-sample-{index}')
        ended = datetime.now(timezone.utc)
        runtime = value['runtime']
        require(value['schema'] == 'se.status/v1' and runtime['state'] == 'running'
                and runtime['host'] == 'daemon' and runtime['process']['pid'] == pid,
                'Public status does not name this live standalone host')
        if side == 'base':
            require('resources' not in runtime and 'resources_unavailable' not in runtime,
                    'Plain base no longer reproduces the missing resource fields')
        else:
            sample = runtime.get('resources')
            require(isinstance(sample, dict) and not runtime.get('resources_unavailable'),
                    'Fresh native resource sample is absent or unavailable')
            require(sample['method'] == 'linux:getrusage(RUSAGE_SELF)+/proc/self/statm',
                    'Resource counters have the wrong native scope')
            for field in ('self_voluntary_switches', 'self_involuntary_switches',
                          'cpu_user_us', 'cpu_system_us', 'rss_bytes'):
                require(type(sample.get(field)) is int and sample[field] >= 0,
                        'Resource counter absent, unreadable or not a native integer')
            require(sample['rss_bytes'] > 0, 'Live host RSS is falsely zero')
            sampled = datetime.fromisoformat(sample['sampled_at'].replace('Z', '+00:00'))
            require(started <= sampled <= ended, 'Counter sample is outside this public call')
        values.append(value)
        bounds.append(dict(started_at=started.isoformat(), ended_at=ended.isoformat()))
        time.sleep(.05)
    if side == 'head':
        before, after = [value['runtime']['resources'] for value in values]
        for field in ('self_voluntary_switches', 'self_involuntary_switches',
                      'cpu_user_us', 'cpu_system_us'):
            require(after[field] >= before[field], 'Native host counter regressed')
        require(after['sampled_at'] > before['sampled_at'], 'Public sample did not refresh')
    return dict(values=values, bounds=bounds,
                outcome='missing-fields-reproduced' if side == 'base' else 'fresh-counters-returned')


def condition(output, images, provider):
    directory = output / provider
    directory.mkdir()
    record = dict(provider=provider, exit=1, sources={k: v['source'] for k, v in images.items()},
                  samples={}, identities={}, cleanup={}, process_closure={}, stopped={})
    smokes = {}
    try:
        for side in ('base', 'head'):
            smoke, pid = prepare(directory / side, images[side], provider, False, smokes, side)
            before = status(smoke, pid, False, 'resource-host-before')
            record['samples'][side] = samples(smoke, pid, side)
            after = status(smoke, pid, False, 'resource-host-after')
            require(before == after, 'Native host instance changed during field observation')
            record['identities'][side] = before
        record['exit'] = 0
    except Exception as error:
        record['error'] = str(error)
    finally:
        close(smokes, record)
        for side, smoke in smokes.items():
            if record['cleanup'].get(side, {}).get('complete') is not True:
                continue
            try:
                value = smoke.call(['status'], 'resource-stopped-status')
                runtime = value['runtime']
                require(runtime['state'] == 'stopped' and 'resources' not in runtime
                        and 'resources_unavailable' not in runtime,
                        'Stopped status retained or invented live resource counters')
                record['stopped'][side] = value
                require(smoke.commands.observer.observe() == [],
                        'Read-only stopped status created a persistent process')
            except Exception as error:
                record['exit'] = 1
                record['stopped'][side] = dict(error=str(error))
        save(directory / 'status-resource-observations.json', record)
    return record


def main():
    output = Path(sys.argv[1]).resolve()
    images = json.loads((output / 'images.json').read_text())
    help_rows = {}
    for side, image in images.items():
        require(image['exit'] == 0 and hashlib.sha256(Path(image['image']).read_bytes()).hexdigest()
                == image['sha256'], 'Frozen image or build receipt changed')
        child = subprocess.run([image['image'], 'help', 'status'], capture_output=True,
                               text=True, timeout=30)
        help_rows[side] = dict(exit=child.returncode, stdout=child.stdout, stderr=child.stderr)
        save(output / 'public-status-help.json', help_rows)
        require(child.returncode == 0 and child.stdout.strip(), 'Public status help unavailable')
    result = dict(scope='Author hosted Linux public-consumer probe; fresh standalone hosts; '
                        'configured Claude/Codex agents never launched; no idle/session/provider '
                        'budget qualification; no Windows/macOS or independent review',
                  images=images, observations=[], exit=1)
    for provider in ('claude', 'codex'):
        observed = condition(output, images, provider)
        result['observations'].append(observed)
        save(output / 'result.json', result)
        if any(rows != [] for rows in observed['process_closure'].values()):
            raise RuntimeError('Native cleanup failed; later fixtures were not started')
    result['exit'] = 0 if len(result['observations']) == 2 and all(
        row['exit'] == 0 for row in result['observations']) else 1
    save(output / 'result.json', result)
    raise SystemExit(result['exit'])


if __name__ == '__main__':
    main()
