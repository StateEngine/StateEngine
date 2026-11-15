"""Observe public agent-list latency from a verified stripped native package.

Author performance observation, not an independent correctness judge.
"""
import ctypes
import hashlib
import json
import math
from pathlib import Path
import statistics
import subprocess
import sys

from support import ROUNDS, close, load, prepare, require, save, status, timed, validate


def summary(samples):
    values = sorted(row['ms'] for row in samples[1:])
    return dict(first_timed_ms=samples[0]['ms'], count=len(values),
                p50_ms=statistics.median(values), p95_ms=values[math.ceil(.95*len(values))-1],
                max_ms=max(values), blocks=[
                    dict(count=len(block), p95_ms=sorted(block)[math.ceil(.95*len(block))-1])
                    for offset in range(0, len(samples)-1, 50)
                    if (block := [row['ms'] for row in samples[1:]][offset:offset+50])])


def condition(output, image, provider, dirty, count):
    directory = output / (provider + '-' + str(count) + '-' + ('dirty' if dirty else 'clean'))
    directory.mkdir()
    record = dict(provider=provider, count=count, dirty=dirty, exit=1, load_before=load(),
                  source=image['source'], samples=[], cleanup={}, process_closure={})
    smokes = {}
    try:
        smoke, pid = prepare(directory / 'package', image, provider, dirty, smokes, 'package', count)
        record['identity_before'] = status(smoke, pid, dirty, count, 'host-before')
        initial = smoke.call(['agent', 'list'], 'initial-list')
        saved = {row['name']: row['id'] for row in initial['items']}
        require(saved.get('reader-00') == smoke.agent, 'Initial saved identity changed')
        record['saved_ids'] = saved
        for index in range(ROUNDS + 1):
            sample = timed(smoke, ['agent', 'list'])
            record['samples'].append(dict(index=index, **sample))
            if index % 25 == 0:
                save(directory / 'samples.json', record)
        for sample in record['samples']:
            validate(sample, smoke, count, provider, saved)
        record['identity_after'] = status(smoke, pid, dirty, count, 'host-after')
        require(record['identity_after'] == record['identity_before'],
                'Serving host changed during timing')
        record['summary'] = summary(record['samples'])
        record['exit'] = 0
    except Exception as error:
        record['error'] = str(error)
    finally:
        close(smokes, record)
        record['load_after'] = load()
        save(directory / 'samples.json', record)
    return {key: value for key, value in record.items() if key != 'samples'}


def main():
    output = Path(sys.argv[1]).resolve()
    image = json.loads((output / 'image.json').read_text())
    with Path(image['image']).open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == image['sha256'],
                'Verified package image changed')
    help_row = subprocess.run([image['image'], 'help', 'agent', 'list'], capture_output=True,
                              text=True, timeout=30)
    save(output / 'public-help.json', dict(exit=help_row.returncode,
                                         stdout=help_row.stdout, stderr=help_row.stderr))
    require(help_row.returncode == 0 and help_row.stdout.strip(), 'Agent-list help is unavailable')
    observations = output / 'observations'
    observations.mkdir()
    result = dict(result='NOT RUN', exit=1, image=image, cohorts=[], budget_ms=20,
        scope='native runner; verified stripped full-LTO native-only package; '
              'configured providers never launched; no installer, remote, active provider or MCP timing qualification',
        method='public CLI spawn through pipe EOF and exact-child join; first timed call separate '
               f'from {ROUNDS} warm calls per cohort; one and ten saved agents across provider and '
               'clean/dirty repository cohorts; output and outside identity/closure validation off timer',
        historical='same cohort setup as the earlier development-build observation; this is an '
                   'absolute current-package measurement, not a paired optimization comparison')
    for provider in ('claude', 'codex', 'acp'):
        for dirty in (False, True):
            for count in (1, 10):
                row = condition(observations, image, provider, dirty, count)
                result['cohorts'].append(row)
                save(output / 'result.json', result)
                print(json.dumps(row), flush=True)
                require(all(value == [] for value in row['process_closure'].values()),
                        'Process closure failed; later fixtures were not started')
    result['exit'] = 0 if len(result['cohorts']) == 12 and all(
        row['exit'] == 0 for row in result['cohorts']) else 1
    result['result'] = 'OBSERVED' if result['exit'] == 0 else 'FAIL'
    result['all_cohorts_within_budget'] = result['exit'] == 0 and all(
        row['summary']['p95_ms'] <= result['budget_ms'] for row in result['cohorts'])
    save(output / 'result.json', result)
    raise SystemExit(result['exit'])


if __name__ == '__main__':
    if sys.platform == 'linux':
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0):
            raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
    main()
