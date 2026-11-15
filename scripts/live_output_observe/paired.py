"""Compare two pinned release packages through sequential public output cohorts."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def invoke(script, root, env, log, timeout):
    started = time.monotonic_ns()
    with log.open('xb') as output:
        try:
            result = subprocess.run([sys.executable, '-B', HERE / script, root],
                                    env=env, stdout=output, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False)
            return dict(exit_code=result.returncode, started_ns=started,
                        finished_ns=time.monotonic_ns())
        except subprocess.TimeoutExpired:
            return dict(exit_code=None, failure='Command exceeded its time bound',
                        started_ns=started, finished_ns=time.monotonic_ns())


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=False)
    sources = {arm: os.environ['OUTPUT_' + arm.upper()] for arm in ('base', 'head')}
    if any(not re.fullmatch(r'[0-9a-f]{40}', source) for source in sources.values()):
        raise ValueError('Both arms require exact product revisions')
    if sources['base'] == sources['head']:
        raise ValueError('Comparison revisions must differ')
    ledger = dict(sources=sources, builds={}, cohorts=[], qualified=False,
                  scope='Two native stripped release packages; synthetic provider; sequential cohorts')
    save(root / 'paired.json', ledger)
    blocked = None
    for arm, source in sources.items():
        if blocked:
            ledger['builds'][arm] = dict(exit_code=None, blocked=blocked)
            save(root / 'paired.json', ledger)
            continue
        env = dict(os.environ, MEASURE_SOURCE=source, OUTPUT_BUILD_ONLY='1')
        ledger['builds'][arm] = invoke('build.py', root / arm, env,
                                      root / (arm + '-build.stdout'), 6000)
        if ledger['builds'][arm]['exit_code'] == 0:
            cache = root / arm / 'target'
            if cache.is_symlink():
                raise ValueError('Owned compiler cache unexpectedly became a link')
            shutil.rmtree(cache)
            ledger['builds'][arm]['compiler_cache_removed'] = True
        else:
            blocked = 'Previous build failed; no further work is qualified on this runner'
        save(root / 'paired.json', ledger)
    for phase, delay, order in [('immediate', '0', ('base', 'head')),
                                 ('inflight', '250', ('head', 'base'))]:
        for arm in order:
            row = dict(arm=arm, source=sources[arm], phase=phase, completion_delay_ms=int(delay))
            ledger['cohorts'].append(row)
            if blocked or ledger['builds'][arm]['exit_code'] != 0:
                row['blocked'] = blocked or 'This arm did not build successfully'
                save(root / 'paired.json', ledger)
                continue
            output = root / arm
            if phase == 'inflight':
                output = output / phase
                output.mkdir()
                shutil.copyfile(root / arm / 'image.json', output / 'image.json')
            env = dict(os.environ, OUTPUT_BOTH_COHORTS='0', OUTPUT_RESULT_DELAY_MS=delay)
            row.update(invoke('observe.py', output, env,
                              root / (arm + '-' + phase + '.stdout'), 600))
            result_path = output / 'result.json'
            result = json.loads(result_path.read_text()) if result_path.exists() else None
            row['qualified'] = bool(row['exit_code'] == 0 and result and result['qualified'])
            if not result or result.get('cleanup_errors') or result.get('remaining'):
                blocked = 'Previous cohort has no complete cleanup witness'
            save(root / 'paired.json', ledger)
    ledger['qualified'] = (all(row['exit_code'] == 0 for row in ledger['builds'].values())
                           and all(row.get('qualified') for row in ledger['cohorts']))
    save(root / 'paired.json', ledger)
    if not ledger['qualified']:
        raise SystemExit('Paired observation did not qualify; retain every arm and failure')


if __name__ == '__main__':
    main()
