"""Alternate native package startup cohorts on one runner, with full closures."""
import json
import os
from pathlib import Path
import subprocess
import sys

from build import save
from observe import prepare, sample, stop, summary


def main(root):
    root.mkdir(exist_ok=False)
    arms = ('base', 'head')
    sources = {arm: os.environ['STARTUP_' + arm.upper()] for arm in arms}
    # Release builds are sequential; each keeps its own source and target tree.
    for arm in arms:
        environment = dict(os.environ, MEASURE_SOURCE=sources[arm], STARTUP_BUILD_ONLY='1')
        subprocess.run([sys.executable, '-B', Path(__file__).with_name('build.py'), root/arm],
                       env=environment, check=True, timeout=7200)
    receipts, images = {}, {}
    smokes = {arm: [] for arm in arms}
    failures = {}
    ledger = []
    for arm in arms:
        images[arm] = json.loads((root/arm/'image.json').read_text())
        receipts[arm] = dict(result='NOT RUN', image=images[arm], samples=[], cleanup=[],
            qualification='Startup-only alternating base/head observation on one native runner; cached file pages, not cold disk; no providers',
            timing='Unlogged public up command return; logged diagnostics kept separate; restart index zero excluded',
            source=sources[arm])

    def persist():
        for arm in arms:
            save(root/arm/'observation.json', receipts[arm])
        save(root/'paired-receipt.json', dict(sources=sources, order=ledger, failures=failures))

    def attempt(arm, condition, index, traced, smoke):
        if arm in failures:
            return
        row = dict(condition=condition, index=index, traced=traced)
        receipts[arm]['samples'].append(row)
        ledger.append(dict(arm=arm, condition=condition, index=index, traced=traced))
        try:
            if smoke is None:
                smoke = prepare(root/arm/f'fresh-{traced}-{index}', images[arm], smokes[arm])
            row['observation'] = sample(smoke, traced, index)
        except BaseException as error:
            failures[arm] = str(error) or type(error).__name__
        persist()

    try:
        for traced in (False, True):
            for index in range(10):
                for arm in (arms if index % 2 == 0 else arms[::-1]):
                    attempt(arm, 'fresh', index, traced, None)
            restart = {}
            for arm in arms:
                if arm not in failures:
                    try:
                        restart[arm] = prepare(root/arm/f'restart-{traced}', images[arm], smokes[arm])
                    except BaseException as error:
                        failures[arm] = str(error) or type(error).__name__
            for index in range(21 if traced else 101):
                for arm in (arms if index % 2 == 0 else arms[::-1]):
                    if arm in restart:
                        attempt(arm, 'restart', index, traced, restart[arm])
    finally:
        for arm in arms:
            for smoke in smokes[arm]:
                try:
                    closure = stop(smoke, 'final-down') if smoke.initialization_attempted else {
                        'outside': smoke.commands.observer.observe()}
                    if closure['outside'] != []:
                        raise RuntimeError('Final outside census is not empty')
                    receipts[arm]['cleanup'].append(dict(home=str(smoke.home), **closure))
                except BaseException as error:
                    receipts[arm]['cleanup'].append(dict(home=str(smoke.home), failure=str(error)))
                    failures[arm] = failures.get(arm, 'Final fixture closure failed')
            if arm in failures:
                receipts[arm].update(result='FAIL', failure=failures[arm])
                continue
            receipts[arm]['summary'] = {}
            for condition in ('fresh', 'restart'):
                for traced in (False, True):
                    rows = [r['observation'] for r in receipts[arm]['samples']
                            if r['condition'] == condition and r['traced'] == traced
                            and (condition != 'restart' or r['index'] > 0)]
                    value = dict(wall=summary(r['ms'] for r in rows))
                    if traced:
                        import statistics
                        value['native_verification'] = summary(r['native_verification']['verification_ms'] for r in rows)
                        value['median_fraction_of_traced_wall'] = statistics.median(
                            r['native_verification']['verification_ms']/r['ms'] for r in rows)
                    receipts[arm]['summary'][f'{condition}-traced-{traced}'] = value
            receipts[arm]['result'] = 'OBSERVED'
        persist()
    if failures:
        raise RuntimeError(str(failures))
    print(json.dumps({arm: receipts[arm]['summary'] for arm in arms}), flush=True)


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve())
