"""Repeat a frozen package comparison, keeping loader diagnostics separate."""
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from build import digest, save, unpack
from observe import prepare, sample, stop, summary

root, prior = map(lambda value: Path(value).resolve(), sys.argv[1:3])
root.mkdir()
pins = {
    'base': ('3b6fd70af3da4c55b6fc423abf3b24cbff337c84', '9b8772300a694109044215907852ee950c1abcf7f5218c6705bdc142a64e845f'),
    'head': ('a0163c9b3157415aa5d5eca71e7ec063eebc7e07', '4811d936c48bb93bdb4dca433d4eddb0374a40ca266c5bf1c679dac1ab245421'),
}
images, receipts, active = {}, {}, []
ledger, failures = [], []


def persist():
    for side, receipt in receipts.items():
        save(root / side / 'observation.json', receipt)
    save(root / 'paired-receipt.json', dict(order=ledger, failures=failures))


def close(smoke, side):
    closed = stop(smoke, 'final-down')
    assert closed['outside'] == []
    assert smoke.home == smoke.output / 'home' and smoke.output.is_relative_to(root / side)
    assert smoke.home.is_dir() and not smoke.home.is_symlink()
    # Every raw command receipt and phase log lives outside this exact private
    # home. Release its copied executable only after witnessed native closure.
    shutil.rmtree(smoke.home)
    assert not smoke.home.exists()
    receipts[side]['cleanup'].append(dict(output=str(smoke.output), home_removed=True, **closed))
    active.remove((smoke, side))


for side, (source, checksum) in pins.items():
    output = root / side
    output.mkdir()
    archive = next((prior / side / 'archive').glob('*.tar.gz'))
    assert digest(archive) == checksum
    build = json.loads((prior / side / 'build.json').read_text())
    assert build['source_commit'] == source
    (output / 'archive').mkdir()
    retained = output / 'archive' / archive.name
    shutil.copyfile(archive, retained)
    image, manifest = unpack(retained, output / 'extracted', build)
    images[side] = dict(image=str(image), sha256=digest(image), source=source,
        bytes=image.stat().st_size, archive=dict(path=str(retained), sha256=checksum), stripping=build['stripping'])
    save(output / 'image.json', images[side])
    save(output / 'build.json', build)
    save(output / 'manifest.json', manifest)
    receipts[side] = dict(result='NOT RUN', source=source, image=images[side], samples=[], cleanup=[],
        scope='Exact retained unsigned package bytes on a new native runner; alternating pairs, private homes, cached file pages, no providers; unlogged budget cohort separate from diagnostic cohort',
        loader_scope='DYLD_PRINT_STATISTICS applies only to the public CLI; detached child environment is unchanged and does not inherit it')
    for label, argv in (
        ('code-signature', ['/usr/bin/codesign', '-d', '--verbose=4', str(image)]),
        ('extended-attributes', ['/usr/bin/xattr', '-l', str(image)]),
    ):
        result = subprocess.run(argv, capture_output=True, timeout=30)
        save(output / (label + '.json'), dict(argv=argv, exit=result.returncode,
            stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace')))

started = datetime.datetime.now(datetime.timezone.utc)
try:
    for traced in (False, True):
        fresh_count, restart_count = (100, 101) if not traced else (20, 21)
        for index in range(fresh_count):
            for side in (('base', 'head') if index % 2 == 0 else ('head', 'base')):
                row = dict(condition='fresh', index=index, traced=traced)
                receipts[side]['samples'].append(row)
                ledger.append(dict(side=side, **row))
                owned = []
                try:
                    smoke = prepare(root / side / f'fresh-{traced}-{index}', images[side], owned)
                    active.append((smoke, side))
                    if traced:
                        smoke.commands.environment['DYLD_PRINT_STATISTICS'] = '1'
                    row['observation'] = sample(smoke, traced, index)
                    close(smoke, side)
                finally:
                    for smoke in owned:
                        if (smoke, side) not in active and smoke.home.exists():
                            active.append((smoke, side))
                    persist()
        restart = {}
        for side in ('base', 'head'):
            owned = []
            try:
                restart[side] = prepare(root / side / f'restart-{traced}', images[side], owned)
            finally:
                active.extend((smoke, side) for smoke in owned)
            if traced:
                restart[side].commands.environment['DYLD_PRINT_STATISTICS'] = '1'
        for index in range(restart_count):
            for side in (('base', 'head') if index % 2 == 0 else ('head', 'base')):
                row = dict(condition='restart', index=index, traced=traced)
                receipts[side]['samples'].append(row)
                ledger.append(dict(side=side, **row))
                row['observation'] = sample(restart[side], traced, index)
                persist()
        for side in ('base', 'head'):
            close(restart[side], side)
except BaseException as error:
    failures.append(repr(error))
finally:
    for smoke, side in list(active):
        try:
            close(smoke, side)
        except BaseException as error:
            failures.append(repr(error))
    for side in ('base', 'head'):
        receipt = receipts[side]
        if not failures:
            receipt['summary'] = {}
            for condition in ('fresh', 'restart'):
                for traced in (False, True):
                    rows = [x['observation'] for x in receipt['samples'] if x['condition'] == condition and x['traced'] == traced and (condition != 'restart' or x['index'] > 0)]
                    receipt['summary'][f'{condition}-traced-{traced}'] = summary(x['ms'] for x in rows)
        receipt['result'] = 'FAIL' if failures else 'OBSERVED'
    persist()
    # Retain only matching system-policy observations for these private paths.
    # Missing or redacted events cannot establish that assessment cost is zero.
    argv = ['/usr/bin/log', 'show', '--style', 'json', '--start', started.strftime('%Y-%m-%d %H:%M:%S%z'),
        '--predicate', '(process == "syspolicyd" OR process == "amfid" OR process == "taskgated-helper") AND eventMessage CONTAINS "startup-reobserve"']
    with (root / 'system-policy.stdout').open('xb') as out, (root / 'system-policy.stderr').open('xb') as err:
        observed = subprocess.run(argv, stdout=out, stderr=err, timeout=120)
    save(root / 'system-policy.json', dict(argv=argv, exit=observed.returncode,
        qualification='Matching retained OS log events only; no assessment time inferred from absence or privacy redaction'))
if failures:
    raise RuntimeError(str(failures))
