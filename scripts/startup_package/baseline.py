"""Reobserve one verified retained package without inventing a second arm."""
import json
import os
from pathlib import Path
import shutil
import sys

from build import digest, save, unpack
from observe import prepare, sample, stop, summary

root, prior = (Path(value).resolve() for value in sys.argv[1:3])
root.mkdir()
build = json.loads((prior / 'build.json').read_text())
archives = list((prior / 'archive').glob('*.tar.gz'))
assert len(archives) == 1
archive = archives[0]
assert digest(archive) == os.environ['STARTUP_ARCHIVE_SHA256']
assert build['source_commit'] == os.environ['STARTUP_BASE_SOURCE']
(root / 'archive').mkdir()
retained = root / 'archive' / archive.name
shutil.copyfile(archive, retained)
image, manifest = unpack(retained, root / 'extracted', build)
image_record = dict(image=str(image), sha256=digest(image), source=build['source_commit'],
    bytes=image.stat().st_size, archive=dict(path=str(retained), sha256=digest(retained)),
    stripping=build['stripping'])
save(root / 'image.json', image_record)
save(root / 'manifest.json', manifest)
save(root / 'build.json', build)
receipt = dict(result='NOT RUN', image=image_record, samples=[], cleanup=[], failures=[],
    scope='One retained cold-hashing baseline package on a new native runner; no before/after performance claim; cached file pages, private homes and no providers',
    timing='Unlogged time to flushed public running JSON; separate logged diagnostic cohort')
active = []


def persist():
    save(root / 'observation.json', receipt)


def close(smoke):
    closed = stop(smoke, 'final-down')
    assert closed['outside'] == []
    assert smoke.home == smoke.output / 'home' and smoke.output.is_relative_to(root)
    assert smoke.home.is_dir() and not smoke.home.is_symlink()
    shutil.rmtree(smoke.home)
    assert not smoke.home.exists()
    receipt['cleanup'].append(dict(output=str(smoke.output), home_removed=True, **closed))
    active.remove(smoke)


try:
    for traced in (False, True):
        fresh_count, restart_count = (100, 101) if not traced else (20, 21)
        for index in range(fresh_count):
            row = dict(condition='fresh', index=index, traced=traced, load_before=os.getloadavg())
            receipt['samples'].append(row)
            smoke = prepare(root / f'fresh-{traced}-{index}', image_record, active)
            row['observation'] = sample(smoke, traced, index)
            close(smoke)
            persist()
        smoke = prepare(root / f'restart-{traced}', image_record, active)
        for index in range(restart_count):
            row = dict(condition='restart', index=index, traced=traced, load_before=os.getloadavg())
            receipt['samples'].append(row)
            row['observation'] = sample(smoke, traced, index)
            persist()
        close(smoke)
except BaseException as error:
    receipt['failures'].append(repr(error))
finally:
    for smoke in list(active):
        try:
            close(smoke)
        except BaseException as error:
            receipt['failures'].append(repr(error))
    if not receipt['failures']:
        receipt['summary'] = {}
        for condition in ('fresh', 'restart'):
            for traced in (False, True):
                rows = [row['observation'] for row in receipt['samples']
                    if row['condition'] == condition and row['traced'] == traced
                    and (condition != 'restart' or row['index'] > 0)]
                receipt['summary'][f'{condition}-traced-{traced}'] = summary(row['ms'] for row in rows)
    receipt['result'] = 'FAIL' if receipt['failures'] else 'OBSERVED'
    persist()
if receipt['failures']:
    raise RuntimeError(str(receipt['failures']))
