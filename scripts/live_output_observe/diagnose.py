"""Rebuild only a diagnostic image after the unmodified packaged observation."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from instrument import apply
from observe import stats


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    base = Path(sys.argv[1]).resolve()
    root = base / 'source'
    diagnostic = base / 'diagnostic'
    diagnostic.mkdir()
    patch = apply(root)
    (diagnostic / 'probe.patch').write_bytes(patch)
    shutil.copyfile(root / 'crates/se-host/src/output_observer.rs', diagnostic / 'output_observer.rs')
    metadata = json.loads((base / 'build.json').read_text())
    sysroot = Path(subprocess.check_output(['rustc', '+' + metadata['toolchain'], '--print', 'sysroot'], text=True).strip())
    cargo_home = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo')).resolve()
    mappings = [(root, '/stateengine/source'), (cargo_home, '/rust/cargo'),
                (sysroot, '/rust/toolchain'), (base / 'target', '/stateengine/target')]
    remaps = [f'--remap-path-prefix={spelling}={replacement}' for prefix, replacement in mappings
              for spelling in sorted({str(prefix), prefix.as_posix()})]
    environment = dict(os.environ, CARGO_TARGET_DIR=str(base / 'target'),
                       RUSTUP_TOOLCHAIN=metadata['toolchain'],
                       CARGO_ENCODED_RUSTFLAGS='\x1f'.join(metadata['rustflags'] + remaps),
                       CARGO_INCREMENTAL='0', RUSTUP_AUTO_INSTALL='0',
                       SOURCE_DATE_EPOCH=str(metadata['source_timestamp']))
    started = time.monotonic()
    argv = ['cargo', *metadata['cargo_config_overrides'], 'build', '--locked', '--jobs', '1',
            '--profile', 'distribution', '--target', metadata['target'], '--no-default-features']
    if metadata['features']:
        argv += ['--features', ','.join(metadata['features'])]
    argv += ['-p', 'se', '--bin', 'se']
    with (diagnostic / 'compile.log').open('wb') as log:
        subprocess.run(argv, cwd=root, env=environment, check=True, stdout=log,
                       stderr=subprocess.STDOUT, timeout=3600)
    image = diagnostic / 'se-diagnostic'
    shutil.copy2(base / 'target' / metadata['target'] / 'distribution/se', image)
    facts = {'image': str(image), 'sha256': digest(image), 'bytes': image.stat().st_size,
             'source': metadata['source_commit'], 'probe_patch_sha256': hashlib.sha256(patch).hexdigest(),
             'probe_helper_sha256': digest(diagnostic / 'output_observer.rs'),
             'compile_seconds': time.monotonic() - started,
             'qualification': 'diagnostic only; opt-in synchronous probes and instrumented source'}
    (diagnostic / 'image.json').write_text(json.dumps(facts, indent=2) + '\n')
    environment['OUTPUT_OBSERVER_TRACE'] = str(diagnostic / 'trace.log')
    subprocess.run([sys.executable, '-B', Path(__file__).with_name('observe.py'), diagnostic],
                   env=environment, check=True, timeout=1200)
    stages = {}
    for line in (diagnostic / 'trace.log').read_text().splitlines():
        stage, marker, us, pid = line.split()
        stages.setdefault(marker, {}).setdefault(stage, []).append(int(us))
    folders = [diagnostic]
    if (diagnostic / 'inflight').exists():
        folders.append(diagnostic / 'inflight')
    for folder in folders:
        summarize(folder, stages, metadata)


def summarize(diagnostic, stages, metadata):
    result = json.loads((diagnostic / 'result.json').read_text())
    serial = ['stream_read', 'transcript_read', 'published', 'watch_page_ready',
              'ipc_response_flushed', 'stdout_flushed']
    intervals, rows = {}, []
    for sample in result['samples']:
        marker = sample['id']
        start = sample['producer']['emit_begin_ns'] // 1000
        observed = {'emit_begin': start}
        for stage in serial + ['capture_ready']:
            times = [t for t in stages.get(marker, {}).get(stage, []) if t >= start]
            if not times:
                raise ValueError('Missing diagnostic stage: ' + marker + '/' + stage)
            observed[stage] = min(times)
        row = {'id': marker, 'warmup': sample['warmup'], 'timestamps_us': observed}
        rows.append(row)
        for before, after in zip(['emit_begin'] + serial, serial):
            duration = (observed[after] - observed[before]) / 1000
            if duration < 0:
                # A callback can enqueue its page before the producer's trailing
                # probe records completion. Keep this overlap explicit.
                row.setdefault('overlaps', []).append(before + '→' + after)
            if not sample['warmup']:
                intervals.setdefault(before + '→' + after, []).append(duration)
    report = {'source': metadata['source_commit'], 'matched': len(rows), 'rows': rows,
              'stages': {stage: stats(values) for stage, values in intervals.items()},
              'qualification': 'Diagnostic synchronous-probe image; only the separate unmodified package qualifies the end-to-end budget'}
    (diagnostic / 'stages.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
