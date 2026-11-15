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


if __name__ == '__main__':
    main()
