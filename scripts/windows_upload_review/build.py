"""Build identical reviewer entry points against two exact product revisions."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

BASE = 'e74686227b649d2489568f4034ff787668be093c'
HEAD = '3b68277f87f16e85139bb804db5f9e6f19812ca6'


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    reports = root / 'reports'
    reports.mkdir(exist_ok=True)
    source = Path(__file__).resolve().parents[2]
    overlay = source / 'crates/se-host/tests/windows_upload_review.rs'
    images = {}
    for label, revision in [('base', BASE), ('head', HEAD)]:
        checkout = root / ('source-' + label)
        subprocess.run(['git', 'worktree', 'add', '--detach', str(checkout), revision], check=True)
        actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout, text=True).strip()
        assert actual == revision
        target = root / ('target-' + label)
        shutil.copyfile(overlay, checkout / overlay.relative_to(source))
        env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL='0',
                   CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_BUILD_JOBS='2')
        argv = ['cargo', 'test', '-p', 'se-host', '--all-features', '--locked',
                '--test', 'windows_upload_review', '--no-run', '--message-format=json']
        executable = None
        with (reports / (label + '-build.jsonl')).open('w') as log:
            with (reports / (label + '-build.stderr')).open('w') as err:
                proc = subprocess.Popen(argv, cwd=checkout, env=env, text=True,
                                        stdout=subprocess.PIPE, stderr=err)
                for line in proc.stdout:
                    log.write(line)
                    row = json.loads(line)
                    if row.get('reason') == 'compiler-artifact' and row.get('executable'):
                        executable = row['executable']
                code = proc.wait()
        if code != 0 or executable is None:
            raise RuntimeError(f'{label} build failed: exit {code}')
        binary = root / (label + '.exe')
        shutil.copyfile(executable, binary)
        import hashlib
        images[label] = {'source': actual, 'binary': str(binary),
                         'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                         'review_overlay': str(overlay.relative_to(source)), 'build_exit': code}
        (reports / 'images.json').write_text(json.dumps(images, indent=2))
        # Both copies are already joined; release only this build's owned cache.
        shutil.rmtree(target)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
