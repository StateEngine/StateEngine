"""Native filesystem consumer; the optional interleaver delegates to the real ln."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys

PAYLOAD = b'synthetic-image-payload\n'
FOREIGN = b'foreign-incumbent-bytes\n'


def snapshot(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'state': 'absent'}
    if stat.S_ISLNK(info.st_mode):
        return {'state': 'link', 'target': os.readlink(path)}
    if stat.S_ISDIR(info.st_mode):
        return {'state': 'directory', 'entries': {
            p.name: snapshot(p) for p in sorted(path.iterdir())}}
    assert stat.S_ISREG(info.st_mode), 'unexpected fixture object'
    return {'state': 'file', 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'mode': stat.S_IMODE(info.st_mode), 'inode': info.st_ino}


def install_incumbent(root, case):
    target, foreign = root / 'cache/se', root / 'foreign'
    if case in ('file', 'matching-file'):
        target.write_bytes(PAYLOAD if case == 'matching-file' else FOREIGN)
        target.chmod(0o700)
    elif case == 'directory':
        target.mkdir(mode=0o700)
        (target / 'unrelated-marker').write_bytes(FOREIGN)
    elif case == 'directory-link':
        foreign.mkdir(mode=0o700, exist_ok=True)
        (foreign / 'unrelated-marker').write_bytes(FOREIGN)
        target.symlink_to(foreign, target_is_directory=True)
    elif case == 'dangling-link':
        target.symlink_to(root / 'absent-target')
    elif case != 'absent':
        raise AssertionError('unknown fixture case ' + case)


def interleave(arguments):
    root, native_ln, *words = arguments
    root = Path(root)
    config = json.loads((root / 'interleave.json').read_text())
    install_incumbent(root, config['case'].removeprefix('race-'))
    witness = {'argv': words, 'incumbent': snapshot(root / 'cache/se'),
               'foreign': snapshot(root / 'foreign')}
    (root / 'at-link.json').write_text(json.dumps(witness))
    # Preserve every argument and use the platform's actual hard-link utility.
    os.execv(native_ln, [native_ln, *words])


def run(options):
    root = options.root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    (root / 'cache').mkdir(mode=0o700)
    upload, target = root / 'cache/se.upload-0123456789abcdef', root / 'cache/se'
    upload.write_bytes(PAYLOAD)
    upload.chmod(0o600)
    native_path = '/usr/bin:/bin:/usr/sbin:/sbin'
    native_ln = shutil.which('ln', path=native_path)
    assert native_ln
    racing = options.case.startswith('race-')
    if not racing:
        install_incumbent(root, options.case)
    before = {'incumbent': snapshot(target), 'foreign': snapshot(root / 'foreign')}
    env = {'PATH': native_path, 'HOME': str(root), 'LANG': 'C', 'TMPDIR': str(root)}
    if racing:
        shim = root / 'tools'
        shim.mkdir(mode=0o700)
        (root / 'interleave.json').write_text(json.dumps({'case': options.case}))
        command = ' '.join(shlex.quote(s) for s in
            [sys.executable, str(Path(__file__).resolve()), '--shim', str(root), native_ln])
        (shim / 'ln').write_text('#!/bin/sh\nexec ' + command + ' "$@"\n')
        (shim / 'ln').chmod(0o700)
        env['PATH'] = str(shim) + ':' + native_path
    output = subprocess.run(['/bin/sh', str(options.command.resolve())], cwd=root,
        env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    if racing:
        before = json.loads((root / 'at-link.json').read_text())
    after = {'incumbent': snapshot(target), 'foreign': snapshot(root / 'foreign')}
    healthy = options.case in ('absent', 'matching-file')
    checks = {'status': (output.returncode == 0) is healthy,
              'upload_removed': snapshot(upload)['state'] == 'absent'}
    if options.case == 'absent':
        checks['exact_published_image'] = (after['incumbent']['state'] == 'file'
            and after['incumbent']['sha256'] == hashlib.sha256(PAYLOAD).hexdigest()
            and after['incumbent']['mode'] == 0o700)
    else:
        checks['incumbent_unchanged'] = before['incumbent'] == after['incumbent']
    checks['foreign_unchanged'] = before['foreign'] == after['foreign']
    result = {'case': options.case, 'platform': sys.platform, 'native_ln': native_ln,
              'exit': output.returncode, 'stdout': output.stdout.decode(),
              'stderr': output.stderr.decode(), 'before': before, 'after': after,
              'checks': checks, 'passed': all(checks.values()),
              'production_script': options.command.read_text()}
    (root / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--shim':
        interleave(sys.argv[2:])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--case', required=True)
        parser.add_argument('--root', type=Path, required=True)
        parser.add_argument('--command', type=Path, required=True)
        raise SystemExit(run(parser.parse_args()))
