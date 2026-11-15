"""External mutations of a private reviewer fixture, with exact restoration."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

action, path, saved = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
if action in ('loosen', 'restore'):
    if os.name == 'nt':
        script = Path(__file__).with_name('security.ps1')
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
                                 str(script), str(path), str(saved), action], capture_output=True)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
    elif action == 'loosen':
        saved.write_text(str(stat.S_IMODE(path.stat().st_mode)))
        os.chmod(path, stat.S_IMODE(path.stat().st_mode) | 0o044)
        assert stat.S_IMODE(path.stat().st_mode) & 0o044
    else:
        mode = int(saved.read_text())
        os.chmod(path, mode)
        assert stat.S_IMODE(path.stat().st_mode) == mode
elif action == 'swap':
    replacement = path.with_name('replacement.db')
    try:
        path.rename(saved)
    except OSError as error:
        assert os.name == 'nt' and error.winerror in (5, 32), error
        print(json.dumps({'state': 'native-denied', 'winerror': error.winerror}))
        raise SystemExit(0)
    try:
        replacement.rename(path)
    except BaseException:
        saved.rename(path)
        raise
elif action == 'unswap':
    path.rename(path.with_name('replacement.db'))
    saved.rename(path)
elif action == 'link':
    os.link(path, saved)
    assert path.stat().st_nlink == 2
elif action == 'unlink':
    saved.unlink()
    assert path.stat().st_nlink == 1
else:
    raise ValueError('Unknown fixture mutation')
print(json.dumps({'state': 'completed', 'action': action}))
