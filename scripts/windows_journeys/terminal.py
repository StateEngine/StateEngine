"""Pass literal argv through the existing native pseudoconsole transport."""
import base64
import json
from pathlib import Path
import subprocess
import sys

if __name__ == '__main__':
    if sys.platform != 'win32' or len(sys.argv) < 2:
        raise SystemExit('A native Windows command is required')
    data = base64.b64encode(json.dumps(sys.argv[1:]).encode()).decode()
    raise SystemExit(subprocess.call(['powershell.exe', '-NoLogo', '-NoProfile',
                                     '-NonInteractive', '-File', str(Path(__file__).with_suffix('.ps1')),
                                     '-ArgvBase64', data]))
