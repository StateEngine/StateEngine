"""Probe (not a test): what the pinned Claude and Codex CLIs print for the MCP
commands `se init` runs, inside the Windows journey's private-home environment."""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

root = Path(tempfile.mkdtemp(prefix='mcp-probe-'))
home = root / 'home'
for d in ['AppData/Roaming', 'AppData/Local', '.config', '.local/state', '.local/share', '.cache', 'tmp', 'repository']:
    (home / d).mkdir(parents=True, exist_ok=True)
subprocess.run(['git', 'init', '-q', str(home / 'repository')], check=False)
inherited = dict(os.environ)
npm = shutil.which('npm', path=inherited.get('PATH'))
print('npm', npm, flush=True)
r = subprocess.run([npm, 'install', '--global', '@anthropic-ai/claude-code@2.1.326', '@openai/codex@0.169.0'],
                   capture_output=True, text=True, shell=False)
print('npm-install', r.returncode, r.stdout[-400:], r.stderr[-400:], flush=True)
prefix = subprocess.run([npm, 'prefix', '--global'], capture_output=True, text=True).stdout.strip()
print('npm-prefix', prefix, flush=True)
keep = ('PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'OS', 'SYSTEMDRIVE', 'PROGRAMDATA',
        'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_ARCHITEW6432', 'LANG', 'LC_ALL')
env = {k: v for k, v in inherited.items() if k.upper() in keep}
env.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / 'AppData/Roaming'),
           LOCALAPPDATA=str(home / 'AppData/Local'), XDG_CONFIG_HOME=str(home / '.config'),
           XDG_STATE_HOME=str(home / '.local/state'), XDG_DATA_HOME=str(home / '.local/share'),
           XDG_CACHE_HOME=str(home / '.cache'), TMPDIR=str(home / 'tmp'), TMP=str(home / 'tmp'),
           TEMP=str(home / 'tmp'), LANG='C.UTF-8', LC_ALL='C.UTF-8', CODEX_HOME=str(home / '.codex'),
           GIT_CONFIG_GLOBAL=str(home / '.gitconfig'), GIT_CONFIG_NOSYSTEM='1')
(home / '.codex').mkdir(exist_ok=True)
candidates = {}
for name in ('claude', 'codex'):
    found = [p for p in (shutil.which(name, path=env['PATH']), shutil.which(name + '.cmd', path=env['PATH']),
                         shutil.which(name + '.exe', path=env['PATH'])) if p]
    for exe in Path(prefix).rglob(name + '.exe'):
        found.append(str(exe))
    candidates[name] = sorted(set(found))
print('candidates', json.dumps(candidates, indent=1), flush=True)
commands = {'claude': [['mcp', 'get', 'stateengine'], ['--version']],
            'codex': [['mcp', 'list', '--json'], ['--version']]}
for name, paths in candidates.items():
    for path in paths:
        for args in commands[name]:
            try:
                r = subprocess.run([path, *args], cwd=home / 'repository', env=env, capture_output=True,
                                   timeout=90, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                print('MCP_PROBE', json.dumps({'exe': path, 'args': args, 'exit': r.returncode,
                      'stdout': r.stdout.decode('utf-8', 'replace')[:1500],
                      'stderr': r.stderr.decode('utf-8', 'replace')[:1500]}), flush=True)
            except Exception as error:
                print('MCP_PROBE', json.dumps({'exe': path, 'args': args, 'error': repr(error)}), flush=True)
sys.exit(0)
