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
def run(path, args, env, cwd):
    try:
        r = subprocess.run([path, *args], cwd=cwd, env=env, capture_output=True, timeout=120,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return {'exit': r.returncode, 'stdout': r.stdout.decode('utf-8', 'replace')[:1500],
                'stderr': r.stderr.decode('utf-8', 'replace')[:1500]}
    except Exception as error:
        return {'error': repr(error)}

stub_dir = root / 'stub'
stub_dir.mkdir()
(stub_dir / 'se.cmd').write_text('@echo off\r\nexit /b 0\r\n')
sequences = {'claude': [['mcp', 'get', 'stateengine'], ['mcp', 'add', '--scope', 'local', 'stateengine', '--', 'se', '--home', 'HOMESTATE', 'mcp'],
                        ['mcp', 'get', 'stateengine'], ['mcp', 'list']],
             'codex': [['mcp', 'list', '--json'], ['mcp', 'add', 'stateengine', '--', 'se', '--home', 'HOMESTATE', 'mcp'],
                       ['mcp', 'list', '--json']]}
for variant in ('no-se-on-path', 'stub-se-on-path'):
    for name, paths in candidates.items():
        native = [p for p in paths if p.lower().endswith('.exe')]
        if not native:
            continue
        path = native[-1]
        vhome = root / f'{variant}-{name}'
        for d in ['AppData/Roaming', 'AppData/Local', '.codex', 'tmp', 'repository']:
            (vhome / d).mkdir(parents=True, exist_ok=True)
        subprocess.run(['git', 'init', '-q', str(vhome / 'repository')], check=False)
        venv = dict(env)
        venv.update(HOME=str(vhome), USERPROFILE=str(vhome), APPDATA=str(vhome / 'AppData/Roaming'),
                    LOCALAPPDATA=str(vhome / 'AppData/Local'), CODEX_HOME=str(vhome / '.codex'),
                    TMP=str(vhome / 'tmp'), TEMP=str(vhome / 'tmp'), TMPDIR=str(vhome / 'tmp'))
        if variant == 'stub-se-on-path':
            venv['PATH'] = str(stub_dir) + os.pathsep + venv['PATH']
        for args in sequences[name]:
            args = [str(vhome / 'state') if a == 'HOMESTATE' else a for a in args]
            print('MCP_SEQ', json.dumps({'variant': variant, 'exe': path, 'args': args,
                  **run(path, args, venv, vhome / 'repository')}), flush=True)
sys.exit(0)
