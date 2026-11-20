"""Probe (not a test): run the branch's real `se init` on Windows in the journey's
private-home environment, with the pinned Claude and Codex installed, and print
its full output, which names the refused harness command."""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

workspace = Path(sys.argv[1])
se = next((p for p in [workspace / 'target/release/se.exe', workspace / 'target/x86_64-pc-windows-msvc/release/se.exe'] if p.exists()), None)
print('se', se, flush=True)
inherited = dict(os.environ)
npm = shutil.which('npm', path=inherited.get('PATH'))
r = subprocess.run([npm, 'install', '--global', '@anthropic-ai/claude-code@2.1.326', '@openai/codex@0.169.0'],
                   capture_output=True, text=True)
print('npm-install', r.returncode, flush=True)
keep = ('PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'OS', 'SYSTEMDRIVE', 'PROGRAMDATA',
        'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_ARCHITEW6432', 'LANG', 'LC_ALL')
root = Path(tempfile.mkdtemp(prefix='se-init-probe-'))
for provider in ('claude', 'codex'):
    home = root / provider
    for d in ['AppData/Roaming', 'AppData/Local/StateEngine/bin', '.config', '.local/state', '.local/share',
              '.cache', 'tmp', 'repository', '.codex']:
        (home / d).mkdir(parents=True, exist_ok=True)
    shutil.copy2(se, home / 'AppData/Local/StateEngine/bin/se.exe')
    env = {k: v for k, v in inherited.items() if k.upper() in keep}
    env.update(HOME=str(home), USERPROFILE=str(home), SE_HOME=str(home / 'state'),
               PATH=str(home / 'AppData/Local/StateEngine/bin') + os.pathsep + inherited.get('PATH', ''),
               APPDATA=str(home / 'AppData/Roaming'), LOCALAPPDATA=str(home / 'AppData/Local'),
               XDG_CONFIG_HOME=str(home / '.config'), XDG_STATE_HOME=str(home / '.local/state'),
               XDG_DATA_HOME=str(home / '.local/share'), XDG_CACHE_HOME=str(home / '.cache'),
               TMPDIR=str(home / 'tmp'), TMP=str(home / 'tmp'), TEMP=str(home / 'tmp'),
               LANG='C.UTF-8', LC_ALL='C.UTF-8', CODEX_HOME=str(home / '.codex'),
               GIT_CONFIG_GLOBAL=str(home / '.gitconfig'), GIT_CONFIG_NOSYSTEM='1', GIT_OPTIONAL_LOCKS='0')
    (home / '.gitconfig').write_text('[user]\n\tname = Probe\n\temail = probe@example.invalid\n')
    subprocess.run(['git', 'init', '-q', str(home / 'repository')], env=env, check=False)
    exe = str(home / 'AppData/Local/StateEngine/bin/se.exe')
    r = subprocess.run([exe, 'init', '--repo', str(home / 'repository'), '--agent', 'main', '--provider', provider,
                        '--home', str(home / 'state'), '--json', '--no-color'],
                       cwd=home, env=env, capture_output=True, timeout=300)
    print('SE_INIT', json.dumps({'provider': provider, 'exit': r.returncode,
          'stdout': r.stdout.decode('utf-8', 'replace')[-3000:], 'stderr': r.stderr.decode('utf-8', 'replace')[-2000:]}), flush=True)
claude = next(Path(npm).parent.rglob('claude-code/bin/claude.exe'), None)
if claude:
    verbatim = '\\\\?\\' + str(claude.resolve())
    for path in (str(claude), verbatim):
        r = subprocess.run([path, 'mcp', 'get', 'stateengine'], cwd=root, capture_output=True, timeout=120)
        print('VERBATIM', json.dumps({'exe': path, 'exit': r.returncode, 'stdout': r.stdout.decode('utf-8', 'replace')[:600],
              'stderr': r.stderr.decode('utf-8', 'replace')[:600]}), flush=True)
sys.exit(0)
