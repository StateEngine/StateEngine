"""Real loopback SSH comparisons; failures and fixture cleanup stay separate."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback

from payload import IMAGE, SIZE

HERE = Path(__file__).resolve().parent
PS = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
SSH_DIR = Path(os.environ['SystemRoot']) / 'System32/OpenSSH'
SSH = str(SSH_DIR / 'ssh.exe')


def encoded(script):
    return ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
            base64.b64encode(script.encode('utf-16le')).decode()]


def local_ps(script):
    proc = subprocess.run([PS, *encoded(script)], capture_output=True, timeout=60)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode(errors='replace'))
    return proc.stdout.decode('utf-8-sig').strip()


def process_tree(pid):
    script = r'''$all=@(Get-CimInstance Win32_Process);$ids=@(%d);$rows=@();
do {$changed=$false;foreach($p in $all){if($p.ParentProcessId -in $ids -and $p.ProcessId -notin $ids){$ids+= $p.ProcessId;$changed=$true}}}while($changed);
foreach($p in $all){if($p.ProcessId -in $ids){$rows+=@{pid=$p.ProcessId;created=$p.CreationDate.ToString('o');command=$p.CommandLine}}};
ConvertTo-Json -InputObject $rows -Compress''' % pid
    return json.loads(local_ps(script) or '[]')


def close_exact(pins):
    for pin in reversed(pins):
        pin64 = base64.b64encode(json.dumps(pin).encode()).decode()
        local_ps(r"""$pin=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))|ConvertFrom-Json;
$p=Get-CimInstance Win32_Process -Filter "ProcessId=$($pin.pid)";
if($p){if($p.CreationDate.ToString('o') -ne $pin.created -or $p.CommandLine -ne $pin.command){throw 'process identity changed'};Stop-Process -Id $pin.pid -Force}""" % pin64)


class Review:
    def __init__(self, root):
        self.root = root
        self.out = root / 'reports'
        self.out.mkdir(exist_ok=True)
        self.report = {'qualified': False, 'trials': [], 'commands': [], 'scope':
            'Real hosted Windows SSH upload stage; not full pairing or detached runtime qualification'}

    def save(self):
        (self.out / 'result.json').write_text(json.dumps(self.report, indent=2))

    def run(self, name, argv, limit=60, env=None, stdin=None):
        row = {'name': name, 'argv': argv, 'deadline_seconds': limit}
        self.report['commands'].append(row)
        begin = time.monotonic()
        with (self.out / (name + '.stdout')).open('wb') as stdout:
            with (self.out / (name + '.stderr')).open('wb') as stderr:
                child = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE if stdin is not None
                                         else subprocess.DEVNULL, stdout=stdout, stderr=stderr)
                try:
                    child.communicate(stdin, timeout=limit)
                except subprocess.TimeoutExpired:
                    row['timed_out'] = True
                    # The retained Popen process handle owns the root identity.
                    # Read full command lines before any exact-PID stop.
                    current = process_tree(child.pid) if child.poll() is None else []
                    row['forced_local_closure'] = current
                    close_exact(current)
                    child.wait(timeout=20)
                row.update(exit=child.returncode, elapsed_seconds=time.monotonic()-begin, joined=True)
        self.save()
        return row

    def environment(self, name, mode, shell=None):
        argv = [PS, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                str(HERE / 'environment.ps1'), '-Mode', mode, '-Root', str(self.root)]
        if shell:
            argv += ['-ShellPath', shell]
        row = self.run(name, argv, limit=180)
        if row['exit']:
            raise RuntimeError(name + ' failed; see retained stderr')
        text = (self.out / (name + '.stdout')).read_text(encoding='utf-8-sig').strip()
        return json.loads(text)

    def remote(self, name, script, checked=True):
        command = 'powershell.exe ' + ' '.join(encoded(script))
        row = self.run(name, [SSH, '-T', 'upload-review', command])
        if checked and row['exit']:
            raise RuntimeError(name + ' remote command failed')
        text = (self.out / (name + '.stdout')).read_text(encoding='utf-8-sig').strip()
        return row, text

    def idle(self, name):
        pins = self.environment(name + '-census', 'census')
        for attempt in range(3):
            if not pins:
                return {'absent': True, 'forced': False}
            time.sleep(1)
            pins = self.environment(name + f'-census-{attempt}', 'census')
        result = self.environment(name + '-forced-drain', 'drain')
        if result['after']:
            raise RuntimeError('Synthetic account processes remain after drain')
        return {'absent': True, 'forced': True, 'forced_processes': result['before']}

    def readback(self, name, relative, product):
        # Hashing happens after the timer and over a new SSH session.
        script = r"""$ErrorActionPreference='Stop';$p=Join-Path $HOME '%s';
$files=@();if(Test-Path -LiteralPath $p){$i=Get-Item -LiteralPath $p -Force;
$a=Get-Acl -LiteralPath $p;$files+=@{path=$p;bytes=$i.Length;sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;attributes=$i.Attributes.ToString()}};
$partial=@();$dir=Split-Path $p;if(Test-Path -LiteralPath $dir){$partial=@(Get-ChildItem -LiteralPath $dir -Force|Where-Object Name -like '*.upload-*'|Select-Object Name,Length)};
@{files=$files;partials=$partial;home=$HOME;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}|ConvertTo-Json -Depth 6 -Compress""" % relative
        _, text = self.remote(name, script)
        result = json.loads(text)
        files = result['files']
        result['hash_matches'] = len(files) == 1 and files[0]['bytes'] == SIZE and files[0]['sha256'] == IMAGE
        result['account_owner_matches'] = len(files) == 1 and files[0]['owner'] == result['sid']
        if product:
            result['nonce_cleanup_witnessed'] = len(result['partials']) == 0
        return result

    def reset(self, name, relative):
        # Only the exact cache/file in the fresh synthetic account is owned here.
        target = relative.rsplit('/', 1)[0] if relative.startswith('.stateengine-runtime/') else relative
        script = "$ErrorActionPreference='Stop';$p=Join-Path $HOME '" + target + "';if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p -Force -Recurse};if(Test-Path -LiteralPath $p){throw 'fixture reset failed'};Write-Output 'absent'"
        self.remote(name, script)

    def trials(self):
        images = json.loads((self.out / 'images.json').read_text())
        payload = self.root / 'payload.exe'
        assert payload.stat().st_size == SIZE
        assert hashlib.sha256(payload.read_bytes()).hexdigest() == IMAGE
        self.report.update(images=images, payload_sha256=IMAGE, payload_bytes=SIZE)
        self.report['environment'] = self.environment('setup', 'setup')
        pwsh = shutil.which('pwsh.exe')
        if not pwsh:
            raise RuntimeError('PowerShell 7 is absent')
        self.report['ssh_version'] = subprocess.run([SSH, '-V'], capture_output=True, text=True).stderr
        for shell_label, shell_path, major in [('ps51', PS, 5), ('ps7', pwsh, 7)]:
            self.report[shell_label] = self.environment(shell_label+'-switch', 'shell', shell_path)
            probe = "$v=@{version=$PSVersionTable.PSVersion.ToString();major=$PSVersionTable.PSVersion.Major;home=$HOME;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value};$v|ConvertTo-Json -Compress"
            row = self.run(shell_label+'-default-shell', [SSH, '-T', 'upload-review', probe])
            if row['exit']:
                raise RuntimeError('Real SSH default shell did not start')
            facts = json.loads((self.out/(shell_label+'-default-shell.stdout')).read_text(encoding='utf-8-sig'))
            assert facts['major'] == major
            assert facts['sid'] == self.report['environment']['sid']
            self.report[shell_label]['outside_shell'] = facts
            for label in ['base', 'head', 'scp-default-sftp', 'scp-legacy', 'sftp']:
                name = shell_label + '-' + label
                product = label in images
                relative = '.stateengine-runtime/' + IMAGE + '/se.exe' if product else name+'.bin'
                self.idle(name+'-before')
                self.reset(name+'-reset', relative)
                trial = {'name': name, 'product': product, 'relative': relative}
                self.report['trials'].append(trial)
                if product:
                    output = self.out / name
                    output.mkdir()
                    env = dict(os.environ, UPLOAD_REVIEW_PAYLOAD=str(payload), UPLOAD_REVIEW_OUTPUT=str(output))
                    trial['command'] = self.run(name, [images[label]['binary'], '--exact',
                        'native_first_pairing_upload', '--ignored', '--nocapture'], limit=180, env=env)
                    outcome = output / 'outcome.json'
                    trial['product_outcome'] = json.loads(outcome.read_text()) if outcome.exists() else None
                else:
                    if label.startswith('scp'):
                        argv = [str(SSH_DIR/'scp.exe'), '-B']
                        if label == 'scp-legacy':
                            argv += ['-O']
                        argv += [str(payload), 'upload-review:'+relative]
                        trial['command'] = self.run(name, argv, limit=90)
                    else:
                        batch = self.root / (name+'.batch')
                        batch.write_text('put "'+payload.as_posix()+'" "'+relative+'"\n', encoding='ascii')
                        trial['command'] = self.run(name, [str(SSH_DIR/'sftp.exe'), '-b', str(batch), 'upload-review'], limit=90)
                trial['outside_closure'] = self.idle(name+'-after')
                trial['readback'] = self.readback(name+'-readback', relative, product)
                trial['passed'] = (trial['command']['exit'] == 0 and
                    not trial['command'].get('timed_out') and trial['readback']['hash_matches'] and
                    not trial['outside_closure']['forced'])
                if product:
                    trial['passed'] = (trial['passed'] and trial['product_outcome'] is not None
                        and trial['product_outcome']['passed'] and trial['readback']['account_owner_matches']
                        and trial['readback']['nonce_cleanup_witnessed'])
                self.save()
                self.reset(name+'-remove', relative)
            self.idle(shell_label+'-finished')
        heads = [row for row in self.report['trials'] if row['name'].endswith('-head')]
        bases = [row for row in self.report['trials'] if row['name'].endswith('-base')]
        self.report['head_uploads_passed'] = len(heads) == 2 and all(row['passed'] for row in heads)
        self.report['base_failure_reproduced'] = len(bases) == 2 and all(not row['passed'] for row in bases)
        self.report['qualified'] = self.report['head_uploads_passed'] and self.report['base_failure_reproduced']


def main():
    review = Review(Path(sys.argv[1]).resolve())
    try:
        review.trials()
    except Exception:
        review.report['error'] = traceback.format_exc()
    finally:
        state = review.root / 'private/environment.json'
        if state.exists():
            try:
                review.report['cleanup'] = review.environment('cleanup', 'cleanup')
            except Exception:
                review.report['cleanup_error'] = traceback.format_exc()
                review.report['qualified'] = False
        review.save()
    print(json.dumps({key: review.report.get(key) for key in
        ['qualified','head_uploads_passed','base_failure_reproduced','error','cleanup_error']}, indent=2))
    return 0 if review.report['qualified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
