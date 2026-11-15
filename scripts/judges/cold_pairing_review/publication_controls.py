"""Execute source-generated publication commands against native private files."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
import base64

emitter, output, side = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
output.mkdir(parents=True)
windows = sys.platform == 'win32'
home = Path.home() if windows else output / 'home'
home.mkdir(exist_ok=True)
namespace = 'se418-' + uuid.uuid4().hex
root = home / namespace
root.mkdir(mode=0o700)
payload = b'private publication content\n' * 4096
digest = hashlib.sha256(payload).hexdigest()
receipt = dict(side=side, platform=sys.platform, cases=[], source_files={})
receipt['scope'] = 'Native verification and publication commands; Windows upload is a synthetic fixture and unchanged receive is recorded separately'


def run(command, folder, label, data=None, env=None):
    argv = command.split() if windows else ['/bin/sh', '-c', command]
    result = subprocess.run(argv, cwd=home, input=data, capture_output=True, env=env, timeout=30)
    row = dict(argv=argv, exit=result.returncode, stdout=result.stdout.decode(), stderr=result.stderr.decode())
    (folder / (label + '.json')).write_text(json.dumps(row, indent=2) + '\n')
    return row


def harden(path):
    if not windows:
        path.chmod(0o700)
        return
    # Test-created paths only. The product commands subsequently verify them.
    inherit = 'ContainerInherit,ObjectInherit' if path.is_dir() else 'None'
    script = "$ErrorActionPreference='Stop';$p=$env:REVIEW_NATIVE_PATH;$a=Get-Acl -LiteralPath $p;$a.SetAccessRuleProtection($true,$false);" \
        "$u=[Security.Principal.WindowsIdentity]::GetCurrent().User;" \
        "$a.SetOwner($u);" \
        "foreach($s in @($u,[Security.Principal.SecurityIdentifier]::new('S-1-5-18')))" \
        "{$a.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,'FullControl','" + inherit + "','None','Allow'))};" \
        "Set-Acl -LiteralPath $p -AclObject $a"
    subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
        env=dict(os.environ, REVIEW_NATIVE_PATH=str(path)), check=True, capture_output=True, timeout=120)


try:
    harden(root)
    if windows:
        # Receive is unchanged by the reviewed delta. Keep its direct native
        # result and a reason-only diagnostic, separately from publication.
        probe = output / 'unchanged-receive'
        probe.mkdir()
        for name in ('original', 'diagnostic'):
            path = (root / ('receive-' + name)).relative_to(home).as_posix()
            commands = json.loads(subprocess.check_output([str(emitter), path, path + '-published', digest, 'windows'], text=True))
            command = commands['receive']
            if name == 'diagnostic':
                script = base64.b64decode(command.split()[-1]).decode('utf-16le')
                needle = 'catch {if ($f) {$f.Dispose()}; exit 1}'
                assert script.count(needle) == 1
                script = script.replace(needle, 'catch {[Console]::Error.WriteLine($_.Exception.ToString()); if ($f) {$f.Dispose()}; exit 1}')
                command = 'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + base64.b64encode(script.encode('utf-16le')).decode()
            run(command, probe, name, payload)
    modes = ('fresh', 'corrupt-upload', 'matching-incumbent', 'corrupt-incumbent', 'warm-match', 'warm-corrupt')
    if not windows:
        modes += ('symlink-incumbent', 'writable-upload')
    else:
        modes += ('foreign-write-upload',)
    for mode in modes:
        folder = output / mode
        folder.mkdir()
        files = root / mode
        files.mkdir(mode=0o700)
        if windows:
            harden(files)
        upload, published = files / 'upload', files / 'se'
        relative_upload, relative_published = (p.relative_to(home).as_posix() for p in (upload, published))
        commands = json.loads(subprocess.check_output([str(emitter), relative_upload, relative_published, digest, 'windows' if windows else 'unix'], text=True))
        (folder / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if windows:
            # A synthetic private upload isolates the changed verify/promote
            # commands from the unchanged receive path's separately kept result.
            upload.write_bytes(payload)
            harden(upload)
            (folder / 'fixture-upload.json').write_text(json.dumps(dict(state='created', bytes=len(payload), sha256=hashlib.sha256(upload.read_bytes()).hexdigest())) + '\n')
        else:
            receive = run(commands['receive'], folder, 'receive', payload)
            assert receive['exit'] == 0
        assert upload.read_bytes() == payload
        if mode == 'corrupt-upload':
            upload.write_bytes(b'wrong upload')
        if mode == 'writable-upload':
            upload.chmod(0o722)
        if mode == 'foreign-write-upload':
            script = "$ErrorActionPreference='Stop';$p=$env:REVIEW_NATIVE_PATH;$a=Get-Acl -LiteralPath $p;$s=[Security.Principal.SecurityIdentifier]::new('S-1-1-0');$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,'WriteData','None','None','Allow'));Set-Acl -LiteralPath $p -AclObject $a"
            subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],env=dict(os.environ,REVIEW_NATIVE_PATH=str(upload)),capture_output=True,check=True,timeout=120)
        if windows:
            script = "$p=$env:REVIEW_NATIVE_PATH;$a=Get-Acl -LiteralPath $p;[pscustomobject]@{home=$HOME;path=$p;user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object{[pscustomobject]@{sid=$_.IdentityReference.Value;rights=$_.FileSystemRights.ToString();kind=$_.AccessControlType.ToString();inherited=$_.IsInherited}})}|ConvertTo-Json -Depth 5"
            observed = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],env=dict(os.environ,REVIEW_NATIVE_PATH=str(upload)),capture_output=True,text=True,check=True,timeout=120)
            (folder / 'fixture-identity.json').write_text(observed.stdout)
        if 'incumbent' in mode or mode.startswith('warm'):
            published.write_bytes(b'incumbent corruption' if 'corrupt' in mode else payload)
            harden(files)
            if not windows:
                published.chmod(0o700)
        if mode == 'symlink-incumbent':
            published.unlink()
            published.symlink_to(upload.name)
        before = published.read_bytes() if published.exists() else None
        env = None
        hash_log = folder / 'hash-reads.txt'
        if not windows:
            import shutil
            wrapper = folder / 'tools'
            wrapper.mkdir()
            original = shutil.which('sha256sum')
            assert original
            tool = wrapper / 'sha256sum'
            tool.write_text('#!' + sys.executable + '\nimport os,sys\nwith open(os.environ["REVIEW_HASH_LOG"],"a") as out:out.write(repr(sys.argv[1:])+"\\n")\nos.execv(' + repr(original) + ',["sha256sum",*sys.argv[1:]])\n')
            tool.chmod(0o700)
            env = dict(os.environ, PATH=str(wrapper) + os.pathsep + os.environ['PATH'], REVIEW_HASH_LOG=str(hash_log))
        expected = mode in ('fresh', 'matching-incumbent', 'warm-match')
        if mode.startswith('warm'):
            final = run(commands['verify_path'], folder, 'warm-verify', env=env)
        elif windows:
            verified = run(commands['verify_upload'], folder, 'verify-upload')
            if verified['exit'] == 0:
                promoted = run(commands['publish'], folder, 'publish')
                final = run(commands['post_promote'] if promoted['exit'] == 0 else commands['verify_path'], folder, 'verify-published')
            else:
                final = verified
            removed = run(commands['remove'], folder, 'remove')
            assert removed['exit'] == 0
        else:
            final = run(commands['transaction'], folder, 'transaction', env=env)
        assert (final['exit'] == 0) == expected, (mode, final)
        if mode == 'fresh':
            assert published.read_bytes() == payload and not upload.exists()
            assert hashlib.sha256(published.read_bytes()).hexdigest() == digest
        if mode == 'symlink-incumbent':
            assert published.is_symlink() and published.readlink() == Path('upload')
        elif 'incumbent' in mode or mode.startswith('warm'):
            assert published.read_bytes() == before, 'Existing path changed'
        if not mode.startswith('warm'):
            assert not upload.exists(), 'Owned upload cleanup incomplete'
        hash_reads = None
        if not windows:
            hash_reads = len(hash_log.read_text().splitlines()) if hash_log.exists() else 0
            wanted = {'fresh': 1 if side == 'head' else 2, 'corrupt-upload': 1, 'matching-incumbent': 2, 'corrupt-incumbent': 2, 'warm-match': 1, 'warm-corrupt': 1, 'symlink-incumbent': 1, 'writable-upload': 0}[mode]
            assert hash_reads == wanted, (mode, hash_reads, wanted)
        receipt['cases'].append(dict(mode=mode, exit=final['exit'], hash_reads=hash_reads, expected_success=expected, passed=True))
    receipt['qualified'] = True
finally:
    # No recursive deletion of an unverified home: remove only our exact namespace.
    import shutil
    shutil.rmtree(root)
    receipt['private_namespace_removed'] = not root.exists()
    (output / 'summary.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt))
