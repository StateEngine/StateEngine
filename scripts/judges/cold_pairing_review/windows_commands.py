"""Observe exact-source Windows publication commands on product-created files."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


SNAPSHOT = r"""
$ErrorActionPreference='Stop';
$p=$env:REVIEW_NATIVE_PATH;
try {
  $i=Get-Item -LiteralPath $p -Force -ErrorAction Stop;
} catch [System.Management.Automation.ItemNotFoundException] {
  [pscustomobject]@{path=$p;state='absent'} | ConvertTo-Json; exit 0
} catch { [Console]::Error.WriteLine($_.Exception.ToString()); exit 2 }
try {
  $a=Get-Acl -LiteralPath $p -ErrorAction Stop;
  $hash=$null; $bytes=$null;
  if (-not $i.PSIsContainer) {
    $hash=(Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();
    $bytes=$i.Length
  };
  [pscustomobject]@{
    path=$p;state='present';directory=$i.PSIsContainer;attributes=$i.Attributes.ToString();
    user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
    owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;
    protected=$a.AreAccessRulesProtected;sddl=$a.Sddl;bytes=$bytes;sha256=$hash;
    rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
      [pscustomobject]@{sid=$_.IdentityReference.Value;rights=$_.FileSystemRights.ToString();
        kind=$_.AccessControlType.ToString();inherited=$_.IsInherited;
        inheritance=$_.InheritanceFlags.ToString();propagation=$_.PropagationFlags.ToString()}
    })
  } | ConvertTo-Json -Depth 6; exit 0
} catch { [Console]::Error.WriteLine($_.Exception.ToString()); exit 2 }
"""


def main():
    emitter, output, side = Path(sys.argv[1]).resolve(), Path(sys.argv[2]), sys.argv[3]
    assert sys.platform == 'win32', 'This fixture requires native Windows PowerShell'
    output.mkdir(parents=True)
    home = Path(subprocess.check_output(['powershell.exe', '-NoProfile', '-NonInteractive',
                                        '-Command', '[Console]::Write($HOME)'], text=True).strip())
    cache = home / '.stateengine-runtime'
    cache_existed = cache.exists()
    namespace = cache / ('publication-probe-' + uuid.uuid4().hex)
    assert not namespace.exists()
    payload = b'private publication fixture\n' * 4096
    digest = hashlib.sha256(payload).hexdigest()
    receipt = dict(side=side, cases=[], failures=[], qualified=False,
                   scope='Native generated command boundary; no full public CLI journey or latency claim',
                   payload_sha256=digest)

    def commands(upload, published):
        argv = [str(emitter), upload.relative_to(home).as_posix(),
                published.relative_to(home).as_posix(), digest, 'windows']
        return json.loads(subprocess.check_output(argv, text=True, timeout=30))

    def run(command, folder, label, data=None, path=None):
        argv = command.split() if isinstance(command, str) else command
        env = dict(os.environ)
        if path is not None:
            env['REVIEW_NATIVE_PATH'] = str(path)
        result = subprocess.run(argv, cwd=home, input=data, capture_output=True, env=env, timeout=120)
        (folder / (label + '.stdout')).write_bytes(result.stdout)
        (folder / (label + '.stderr')).write_bytes(result.stderr)
        row = dict(argv=argv, exit=result.returncode)
        save(folder / (label + '.json'), row)
        return row

    def snapshot(paths, folder, label):
        rows = {}
        for name, path in paths.items():
            result = run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', SNAPSHOT],
                         folder, label + '-' + name, path=path)
            assert result['exit'] == 0, ('Unreadable snapshot', label, name, result['exit'])
            rows[name] = json.loads((folder / (label + '-' + name + '.stdout')).read_text(encoding='utf-8-sig'))
        save(folder / (label + '.json'), rows)
        return rows

    def receive(path, data, folder, label):
        generated = commands(path, path.with_name(path.name + '-unused'))
        save(folder / (label + '-commands.json'), generated)
        result = run(generated['receive'], folder, label, data)
        assert result['exit'] == 0, ('Product receive failed', label, result['exit'])

    try:
        setup = output / 'prepare'
        setup.mkdir()
        snapshot(dict(home=home, cache=cache, namespace=namespace), setup, 'before')
        prepared = commands(namespace / 'unused-upload', namespace)
        save(setup / 'commands.json', prepared)
        assert run(prepared['prepare'], setup, 'prepare')['exit'] == 0, 'Product directory prepare failed'
        snapshot(dict(home=home, cache=cache, namespace=namespace), setup, 'after')
        for mode in ('fresh', 'corrupt-upload', 'matching-incumbent', 'corrupt-incumbent',
                     'warm-match', 'warm-corrupt', 'foreign-write-upload'):
            folder = output / mode
            folder.mkdir()
            row = dict(mode=mode, passed=False)
            upload, published = namespace / (mode + '-upload'), namespace / (mode + '-published')
            paths = dict(directory=namespace, upload=upload, published=published)
            try:
                generated = commands(upload, published)
                save(folder / 'commands.json', generated)
                snapshot(paths, folder, 'before-receive')
                if not mode.startswith('warm'):
                    receive(upload, b'wrong upload' if mode == 'corrupt-upload' else payload, folder, 'receive-upload')
                if 'incumbent' in mode or mode.startswith('warm'):
                    receive(published, b'wrong incumbent' if 'corrupt' in mode else payload, folder, 'receive-incumbent')
                if mode == 'foreign-write-upload':
                    script = "$ErrorActionPreference='Stop';$p=$env:REVIEW_NATIVE_PATH;$a=Get-Acl -LiteralPath $p;$s=[Security.Principal.SecurityIdentifier]::new('S-1-1-0');$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,'WriteData','None','None','Allow'));Set-Acl -LiteralPath $p -AclObject $a"
                    assert run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                               folder, 'foreign-write-mutation', path=upload)['exit'] == 0
                before = snapshot(paths, folder, 'before-publication')
                if mode.startswith('warm'):
                    final = run(generated['verify_path'], folder, 'warm-verify')
                else:
                    verified = run(generated['verify_upload'], folder, 'verify-upload')
                    if verified['exit'] == 0:
                        promoted = run(generated['publish'], folder, 'publish')
                        row['publish_exit'] = promoted['exit']
                        final = run(generated['post_promote'] if promoted['exit'] == 0 else generated['verify_path'],
                                    folder, 'verify-published')
                    else:
                        final = verified
                after = snapshot(paths, folder, 'after-publication')
                expected = mode in ('fresh', 'matching-incumbent', 'warm-match')
                row.update(exit=final['exit'], expected_success=expected)
                assert (final['exit'] == 0) == expected, ('Unexpected public command outcome', row)
                if mode == 'fresh':
                    assert after['published']['sha256'] == digest and after['upload']['state'] == 'absent'
                    assert row['publish_exit'] == 0
                elif 'incumbent' in mode or mode.startswith('warm'):
                    assert after['published'] == before['published'], 'Incumbent bytes or identity changed'
                    if not mode.startswith('warm'):
                        assert row['publish_exit'] != 0, 'Incumbent unexpectedly replaced'
                else:
                    assert after['published']['state'] == 'absent', 'Refused upload was published'
                row['passed'] = True
            except Exception as error:
                row['error'] = repr(error)
                receipt['failures'].append(dict(mode=mode, error=repr(error)))
            finally:
                cleanup = run(generated['remove'], folder, 'remove-upload')
                closed = snapshot(paths, folder, 'after-upload-cleanup')
                if cleanup['exit'] != 0 or closed['upload']['state'] != 'absent':
                    row['passed'] = False
                    receipt['failures'].append(dict(mode=mode, error='Owned upload cleanup failed'))
                receipt['cases'].append(row)
                save(output / 'summary.json', receipt)
        receipt['qualified'] = len(receipt['cases']) == 7 and not receipt['failures']
    finally:
        # The unique namespace is created only by the product prepare command.
        if namespace.exists():
            assert namespace.parent == cache and not namespace.is_symlink()
            shutil.rmtree(namespace)
        receipt['namespace_removed'] = not namespace.exists()
        if not cache_existed and cache.exists():
            cache.rmdir()  # Refuses if any other work appeared.
        save(output / 'summary.json', receipt)
    assert receipt['qualified'], receipt['failures']


if __name__ == '__main__':
    main()
