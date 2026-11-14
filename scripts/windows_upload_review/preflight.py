"""Validate the native SSH fixture before compiling either product revision."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import traceback

from run import PS, SSH, SSH_DIR, Review, local_ps


def main():
    destination = Path(sys.argv[1]).resolve()
    root = destination / 'preflight'
    root.mkdir(parents=True, exist_ok=False)
    review = Review(root)
    review.report['scope'] = 'Fixture preflight only; no product upload or acceptance'
    try:
        os.environ['PATH'] = str(SSH_DIR) + os.pathsep + os.environ['PATH']
        review.report['local_shell'] = json.loads(local_ps(
            "$null=Get-Acl -LiteralPath $env:TEMP;"
            "@{major=$PSVersionTable.PSVersion.Major;security=(Get-Module Microsoft.PowerShell.Security).Path}"
            "|ConvertTo-Json -Compress"))
        assert review.report['local_shell']['major'] == 5
        review.report['environment'] = review.environment('setup', 'setup')
        pwsh = shutil.which('pwsh.exe')
        assert pwsh, 'PowerShell 7 absent'
        payload = root / 'preflight.txt'
        data = b'isolated-native-ssh-preflight\n'
        payload.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        review.report['shells'] = []
        for label, shell, major in [('ps51', PS, 5), ('ps7', pwsh, 7)]:
            switch = review.environment(label+'-switch', 'shell', shell)
            probe = '$PSVersionTable.PSVersion.Major'
            row = review.run(label+'-version', [SSH, '-T', 'upload-review', probe])
            assert row['exit'] == 0
            observed = int((review.out/(label+'-version.stdout')).read_text(encoding='utf-8-sig').strip())
            assert observed == major
            sent = review.run(label+'-sftp', [str(SSH_DIR/'sftp.exe'), '-b', '-', 'upload-review'],
                stdin=('put "'+payload.as_posix()+'" "preflight.bin"\n').encode('ascii'))
            assert sent['exit'] == 0
            _, text = review.remote(label+'-acl-hash',
                "$ErrorActionPreference='Stop';$p=Join-Path $HOME 'preflight.bin';"
                "$a=Get-Acl -LiteralPath $p;"
                "@{sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();"
                "owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;"
                "sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}"
                "|ConvertTo-Json -Compress")
            facts = json.loads(text)
            assert facts['sha256'] == digest and facts['owner'] == facts['sid']
            closure = review.idle(label+'-closure')
            assert not closure['forced']
            review.reset(label+'-remove', 'preflight.bin')
            review.report['shells'].append({'label': label, 'major': observed,
                'switch': switch, 'readback': facts, 'closure': closure})
        review.report['qualified'] = True
    except Exception:
        review.report['error'] = traceback.format_exc()
    finally:
        if (root/'private/environment.json').exists():
            try:
                review.report['cleanup'] = review.environment('cleanup', 'cleanup')
            except Exception:
                review.report['cleanup_error'] = traceback.format_exc()
                review.report['qualified'] = False
        review.save()
        reports = destination / 'reports'
        reports.mkdir(exist_ok=True)
        shutil.copytree(review.out, reports/'preflight')
    print(json.dumps({key: review.report.get(key) for key in
                     ['qualified','error','cleanup_error']}, indent=2))
    return 0 if review.report['qualified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
