"""Private access-only snapshots; credential bytes never enter command evidence."""
import base64
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import time

from harness_matrix.io import digest, require


class Prerequisite(RuntimeError):
    def __init__(self, state, reason):
        super().__init__(reason)
        self.state = state


def present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def plain(path):
    path = Path(path)
    require(path.is_absolute(), 'Credential seed path must be absolute')
    for parent in [path, *path.parents]:
        info = parent.lstat()
        require(not stat.S_ISLNK(info.st_mode)
                and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'Credential paths must contain no links or reparse points')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 65536,
            'Credential seed must be one bounded private file')
    return info


def protect(directory, establish=True):
    require(os.name == 'nt', 'Private Windows seed provisioning requires native Windows')
    path = str(directory).replace("'", "''")
    code = ("$ErrorActionPreference='Stop';$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;"
            "$a=New-Object Security.AccessControl.DirectorySecurity;"
            "$a.SetAccessRuleProtection($true,$false);$a.SetOwner($sid);"
            "foreach($s in @($sid.Value,'S-1-5-18')) {"
            "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
            "[Security.Principal.SecurityIdentifier]::new($s),'FullControl',"
            "'ContainerInherit,ObjectInherit','None','Allow'))};"
            + ("Set-Acl -LiteralPath '" + path + "' -AclObject $a;" if establish else '') +
            "$r=Get-Acl -LiteralPath '" + path + "';"
            "if(-not $r.AreAccessRulesProtected -or "
            "$r.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value)"
            "{throw 'Private DACL readback failed'};"
            "$rules=@($r.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));"
            "if($rules.Count -ne 2){throw 'Private DACL rule count differs'};"
            "$seen=New-Object 'System.Collections.Generic.HashSet[string]';"
            "foreach($rule in $rules){[void]$seen.Add($rule.IdentityReference.Value);"
            "if($rule.IdentityReference.Value -notin @($sid.Value,'S-1-5-18') -or "
            "$rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl' -or "
            "$rule.InheritanceFlags -ne 'ContainerInherit,ObjectInherit' -or "
            "$rule.PropagationFlags -ne 'None' -or $rule.IsInherited){throw 'Private DACL rule differs'}};"
            "if($seen.Count -ne 2){throw 'Private DACL principals differ'}")
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', code],
                            capture_output=True, timeout=30)
    require(result.returncode == 0, 'Private credential directory DACL could not be established')


def without_refresh(value):
    if isinstance(value, dict):
        return {key: without_refresh(item) for key, item in value.items()
                if key.replace('_', '').lower() != 'refreshtoken'}
    if isinstance(value, list):
        return [without_refresh(item) for item in value]
    return value


def expiry(provider, credential):
    if provider == 'claude':
        require(set(credential) == {'oauth_token'}
                and isinstance(credential['oauth_token'], str) and credential['oauth_token'],
                'Claude requires the provider setup-token credential')
        # The provider's opaque setup token exposes no expiry claim.
        return None
    access = credential.get('tokens', {}).get('access_token')
    require(isinstance(access, str) and access, 'Codex access token is absent')
    try:
        part = access.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
        value = claims['exp']
        require(type(value) in (int, float), 'Codex token expiry is unavailable')
        require(math.isfinite(value), 'Codex token expiry is not finite')
        return value
    except (ValueError, KeyError, IndexError):
        raise Prerequisite('UNREADABLE', 'Codex access token has no readable declared expiry') from None


def provision(provider, source, destination):
    """An external native provisioner supplies fresh JSON on stdin, never a login path."""
    require(provider in ('claude', 'codex'), 'Unsupported native credential format')
    require(isinstance(source, dict) and isinstance(source.get('credential'), dict),
            'Provisioning input requires a credential object')
    credential = without_refresh(source['credential'])
    expires = expiry(provider, credential)
    if expires is not None and expires <= time.time():
        raise Prerequisite('EXPIRED', 'Provisioned access token has already expired')
    native = source.get('native', {})
    if provider == 'claude':
        require(native.get('hasCompletedOnboarding') is True, 'Native Claude onboarding is incomplete')
        native = {'hasCompletedOnboarding': True}
    else:
        native = {}
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    protect(destination)
    seed = destination / 'seed.json'
    descriptor = os.open(seed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(dict(schema='se.journey-access-seed/v1', provider=provider, created_at=time.time(),
                       expires_at=expires, credential=credential, native=native), stream)
    return dict(path=str(seed.resolve()), sha256=digest(seed), expires_at=expires)


class Credentials:
    def __init__(self, specification, provider):
        self.path = Path(specification['path'])
        self.identity = plain(self.path)
        protect(self.path.parent, establish=False)
        self.sha256 = digest(self.path)
        require(self.sha256 == specification['sha256'], 'Private seed identity differs')
        self.value = json.loads(self.path.read_text())
        require(self.value.get('schema') == 'se.journey-access-seed/v1'
                and self.value.get('provider') == provider, 'Private seed format or harness differs')
        require(self.value == without_refresh(self.value), 'Private seed contains a refresh token')
        self.expires = expiry(provider, self.value['credential'])
        require(self.expires == self.value['expires_at'], 'Private seed expiry metadata differs')
        created = self.value['created_at']
        require(type(created) in (int, float) and math.isfinite(created), 'Seed creation time is unreadable')
        age = time.time() - created
        if not 0 <= age <= 300:
            raise Prerequisite('STALE', 'Provision a new private access-only seed immediately before this run')
        self.provider, self.target = provider, None
        self.ready()

    def ready(self):
        if self.expires is not None and time.time() >= self.expires:
            raise Prerequisite('EXPIRED', 'Private access token expired; provision a fresh seed and rerun')

    def environment(self):
        self.ready()
        return ({'CLAUDE_CODE_OAUTH_TOKEN': self.value['credential']['oauth_token']}
                if self.provider == 'claude' else {})

    def install(self, home):
        self.ready()
        directory = Path(home) / ('.claude' if self.provider == 'claude' else '.codex')
        directory.mkdir(mode=0o700, exist_ok=True)
        protect(directory)
        if self.provider == 'codex':
            self.target = directory / 'auth.json'
            # Native TokenData requires a string field, even without renewal authority.
            credential = self.value['credential']
            credential = {**credential, 'tokens': {**credential['tokens'], 'refresh_token': ''}}
            descriptor = os.open(self.target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                json.dump(credential, stream)
            info = plain(self.target)
            require((info.st_dev, info.st_ino) != (self.identity.st_dev, self.identity.st_ino),
                    'Private credential copy shares the seed identity')
        if self.provider == 'claude':
            config = Path(home) / '.claude.json'
            value = json.loads(config.read_text()) if config.exists() else {}
            value.update(self.value['native'])
            temporary = config.with_suffix('.json.private')
            with temporary.open('x', encoding='utf-8') as stream:
                json.dump(value, stream)
            temporary.replace(config)

    def close(self):
        current = plain(self.path)
        require((current.st_dev, current.st_ino) == (self.identity.st_dev, self.identity.st_ino)
                and digest(self.path) == self.sha256, 'Private seed was changed during the run')
        if self.target is not None and present(self.target):
            plain(self.target)
            self.target.unlink()
        return dict(seed_identity_unchanged=True, seed_bytes_unchanged=True,
                    private_copy_absent=self.target is None or not present(self.target),
                    refresh_tokens_copied=False,
                    delivery='environment' if self.provider == 'claude' else 'private-file')
