"""Copy access-only fixture credentials over SSH and witness their closure."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import stat


def access_only(value, surface):
    """Only documented access fields may cross into the disposable account."""
    if surface == "claude":
        oauth = value["claudeAiOauth"]
        if not isinstance(oauth.get("accessToken"), str) or not oauth["accessToken"]:
            raise RuntimeError("dedicated Claude credential has no access token")
        return {"claudeAiOauth": {key: oauth[key] for key in
            ("accessToken", "expiresAt", "scopes", "subscriptionType") if key in oauth}}
    return {key: value[key] for key in ("auth_mode", "OPENAI_API_KEY") if key in value} | {
        "tokens": {key: value.get("tokens", {})[key] for key in
                   ("access_token", "id_token", "account_id") if key in value.get("tokens", {})}}


def dedicated_source(sources, surface):
    selected = sources.get(surface)
    if not selected or not Path(selected).is_absolute():
        raise RuntimeError("configure an absolute dedicated credential_sources." + surface + " file")
    source = Path(selected)
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    if source.resolve(strict=True).is_relative_to(home):
        raise RuntimeError("dedicated provider credential must be outside the login user's real home")
    return source.parent.resolve(strict=True) / source.name


def plain(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024 * 1024:
            raise RuntimeError("provider credential source must be one bounded plain, unlinked file")
        data = stream.read(1024 * 1024 + 1)
    again = path.lstat()
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
            again.st_dev, again.st_ino, again.st_size, again.st_mtime_ns):
        raise RuntimeError("provider credential changed during copy")
    return data, (info.st_dev, info.st_ino, hashlib.sha256(data).hexdigest())


class Credentials:
    def __init__(self, journey, sources):
        self.journey, self.originals, self.remote_paths = journey, [], []
        surface = journey.config["surface"]
        relative = ".claude/.credentials.json" if surface == "claude" else ".codex/auth.json"
        source = dedicated_source(sources, surface)
        data, original = plain(source)
        self.originals.append((source, original))
        files = {relative: access_only(json.loads(data), surface)}
        if surface == "claude":
            files[".claude.json"] = {"hasCompletedOnboarding": True}
        self.files = files
        self.manifest = journey.remote_root + "/credential-copy.json"
        self.refresh_tokens_copied = None

    def snapshot(self):
        return {"originals": [[str(p), list(v)] for p, v in self.originals],
                "remote_paths": self.remote_paths, "manifest": self.manifest,
                "refresh_tokens_copied": self.refresh_tokens_copied}

    @classmethod
    def restore(cls, journey, value):
        result = cls.__new__(cls)
        result.journey = journey
        result.originals = [(Path(p), tuple(v)) for p, v in value["originals"]]
        result.remote_paths, result.manifest = value["remote_paths"], value["manifest"]
        result.refresh_tokens_copied = value["refresh_tokens_copied"]
        result.files = None
        return result

    def stage(self):
        # A dedicated account is locked for this entire attempt. Never replace an
        # unexplained credential left by an interrupted prior run.
        program = '''import json,os,stat,sys
from pathlib import Path
os.umask(0o077)
request=json.load(sys.stdin)
files=request['files']
for name in files:
 p=Path.home()/name
 if p.exists() or p.is_symlink(): raise RuntimeError('fixture credential already exists; inspect prior closure')
with Path(request['manifest']).open('x') as f: json.dump(list(files),f)
for name,value in files.items():
 p=Path.home()/name
 p.parent.mkdir(mode=0o700,exist_ok=True)
 info=p.parent.lstat()
 mask=0o022 if p.parent==Path.home() else 0o077
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & mask:
  raise RuntimeError('unsafe private provider directory')
 with p.open('x') as f: json.dump(value,f)
def refresh(value):
 if isinstance(value,dict): return any('refresh' in k.lower() or refresh(v) for k,v in value.items())
 if isinstance(value,list): return any(refresh(v) for v in value)
 return False
found=any(refresh(json.loads((Path.home()/name).read_text())) for name in files)
print(json.dumps({'copied':list(files),'refresh_tokens_copied':found}))
'''
        self.remote_paths = list(self.files)
        self.journey.persist()  # Intent survives interruption during SSH or the first write.
        result = self.journey.command(self.journey.ssh("python3 -c " + shlex.quote(program)),
                             json.dumps({"files": self.files, "manifest": self.manifest}).encode())
        self.files = None
        self.refresh_tokens_copied = result["refresh_tokens_copied"]
        self.journey.record["credential_scan"] = result
        self.journey.persist()
        if self.refresh_tokens_copied is not False:
            raise RuntimeError("destination credential scan found a refresh key")

    def close(self):
        if not self.journey.custody_safe or self.journey.remote_runtime:
            raise RuntimeError("private credentials retained: original process closure is unproven; next run will retry recovery")
        program = '''import json,sys
from pathlib import Path
request=json.load(sys.stdin)
manifest=Path(request['manifest'])
names=json.loads(manifest.read_text()) if manifest.exists() else []
if names and sorted(names)!=sorted(request['expected']): raise RuntimeError('fixture credential ownership differs')
for name in names:
 p=Path.home()/name
 try: p.unlink()
 except FileNotFoundError: pass
print(json.dumps({'private_copies_absent':all(not (Path.home()/n).exists() for n in names)}))
'''
        result = self.journey.command(self.journey.ssh("python3 -c " + shlex.quote(program)),
                                      json.dumps({"manifest": self.manifest, "expected": self.remote_paths}).encode())
        changed = [str(path) for path, original in self.originals if plain(path)[1] != original]
        if changed or result.get("private_copies_absent") is not True:
            raise RuntimeError("provider credential source or private-copy closure changed")
        self.journey.record["credential_closure"] = {
            "original_inode_unchanged": True, "original_digest_unchanged": True,
            "private_copies_absent": True, "refresh_tokens_copied": self.refresh_tokens_copied}


def provider_binary(surface, config):
    selected = config.get("provider_executable") or shutil.which(surface)
    if selected is None:
        raise RuntimeError("install the native provider executable before scheduling remote journeys")
    path = Path(selected).resolve(strict=True)
    # Copy native executables. A script shim could depend on an unstaged runtime.
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise RuntimeError("remote journey requires the provider's native Linux executable")
    return path
