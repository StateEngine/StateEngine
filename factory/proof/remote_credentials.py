"""Copy access-only fixture credentials over SSH and witness their closure."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat


def access_only(value):
    if isinstance(value, dict):
        return {key: access_only(item) for key, item in value.items()
                if key.replace("_", "").lower() != "refreshtoken"}
    if isinstance(value, list):
        return [access_only(item) for item in value]
    return value


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
    def __init__(self, journey, auth_home, sources):
        self.journey, self.originals, self.remote_paths = journey, [], []
        surface = journey.config["surface"]
        relative = ".claude/.credentials.json" if surface == "claude" else ".codex/auth.json"
        source = Path(sources.get(surface, Path(auth_home) / relative))
        data, original = plain(source)
        self.originals.append((source, original))
        files = {relative: access_only(json.loads(data))}
        if surface == "claude":
            config = Path(auth_home) / ".claude.json"
            data, original = plain(config)
            self.originals.append((config, original))
            metadata = access_only(json.loads(data))
            if metadata.get("hasCompletedOnboarding") is not True:
                raise RuntimeError("complete Claude onboarding before scheduling remote journeys")
            files[".claude.json"] = {key: metadata[key] for key in
                ("hasCompletedOnboarding", "lastOnboardingVersion", "oauthAccount") if key in metadata}
        self.files = files
        self.manifest = journey.remote_root + "/credential-copy.json"

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
print(json.dumps({'copied':list(files),'refresh_tokens_copied':False}))
'''
        self.remote_paths = list(self.files)
        self.journey.command(self.journey.ssh("python3 -c " + shlex.quote(program)),
                             json.dumps({"files": self.files, "manifest": self.manifest}).encode())
        self.files = None

    def close(self):
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
            "private_copies_absent": True, "refresh_tokens_copied": False}


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
