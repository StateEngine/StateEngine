"""Send a dedicated automation token over SSH stdin, with no login-file copies."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import stat


def dedicated_source(sources):
    selected = sources.get("claude")
    if not selected or not Path(selected).is_absolute():
        raise RuntimeError("configure an absolute dedicated automation_tokens.claude file")
    source = Path(selected)
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    if source.resolve(strict=True).is_relative_to(home):
        raise RuntimeError("automation token must be outside the login user's real home")
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
    """Read a dedicated token; never materialize it in the destination home."""
    def __init__(self, journey, sources):
        self.journey = journey
        self.source = dedicated_source(sources)
        self.original = plain(self.source)[1]
        info = self.source.lstat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError("automation token must be an owned private file (mode 600)")
        self.token()  # Validate before any runtime starts; keep no secret in the journal.

    def token(self):
        data, identity = plain(self.source)
        if identity != self.original:
            raise RuntimeError("automation token source changed during the attempt")
        value = data.decode("utf-8").strip()
        if not value or len(value) > 16384 or any(c.isspace() or ord(c) < 33 for c in value):
            raise RuntimeError("automation token must contain one bounded nonempty token")
        return value

    def snapshot(self):
        return {"source": str(self.source), "original": list(self.original)}

    @classmethod
    def restore(cls, journey, value):
        result = cls.__new__(cls)
        result.journey, result.source = journey, Path(value["source"])
        result.original = tuple(value["original"])
        return result

    def scan(self, phase):
        program = '''import json
from pathlib import Path
names=['.claude/.credentials.json','.codex/auth.json']
absent={name:not ((Path.home()/name).exists() or (Path.home()/name).is_symlink()) for name in names}
print(json.dumps({'credential_files_absent':all(absent.values()),'files':absent}))
'''
        result = self.journey.command(self.journey.ssh("python3 -c " + shlex.quote(program)))
        self.journey.record.setdefault("credential_scans", {})[phase] = result
        self.journey.persist()
        if result.get("credential_files_absent") is not True:
            raise RuntimeError("destination has a credential file; no login file may be copied or replaced")

    def stage(self):
        self.scan("before")

    def invoke(self, argv):
        # The only secret transport is stdin. argv and raw command metadata never
        # carry the token, and the destination wrapper writes no credential file.
        program = '''import json,os,sys
request=json.load(sys.stdin)
os.environ['CLAUDE_CODE_OAUTH_TOKEN']=request['token']
os.execv(request['argv'][0],request['argv'])
'''
        return self.journey.command(self.journey.ssh("PATH=" +
            shlex.quote(self.journey.remote_root + "/bin") + ':"$PATH" python3 -c ' + shlex.quote(program)),
            json.dumps({"argv": [str(v) for v in argv], "token": self.token()}).encode())

    def close(self):
        if not self.journey.custody_safe or self.journey.remote_runtime:
            raise RuntimeError("provider-token process custody is unresolved; next run will retry owned cleanup")
        self.scan("after")
        if plain(self.source)[1] != self.original:
            raise RuntimeError("automation token source changed during the attempt")
        self.journey.record["credential_closure"] = {
            "source_inode_unchanged": True, "source_digest_unchanged": True,
            "destination_credential_files_absent": True, "transport": "ssh-stdin/environment"}


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
