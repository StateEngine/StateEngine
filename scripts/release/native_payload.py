"""Publish the verified native runtime for a separately packaged consumer."""
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile


def fingerprint(path):
    with path.open("rb") as stream:
        return {"sha256": hashlib.file_digest(stream, "sha256").hexdigest(),
                "bytes": path.stat().st_size}


def publish(root, metadata, destination):
    """Use only the assembler's verified images and unchanged notice bytes."""
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("native payload output already exists; choose a new directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    binary = "se.exe" if metadata["target"].endswith("windows-msvc") else "se"
    with tempfile.TemporaryDirectory(prefix=".se-payload-", dir=destination.parent) as scratch:
        staged = Path(scratch) / "payload"
        staged.mkdir()
        for name in (binary, "build.json", "notices.tar", "NOTICE.txt"):
            shutil.copyfile(root / name, staged / name)
        with tarfile.open(root / "notices.tar") as notices:
            with notices.extractfile("notices/stateengine/LICENSE") as license_file:
                (staged / "LICENSE").write_bytes(license_file.read())
        if (root / "remote-images").is_dir():
            shutil.copytree(root / "remote-images", staged / "remote-images")
        if binary == "se":
            (staged / binary).chmod(0o755)
        files = {path.relative_to(staged).as_posix(): fingerprint(path)
                 for path in sorted(staged.rglob("*")) if path.is_file()}
        document = {"schema": "stateengine.native-payload/v1", "name": "stateengine",
                    "runtime": "rust-embedded", "version": metadata["version"],
                    "target": metadata["target"], "source_commit": metadata["source_commit"],
                    "entry": binary, "license_path": "LICENSE", "notices_path": "notices.tar",
                    "files": files}
        manifest = staged / "native-payload.json"
        manifest.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pin = {"manifest_sha256": fingerprint(manifest)["sha256"],
               "version": metadata["version"], "source_commit": metadata["source_commit"]}
        staged.rename(destination)
    return {"directory": str(destination), "target": metadata["target"], **pin}
