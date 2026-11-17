"""Judge the public --yes removal path with ordinary redirected process handles.

The bundle is a development fixture made from the candidate native executable and
its unchanged public scripts, not a release qualification. Installation and
uninstallation both run their real public scripts. No provider is launched.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import traceback


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def observed(path):
    try:
        value = path.lstat()
    except FileNotFoundError:
        return {"state": "absent"}
    if path.is_symlink() or value.st_file_attributes & 1024:
        raise AssertionError("fixture contains a link or reparse point: " + str(path))
    if not path.is_file():
        return {"state": "directory"}
    return {"state": "present", "sha256": digest(path), "bytes": value.st_size}


def user_path():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, kind = winreg.QueryValueEx(key, "Path")
        return {"state": "present", "value": value, "kind": kind}
    except FileNotFoundError:
        return {"state": "absent"}


def main(args):
    assert sys.platform == "win32", "native Windows required"
    args.out.mkdir(parents=True, exist_ok=True)
    report = {"fixture": "candidate native image and public scripts", "passed": False,
              "console_emulation": False, "provider_launched": False, "calls": []}
    root = Path(tempfile.mkdtemp(prefix="se-unattended-review-")).resolve(strict=True)
    report["fixture_directory"] = str(root)
    bundle = root / "archive with spaces"
    bundle.mkdir()
    local = root / "Local AppData"
    local.mkdir()
    home = root / "retained state"
    source = args.repository / "scripts/release"
    shutil.copyfile(args.image, bundle / "se.exe")
    for name in ("install.ps1", "uninstall.ps1"):
        shutil.copyfile(source / name, bundle / name)
    manifest = {"schema": "se.release/v1", "variant": "standalone", "trust": "unsigned",
                "target": "x86_64-pc-windows-msvc", "files": {}}
    for name in ("se.exe", "install.ps1", "uninstall.ps1"):
        path = bundle / name
        manifest["files"][name] = {"sha256": digest(path), "bytes": path.stat().st_size}
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (bundle / "SHA256SUMS").write_text("".join(
        digest(path) + "  " + path.name + "\n" for path in sorted(bundle.iterdir())),
        encoding="utf-8")
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(("SE_", "STATEENGINE_", "CODEX_", "CLAUDE"))}
    environment.update(LOCALAPPDATA=str(local), SE_HOME=str(home))
    # Nextest adds the build output to PATH. A fresh installation must not
    # discover that separate candidate image as an existing installation.
    windows = Path(os.environ["WINDIR"])
    environment["PATH"] = os.pathsep.join(str(path) for path in
        (windows / "System32", windows, windows / "System32/WindowsPowerShell/v1.0"))
    report["fixture_process_path"] = environment["PATH"]
    shell = str(Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    before_path = user_path()
    report.update(image_sha256=digest(args.image), manifest=manifest, path_before=before_path)

    def call(label, command, timeout=180):
        started = time.monotonic()
        child = subprocess.Popen(command, cwd=root, env=environment,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        timed_out = False
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            child.kill()
            stdout, stderr = child.communicate(timeout=30)
        (args.out / (label + ".stdout")).write_bytes(stdout)
        (args.out / (label + ".stderr")).write_bytes(stderr)
        row = {"operation": label, "argv": command, "exit": child.returncode,
               "elapsed_ms": (time.monotonic() - started) * 1000,
               "timed_out": timed_out, "stdin": "closed", "stdout": "pipe", "stderr": "pipe"}
        report["calls"].append(row)
        assert not timed_out, label + " exceeded its finite process deadline"
        return row, stdout, stderr

    try:
        installed, _, install_error = call("install", [shell, "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(bundle / "install.ps1")])
        assert installed["exit"] == 0, "public installation refused: " + install_error.decode(errors="replace")
        image = local / "StateEngine/bin/se.exe"
        record = home / "standalone-install.json"
        plan = json.loads(record.read_bytes())
        report["installation_record"] = plan
        assert plan["schema"] == "stateengine-install/v1"
        files = [Path(item["path"]).resolve(strict=True) for item in plan["files"]]
        assert any(os.path.samefile(image, path) for path in files), "record lacks the installed image"
        assert len(files) == len(set(files)), "record repeats an installed path"
        assert all(path.is_relative_to(root) for path in files), "installation escaped the fresh fixture"
        for item in plan["files"]:
            assert observed(Path(item["path"]))["sha256"] == item["sha256"]
        version, _, _ = call("version", [str(image), "--version"])
        assert version["exit"] == 0, "installed native CLI did not run"
        help_row, help_text, _ = call("help", [str(image), "uninstall", "--help"])
        assert help_row["exit"] == 0 and b"--yes" in help_text, "documented unattended flag missing"
        retained = {home / "synthetic-history.txt": b"Synthetic retained history.\n",
                    home / "synthetic-config.txt": b"Synthetic retained configuration.\n",
                    home / "synthetic-provider-login.txt": b"Synthetic marker only; no credentials.\n",
                    image.parent / "user-work.txt": b"Foreign user work remains.\n"}
        for path, data in retained.items():
            path.write_bytes(data)
        report["retained_before"] = {str(path): observed(path) for path in retained}
        row, stdout, stderr = call("uninstall", [shell, "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(bundle / "uninstall.ps1"),
            "--home", str(home), "--yes", "--json"])
        report["payload_after"] = {str(path): observed(path) for path in files}
        report["record_after"] = observed(record)
        journal = home / "uninstall-helper-cleanup.json"
        report["cleanup_journal_after"] = observed(journal)
        report["retained_after"] = {str(path): observed(path) for path in retained}
        report["path_after"] = user_path()
        report["helper_paths_after"] = [str(path) for directory in (home, local)
            if directory.exists() for path in directory.rglob("*")
            if path.name.startswith((".se-stage-", ".se-uninstall-"))]
        assert row["exit"] == 0, "public uninstall failed: " + (stdout + stderr).decode(errors="replace")
        reply = json.loads(stdout)
        report["completion"] = reply
        assert reply.get("complete") is True, "public script did not report final completion"
        assert all(value["state"] == "absent" for value in report["payload_after"].values())
        assert report["record_after"]["state"] == "absent"
        assert report["cleanup_journal_after"]["state"] == "absent"
        assert not report["helper_paths_after"], "temporary uninstall helpers remain"
        assert report["retained_after"] == report["retained_before"], "retained bytes changed"
        assert report["path_after"] == before_path, "public removal did not restore user PATH"
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        report["traceback"] = traceback.format_exc()
    finally:
        (args.out / "result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if report["passed"]:
        shutil.rmtree(root)
        print("Public unattended uninstall completed; recorded files and helpers absent, user files preserved.")
        return 0
    print("Public unattended uninstall failed; receipts retained at " + str(args.out), file=sys.stderr)
    return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    sys.exit(main(parser.parse_args()))
