"""Judge publication and mail state before a controlled final provider result."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import tarfile
import threading
import time

from mail_cli import Fixture


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def image(package, source, out):
    identity = json.loads((package / "image.json").read_text())
    build = json.loads((package / "build.json").read_text())
    assert identity["source"] == build["source_commit"] == source
    archives = list((package / "archive").glob("*.tar.gz"))
    assert len(archives) == 1 and digest(archives[0]) == identity["archive"]["sha256"]
    with tarfile.open(archives[0], "r:gz") as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            assert not path.is_absolute() and ".." not in path.parts
            assert member.isdir() or member.isfile()
        archive.extractall(out, filter="data")
    manifests = list(out.glob("*/manifest.json"))
    assert len(manifests) == 1
    root = manifests[0].parent
    manifest = json.loads(manifests[0].read_text())
    assert manifest["source_commit"] == source
    for name, record in manifest["files"].items():
        assert digest(root / name) == record["sha256"]
        assert (root / name).stat().st_size == record["bytes"]
    executable = root / "se"
    assert digest(executable) == identity["sha256"] == build["files"]["se"]
    return executable


def native(pid):
    root = Path("/proc") / str(pid)
    try:
        stat = (root / "stat").read_text().rsplit(") ", 1)[1].split()
        return {"pid": pid, "birth": stat[19], "argv": (root / "cmdline").read_bytes().hex()}
    except FileNotFoundError:
        return None


def wait_file(path, seconds=10):
    end = time.monotonic() + seconds
    while not path.exists():
        assert time.monotonic() < end, "provider never reached " + path.name
        time.sleep(.005)


def run(executable, out):
    f = Fixture(executable, out / "fixture", provider_helper=Path(__file__).with_name("claude_live_provider.py"))
    f.env = {k: v for k, v in f.env.items() if k in
             ("HOME", "USERPROFILE", "PATH", "LANG", "SHELL", "TMPDIR") or k.startswith("XDG_")}
    pages, records, threads = queue.Queue(), [], []
    watcher, watcher_identity = None, None
    failure, cleanup = None, []

    def pump(stream, path, output):
        with path.open("wb") as log:
            for line in iter(stream.readline, b""):
                log.write(line)
                log.flush()
                if output:
                    pages.put(line)
        if output:
            pages.put(None)

    def consume(seconds, wanted=None):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                line = pages.get(timeout=max(.001, end - time.monotonic()))
            except queue.Empty:
                break
            assert line is not None, "public watcher exited before the witness"
            page = json.loads(line)
            assert not page.get("reset_required"), page
            records.extend(page.get("records", []))
            if wanted == "initial" and page.get("complete"):
                return True
            for record in page.get("records", []):
                if record.get("type") == "provisional":
                    assert "UNTRUSTED_STREAM_TEXT" not in json.dumps(record)
                    item = record["item"]
                    if item["item_id"] == wanted:
                        assert item["role"] == "assistant" and item["preview"]["text"] == wanted
                        assert item["preview"]["complete"]
                        return True
        return False

    def no_output():
        consume(.25)
        assert not any(row.get("type") == "provisional" and
                       row["item"]["item_id"].startswith("native-live-") for row in records), \
            "foreign or incomplete stream frame published transcript output"

    try:
        f.ok("up")
        f.launch()
        watcher = subprocess.Popen([str(executable), "--home", str(f.home), "--json", "watch",
            "--target", f.project + "/" + f.agent, "--wait-ms", "1000", "--budget", "65536"],
            cwd=f.repo, env=f.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        watcher_identity = native(watcher.pid)
        assert watcher_identity is not None, "owned watcher identity absent"
        for stream, filename, output in [(watcher.stdout, "watch.stdout", True),
                                         (watcher.stderr, "watch.stderr", False)]:
            worker = threading.Thread(target=pump, args=(stream, out / filename, output))
            worker.start()
            threads.append(worker)
        assert consume(10, "initial"), "initial watcher snapshot absent"
        time.sleep(.3)
        (f.repo / "begin-output").touch()
        wait_file(f.repo / "foreign-streamed")
        no_output()
        (f.repo / "begin-partial").touch()
        wait_file(f.repo / "partial-streamed")
        no_output()
        (f.repo / "finish-partial").touch()
        assert consume(5, "native-live-first"), "assistant output remained hidden until final result"
        assert not (f.repo / "result-streamed").exists()
        (f.repo / "second-output").touch()
        assert consume(5, "native-live-second"), "second active output did not publish"
        sent = f.mail("send", f.agent, "hold-mail-until-result")
        time.sleep(.3)
        received = f.repo / "received-input.jsonl"
        assert not received.exists() or sent["message_id"] not in received.read_text(), \
            "assistant frame incorrectly made the turn idle"
        (f.repo / "finish-turn").touch()
        wait_file(f.repo / "result-streamed")
        end = time.monotonic() + 10
        while not received.exists() or sent["message_id"] not in received.read_text():
            assert time.monotonic() < end, "final result did not release queued mail"
            time.sleep(.01)
        assert sent["message_id"] in received.read_text(), "provider offer omitted the committed mail"
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        if watcher is not None:
            if watcher.poll() is None:
                if native(watcher.pid) == watcher_identity:
                    watcher.terminate()
                else:
                    cleanup.append("owned watcher identity changed; termination refused")
            try:
                watcher.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cleanup.append("owned watcher did not exit")
            for worker in threads:
                worker.join(timeout=5)
                if worker.is_alive():
                    cleanup.append("watch reader did not join")
        try:
            f.close()
        except Exception as error:
            cleanup.append(str(error))
        for pid, _ in f.processes:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
        result = {"failure": failure, "cleanup_errors": cleanup,
                  "records": records, "passed": failure is None and not cleanup}
        (out / "verdict.json").write_text(json.dumps(result, indent=2) + "\n")
    assert result["passed"], json.dumps({"failure": failure, "cleanup": cleanup})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.name == "posix" and Path("/proc/self/stat").exists(), "native Linux judge only"
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(36, 1, 0, 0, 0) == 0, "cannot retain owned orphan custody"
    output = args.out.resolve()
    output.mkdir(exist_ok=False)
    run(image(args.package.resolve(), args.source, output / "image"), output)
