"""Exercise the real Windows status and a foreground host in a private fixture."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main(image, output):
    output.mkdir(parents=True, exist_ok=False)
    fixture = Path(tempfile.mkdtemp(prefix="watch-judge-"))
    repo, home = fixture / "repo", fixture / "state"
    repo.mkdir()
    env = {
        k: v for k, v in os.environ.items()
        if not k.upper().startswith(("GIT_", "SE_", "STATEENGINE_", "CODEX_", "CLAUDE", "OPENAI_", "ANTHROPIC_"))
        and k.upper() != "XDG_CONFIG_HOME"
    }
    report = {"os": os.name, "run_id": os.environ.get("GITHUB_RUN_ID"), "checks": {}, "observed": {}}
    child = None
    logfile = output / "host.stdout"
    errfile = output / "host.stderr"

    def save():
        (output / "review.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    def run(argv, override=None, timeout=15):
        command = [str(item) for item in argv]
        completed = subprocess.run(command, cwd=repo, env=env if override is None else {**env, **override},
                                   stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                                   text=True, encoding="utf-8", errors="replace")
        if completed.returncode:
            raise RuntimeError(f"{command[:5]} exit {completed.returncode}: {completed.stderr[:1200]} {completed.stdout[:1200]}")
        return completed.stdout

    def git(*args, override=None):
        return run(["git", "-c", "core.fsmonitor=false", *args], override).strip()

    def status(*args, override=None):
        envelope = json.loads(run([image, "--home", home, "--json", "status", *args], override))
        row = envelope["project"]["value"]["git"]
        return {"git": row, "pending": [p for p in envelope["pending"] if p["what"].startswith("repository")]}

    def watched(row):
        return row["git"].get("observation", {}).get("basis") == "watched"

    def count():
        return int(git("rev-list", "--count", "HEAD"))

    def await_status(predicate, seconds):
        until = time.monotonic() + seconds
        while True:
            last = status()
            if predicate(last):
                return last
            if time.monotonic() >= until:
                return last
            time.sleep(.12)

    def keep(key, value):
        report["observed"][key] = value
        save()

    try:
        git("init", "-q")
        git("config", "core.ignorecase", "true")
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@example.invalid")
        tracked = repo / "tracked.txt"
        original = b"original tracked content\n"
        tracked.write_bytes(original)
        git("add", "--", tracked.name)
        git("commit", "-qm", "initial")
        for n in range(8):
            git("commit", "--allow-empty", "-qm", f"history {n}")
        expected = count()
        assert expected == 9
        run([image, "--home", home, "--json", "init", "--repo", repo, "--name", "Watcher judge"])
        with logfile.open("wb") as stdout, errfile.open("wb") as stderr:
            child = subprocess.Popen([str(image), "--home", str(home), "--json", "up", "--foreground"],
                                     cwd=repo, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr)
        until = time.monotonic() + 20
        while True:
            lines = logfile.read_bytes().splitlines()
            if lines and lines[0].endswith(b"}"):
                ready = json.loads(lines[0])
                assert ready["process"]["pid"] == child.pid, ready
                break
            if child.poll() is not None or time.monotonic() >= until:
                raise RuntimeError(f"foreground host did not publish: {errfile.read_text(errors='replace')}")
            time.sleep(.05)

        first = await_status(lambda row: watched(row) and not row["git"]["uncommitted"], 12)
        keep("initial", first)
        assert watched(first) and first["git"]["uncommitted"] is False, first
        assert first["git"]["commits"] == expected
        report["checks"]["initial_count"] = True

        with tracked.open("ab", buffering=0) as writer:
            changed = b"changed while the native writer stays open\n"
            assert writer.write(changed) == len(changed)
            # Invoke the public consumer before an oracle read can affect cache state.
            before_flush = await_status(watched, 4)
            plain = run([image, "--home", home, "status"])
            if "watched" not in plain.lower():
                plain = run([image, "--home", home, "status"])
            keep("held_before_flush", {"status": before_flush, "plain": plain})
            assert tracked.read_bytes() == original + changed and not writer.closed
            observed = before_flush["git"]
            if watched(before_flush):
                basis = observed["observation"]
                assert basis["reconciled_at"]
                assert "watched" in plain.lower() and "last reconciled" in plain.lower(), plain
            forced = status("--fresh")
            keep("held_fresh", forced)
            assert not watched(forced) and forced["git"]["uncommitted"] is True, forced
            os.fsync(writer.fileno())
            after_flush = await_status(lambda row: watched(row) and row["git"]["uncommitted"] is True, 5)
            keep("held_after_flush", after_flush)

        after_close = await_status(lambda row: watched(row) and row["git"]["uncommitted"] is True, 6)
        keep("after_close", after_close)
        assert watched(after_close) and after_close["git"]["uncommitted"] is True, after_close
        report["checks"]["open_writer"] = {"watched_before_flush": watched(before_flush),
                                           "dirty_before_flush": observed["uncommitted"],
                                           "flush_converged_while_open": watched(after_flush) and after_flush["git"]["uncommitted"] is True}
        assert after_close["git"]["commits"] == expected

        tracked.write_bytes(original)
        clean = await_status(lambda row: watched(row) and row["git"]["uncommitted"] is False, 8)
        keep("restored_clean", clean)
        assert watched(clean) and clean["git"]["uncommitted"] is False, clean

        untracked = repo / "untracked.txt"
        untracked.write_text("untracked control\n")
        host_dirty = await_status(lambda row: watched(row) and row["git"]["uncommitted"] is True, 8)
        keep("untracked_watched", host_dirty)
        assert watched(host_dirty) and host_dirty["git"]["uncommitted"] is True, host_dirty
        override = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "status.showUntrackedFiles",
                    "GIT_CONFIG_VALUE_0": "no"}
        oracle = git("status", "--porcelain", override=override)
        alternate = status(override=override)
        keep("git_environment_fallback", {"oracle_dirty": bool(oracle), "status": alternate})
        assert not oracle and not watched(alternate) and alternate["git"]["uncommitted"] is False, alternate
        report["checks"]["git_environment_fallback"] = True
        untracked.unlink()
        clean = await_status(lambda row: watched(row) and row["git"]["uncommitted"] is False, 34)
        keep("deleted_clean", clean)
        assert watched(clean) and clean["git"]["uncommitted"] is False, clean

        # Force a real coverage refusal and hold the incompatible policy long
        # enough that the public fallback is observed before restoring it.
        git("config", "core.ignorecase", "false")
        loss = await_status(lambda row: not watched(row) and bool(row["pending"]), 8)
        keep("coverage_fallback", loss)
        assert not watched(loss) and loss["git"]["uncommitted"] is False, loss
        git("config", "core.ignorecase", "true")
        recovered = await_status(lambda row: watched(row) and row["git"]["commits"] == expected, 34)
        keep("coverage_rearmed", recovered)
        assert watched(recovered) and recovered["git"]["commits"] == expected, recovered
        assert recovered["git"]["observation"]["reconciled_at"] != first["git"]["observation"]["reconciled_at"]
        report["checks"]["coverage_fallback_and_rearm"] = True

        git("commit", "--allow-empty", "-qm", "advance HEAD")
        advanced = await_status(lambda row: watched(row) and row["git"]["commits"] == expected + 1, 8)
        keep("new_head", {"oracle_count": count(), "status": advanced})
        assert watched(advanced) and count() == advanced["git"]["commits"] == expected + 1, advanced
        report["checks"]["new_head_count"] = True

        time.sleep(32)
        idle = status()
        keep("idle", idle)
        report["checks"]["idle_reconciled"] = (
            watched(idle)
            and idle["git"]["observation"]["reconciled_at"] != advanced["git"]["observation"]["reconciled_at"]
        )
        assert report["checks"]["idle_reconciled"], "an armed idle watcher never revised its last reconcile"
    finally:
        if child is not None and child.poll() is None:
            try:
                down = json.loads(run([image, "--home", home, "--json", "down"], timeout=20))
                report["cleanup"] = child.wait(timeout=20) == 0 and down["complete"] and not (home / "endpoint.json").exists()
            finally:
                save()
        else:
            save()
    assert report.get("cleanup") is True, report.get("cleanup")


if __name__ == "__main__":
    if os.name != "nt":
        sys.exit("Requires native Windows")
    main(Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2]).resolve())
