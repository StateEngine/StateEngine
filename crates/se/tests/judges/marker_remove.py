"""Public init/Remove marker custody judges; no provider, model or account use.

The current Remove API has no delete-data/keep-data switch and no MCP tool.
These cases exercise its existing owner-terminal request, not an invented flag.
Remove deletes its exact marker and retires its parent only when empty.
Unowned or linked markers stay untouched, with the reason in a complete receipt.
Native Windows/macOS are not exercised.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import uuid


def snapshot(root):
    """Exact bytes and node kinds, including empty directories; never follow links."""
    result = {}

    def visit(path):
        mode = path.lstat().st_mode
        key = path.relative_to(root).as_posix()
        if stat.S_ISLNK(mode):
            result[key] = ("link", os.readlink(path))
        elif stat.S_ISDIR(mode):
            result[key] = ("directory",)
            for child in sorted(path.iterdir()):
                visit(child)
        elif stat.S_ISREG(mode):
            result[key] = ("file", path.read_bytes())
        else:
            raise AssertionError(f"unexpected node kind: {path}")

    visit(root)
    return result


def same(actual, expected):
    missing = sorted(expected.keys() - actual.keys())
    added = sorted(actual.keys() - expected.keys())
    changed = sorted(k for k in actual.keys() & expected.keys() if actual[k] != expected[k])
    assert not (missing or added or changed), dict(missing=missing, added=added, changed=changed)


class Case:
    def __init__(self, image, root, linked):
        self.root = root
        root.mkdir(mode=0o700)
        # One fixture-owned executable is shared across these sequential cases.
        self.image = image
        self.home = root / "state"
        self.owner = root / "owner"
        self.owner.mkdir(mode=0o700)
        # No ambient accounts, hooks, Git overrides, remote endpoints or capabilities.
        self.env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "TERM") if k in os.environ}
        self.env.update(HOME=str(self.owner), USERPROFILE=str(self.owner),
                        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_OPTIONAL_LOCKS="0", PYTHONDONTWRITEBYTECODE="1")
        for name in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"):
            location = root / name.lower()
            location.mkdir(mode=0o700)
            self.env[name] = str(location)
        self.primary = root / "repository"
        self.primary.mkdir()
        self.repo = self.primary
        self.calls = 0
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.repo / "tracked.txt").write_bytes(b"committed\x00original\xff\n")
        (self.repo / "unchanged.txt").write_bytes(b"unchanged committed work\n")
        self.git("add", "tracked.txt", "unchanged.txt")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.linked = root / "linked-worktree"
        self.git("worktree", "add", "-q", "-b", "linked", str(self.linked))
        if linked:
            self.repo = self.linked
        # The index and working-tree versions deliberately differ from each other and HEAD.
        for repo in (self.primary, self.linked):
            (repo / "tracked.txt").write_bytes(b"staged\x00bytes\xfe\n")
            self.git("add", "tracked.txt", repo=repo)
            (repo / "tracked.txt").write_bytes(b"unstaged\x00bytes\xfd\n")
            (repo / "untracked.bin").write_bytes(b"untracked\x00bytes\xfc\n")
            (repo / "user-folder").mkdir()
            (repo / "user-folder" / "keep.txt").write_bytes(b"untracked nested user work\n")
        self.common = self.primary / ".git"
        self.owned = self.common / "stateengine"
        self.project = None

    def git(self, *args, repo=None):
        output = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c",
                                 f"core.hooksPath={os.devnull}", *args],
                                cwd=repo or self.repo, env=self.env,
                                capture_output=True, timeout=15, check=True)
        return output.stdout

    def inventory(self):
        return {"primary": snapshot(self.primary), "linked": snapshot(self.linked)}

    def run(self, label, *args, terminal=False):
        self.calls += 1
        if terminal:
            helper = Path(__file__).resolve().parents[1] / "support/custody_terminal.py"
            argv = [sys.executable, str(helper), str(self.image), str(self.home), "30000", *args]
        else:
            argv = [str(self.image), "--home", str(self.home), "--json", *args]
        result = subprocess.run(argv, cwd=self.repo, env=self.env,
                                capture_output=True, timeout=40, input=b"")
        base = self.root / f"{self.calls:02}-{label}"
        base.with_suffix(".stdout").write_bytes(result.stdout)
        base.with_suffix(".stderr").write_bytes(result.stderr)
        return result

    @staticmethod
    def value(result):
        frames = [line for line in result.stdout.splitlines() if line.startswith(b"{")]
        assert len(frames) == 1, (result.returncode, result.stdout, result.stderr)
        return json.loads(frames[0])

    def init(self, repo=None):
        selected = repo or self.repo
        before = self.inventory()
        result = self.run("init", "init", "--repo", str(selected), "--name",
                          "Linked" if selected == self.linked else "Primary",
                          "--agent", "main", "--provider", "claude", "--key", str(uuid.uuid4()))
        assert result.returncode == 0, (result.stdout, result.stderr)
        value = self.value(result)
        project = value["profile"]["project"]
        marker = self.owned / f"project-{project}"
        assert stat.S_ISREG(marker.lstat().st_mode), marker
        marker_value = json.loads(marker.read_bytes())
        assert marker_value["project"] == project, marker_value
        assert marker_value["head"] == self.git("rev-parse", "HEAD", repo=selected).decode().strip()
        after = self.inventory()
        relative = marker.relative_to(self.primary).as_posix()
        parent = self.owned.relative_to(self.primary).as_posix()
        expected = {name: dict(nodes) for name, nodes in before.items()}
        if parent not in expected["primary"]:
            expected["primary"][parent] = ("directory",)
        assert relative not in expected["primary"], "init fixture reused an existing project marker"
        expected["primary"][relative] = ("file", marker.read_bytes())
        for name in before:
            same(after[name], expected[name])
        return project, marker

    def remove(self):
        return self.run("remove", "--project", self.project, "remove", "--key",
                        str(uuid.uuid4()), terminal=True)

    def close(self):
        # Only public down; no process-name kill or recursive filesystem cleanup.
        if self.project is not None:
            result = self.run("down", "down")
            assert result.returncode == 0, (result.stdout, result.stderr)
            value = self.value(result)
            assert value["complete"] and value["witness"]["state"] == "witnessed", value
            assert not (self.home / "endpoint.json").exists(), value


def removed_row(case, result):
    assert result.returncode == 0, (result.stdout, result.stderr)
    value = case.value(result)
    assert value["outcome"] == "removed", value
    rows = [row for row in value["projects"] if row["project"]["id"] == case.project]
    assert len(rows) == 1 and rows[0]["outcome"] == "removed", value
    assert rows[0]["remaining"] == [], value
    return rows[0]


def check_retirement(case, marker, before, result):
    row = removed_row(case, result)
    assert not marker.exists() and not marker.is_symlink(), "Remove left its exact git marker behind"
    expected = {name: dict(nodes) for name, nodes in before.items()}
    parent = case.owned.relative_to(case.primary).as_posix()
    del expected["primary"][marker.relative_to(case.primary).as_posix()]
    if not any(key.startswith(parent + "/") for key in expected["primary"]):
        del expected["primary"][parent]
        assert not case.owned.exists(), "empty marker parent was not retired"
    else:
        assert case.owned.is_dir(), "nonempty marker parent was removed"
    after = case.inventory()
    for name in expected:
        same(after[name], expected[name])
    assert any(item["path"] == str(marker) for item in row["removed"]), row


def check_unsafe(case, before, external, external_before, result, marker):
    same(snapshot(external), external_before)
    value = case.value(result)
    row = removed_row(case, result)
    kept = [item for item in row["kept"]
            if item["what"] == "git identity marker" and item["path"] is not None
            and Path(item["path"]).name == marker.name]
    assert len(kept) == 1 and kept[0]["note"].strip(), value
    assert row["removed_at"] is not None and row["event_id"] is not None, value
    after = case.inventory()
    for name, nodes in before.items():
        same(after[name], nodes)


def run_case(image, output, linked, scenario):
    case = Case(image, output, linked)
    try:
        if scenario == "nested":
            case.repo = case.repo / "registered-subdirectory"
            case.repo.mkdir()
        case.project, marker = case.init()
        if scenario == "init":
            return
        if scenario == "missing-marker":
            marker.unlink()
            before = case.inventory()
            row = removed_row(case, case.remove())
            for name, nodes in before.items():
                same(case.inventory()[name], nodes)
            assert not any(item["path"] in (str(marker), str(case.owned))
                           for item in row["removed"]), row
            kept = [item for item in row["kept"] if item["path"] == str(case.owned)]
            assert len(kept) == 1 and kept[0]["note"].strip(), row
            return
        if scenario == "neighbors":
            sibling = case.primary if linked else case.linked
            sibling_id, sibling_marker = case.init(sibling)
            assert sibling_id != case.project and sibling_marker != marker
            (case.owned / "user-file.bin").write_bytes(b"unrelated file\x00\xff")
            nested = case.owned / "nonempty-folder"
            nested.mkdir()
            (nested / "keep.bin").write_bytes(b"never recurse here\x00\xfe")
            before = case.inventory()
            result = case.remove()
            check_retirement(case, marker, before, result)
            # A real sibling registration remains readable, not merely a synthetic marker.
            readback = case.run("sibling-status", "--project", sibling_id, "status")
            assert readback.returncode == 0, (readback.stdout, readback.stderr)
            assert case.value(readback).get("removal") is None, case.value(readback)
        elif scenario in ("empty", "nested", "head-moved"):
            if scenario == "head-moved":
                previous = case.git("rev-parse", "HEAD")
                case.git("-c", "commit.gpgsign=false", "commit", "-qm", "subsequent work")
                assert case.git("rev-parse", "HEAD") != previous
                assert json.loads(marker.read_bytes())["head"] == previous.decode().strip()
            before = case.inventory()
            check_retirement(case, marker, before, case.remove())
        elif scenario in ("ancestor-link", "ancestor-empty"):
            external = case.root / "external-target"
            external.mkdir()
            preserved = case.root / "original-repository"
            case.primary.rename(preserved)
            redirected = external / "foreign-repository"
            shutil.copytree(preserved, redirected, symlinks=True)
            foreign = redirected / ".git" / "stateengine" / marker.name
            if scenario == "ancestor-empty":
                foreign.unlink()
                assert not list(foreign.parent.iterdir())
            else:
                foreign.write_bytes(b"foreign user bytes, never an identity record\x00\xff")
            case.primary.symlink_to(redirected, target_is_directory=True)
            before = case.inventory()
            external_before, original_before = snapshot(external), snapshot(preserved)
            check_unsafe(case, before, external, external_before, case.remove(), marker)
            same(snapshot(preserved), original_before)
        else:
            external = case.root / "external-target"
            external.mkdir()
            (external / "user.bin").write_bytes(b"external user target\x00\xff")
            if scenario == "directory":
                marker.unlink()  # Replace only the exact fixture-created product marker.
                marker.mkdir()
                (marker / "user.bin").write_bytes(b"not a product marker; do not recurse\n")
            elif scenario == "foreign":
                marker.write_bytes(b"foreign user bytes, never an identity record\x00\xff")
            elif scenario == "marker-link":
                marker.unlink()
                marker.symlink_to(external / "user.bin")
            elif scenario == "parent-link":
                case.owned.rename(external / "markers")
                case.owned.symlink_to(external / "markers", target_is_directory=True)
            else:
                raise AssertionError(f"unknown scenario: {scenario}")
            before = case.inventory()
            external_before = snapshot(external)
            check_unsafe(case, before, external, external_before, case.remove(), marker)
    finally:
        original = sys.exc_info()[1]
        try:
            case.close()
        except Exception as cleanup:
            if original is None:
                raise
            raise AssertionError(f"original failure: {original}; public down failed: {cleanup}") from original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--scenario", required=True,
                        choices=("init", "empty", "nested", "neighbors", "directory", "links",
                                 "foreign", "ancestor-link", "ancestor-empty", "missing-marker", "head-moved"))
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("this native terminal judge exercises Linux only")
    os.umask(0o077)
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700)
    supplied_image = args.se.resolve(strict=True)
    owned_image = args.output / "se"
    shutil.copy2(supplied_image, owned_image)
    owned_image.chmod(0o700)
    # Never strip the supplied image. This fresh copy belongs to this fixture;
    # trimming its debug sections avoids duplicating large debug binaries.
    strip = shutil.which("strip")
    if strip is not None:
        stripped = subprocess.run([strip, "--strip-debug", str(owned_image)],
                                  capture_output=True, timeout=60)
        (args.output / "strip.stdout").write_bytes(stripped.stdout)
        (args.output / "strip.stderr").write_bytes(stripped.stderr)
        assert stripped.returncode == 0, (stripped.stdout, stripped.stderr)
    scenarios = ("marker-link", "parent-link") if args.scenario == "links" else (args.scenario,)
    failures = []
    for linked in (False, True):
        for scenario in scenarios:
            label = ("linked" if linked else "normal") + "-" + scenario
            try:
                run_case(owned_image, args.output / label, linked, scenario)
                print("ok - " + label, flush=True)
            except Exception as error:
                failures.append(f"{label}: {type(error).__name__}: {error}")
                print("not ok - " + failures[-1], flush=True)
    assert not failures, failures


if __name__ == "__main__":
    main()
