"""Skip work only for a proved unaffected diff; any detection failure runs it."""
import json
import os
from pathlib import Path
import re
import subprocess

# Linux-only tools, and sources whose names mark them as compiled out of Windows.
# A misnamed ungated file still fails on main, which always runs Windows.
NOT_WINDOWS = re.compile(
    r"factory/ci/box/.*"
    r"|crates/[^/]+/src/(.*/)?(linux|macos|unix)(/.*|\.rs)"
    r"|crates/[^/]+/src/.*_(linux|macos|unix)\.rs"
)


def git(*args):
    return subprocess.check_output(["git", *args], timeout=45)


def changed_paths(event, name):
    """Return the diff's paths, or None when this event must run everything."""
    if name == "pull_request":
        base = event["pull_request"]["base"]["sha"]
        head = event["pull_request"]["head"]["sha"]
        base = git("merge-base", base, head).decode().strip()
    elif name == "push" and event.get("ref") != "refs/heads/main":
        base, head = event["before"], event["after"]
    else:
        return None
    paths = git("diff", "--name-only", "--no-renames", "-z", base, head).decode().split("\0")
    return [path for path in paths if path]


def affected(event, name):
    paths = changed_paths(event, name)
    if paths is None:
        return True
    # Unknown files and empty diffs fail open. Markdown embedded in Rust isn't prose-only.
    if not paths or any(not (path.startswith("docs/") and path.endswith(".md"))
                        and path not in {"README.md", "AGENTS.md"} for path in paths):
        return True
    sources = git("grep", "-l", "-e", "include_str!", "-e", "include_bytes!", "--", "*.rs")
    for source in sources.decode().splitlines():
        text = Path(source).read_text()
        if any(Path(path).name in text for path in paths):
            return True
    return False


def windows_affected(event, name):
    paths = changed_paths(event, name)
    return not paths or not all(NOT_WINDOWS.fullmatch(path) for path in paths)


def main():
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        run = affected(event, os.environ["GITHUB_EVENT_NAME"])
        windows = windows_affected(event, os.environ["GITHUB_EVENT_NAME"])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Change detection unavailable; running all Rust checks: {error}")
        run = windows = True
    lines = f"rust={str(run).lower()}\nwindows={str(windows).lower()}\n"
    print(lines, end="")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(lines)


if __name__ == "__main__":
    main()
