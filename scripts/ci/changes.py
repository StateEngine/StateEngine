"""Skip Rust only for a proved prose-only diff; any detection failure runs it."""
import json
import os
from pathlib import Path
import subprocess


def git(*args):
    return subprocess.check_output(["git", *args], timeout=45)


def affected(event, name):
    if name == "pull_request":
        base = event["pull_request"]["base"]["sha"]
        head = event["pull_request"]["head"]["sha"]
        base = git("merge-base", base, head).decode().strip()
    elif name == "push" and event.get("ref") != "refs/heads/main":
        base, head = event["before"], event["after"]
    else:
        return True
    paths = git("diff", "--name-only", "--no-renames", "-z", base, head).decode().split("\0")
    paths = [path for path in paths if path]
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


def main():
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        run = affected(event, os.environ["GITHUB_EVENT_NAME"])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Change detection unavailable; running all Rust checks: {error}")
        run = True
    value = str(run).lower()
    print(f"rust={value}")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"rust={value}\n")


if __name__ == "__main__":
    main()
