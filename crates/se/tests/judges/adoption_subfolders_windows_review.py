"""An outside provider process drives the real adoption hook on Windows."""

import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4


kernel = c.WinDLL("kernel32", use_last_error=True)


def created():
    process = kernel.GetCurrentProcess
    process.restype = w.HANDLE
    times = kernel.GetProcessTimes
    times.argtypes = (w.HANDLE, *[c.POINTER(w.FILETIME)] * 4)
    times.restype = w.BOOL
    stamps = [w.FILETIME() for _ in range(4)]
    if not times(process(), *(c.byref(stamp) for stamp in stamps)):
        raise c.WinError(c.get_last_error())
    return (stamps[0].dwHighDateTime << 32) | stamps[0].dwLowDateTime


def short_path(path):
    function = kernel.GetShortPathNameW
    function.argtypes = (w.LPCWSTR, w.LPWSTR, w.DWORD)
    function.restype = w.DWORD
    size = function(path, None, 0)
    if size == 0:
        raise c.WinError(c.get_last_error())
    result = c.create_unicode_buffer(size)
    if not 0 < function(path, result, size) < size:
        raise c.WinError(c.get_last_error())
    return None if result.value.casefold() == path.casefold() else result.value


def run(argv, cwd, environment, stdin=None):
    output = subprocess.run(argv, input=stdin, cwd=cwd, env=environment,
                            capture_output=True, timeout=35)
    if output.returncode != 0:
        raise RuntimeError((output.returncode, output.stdout, output.stderr))
    return output.stdout, output.stderr


def agents(se, home, project, root, environment):
    data, _ = run([se, "--home", home, "--json", "--project", project, "agent", "list"], root, environment)
    rows = json.loads(data)["items"]
    return {row["id"]: row for row in rows}


def check_case(entry, payload_directory, physical, should_attach, inputs):
    se, home, config, root, project, environment = inputs
    previous = agents(se, home, project, root, environment)
    conversation = str(uuid4())
    slug = "".join(ch if ch.isascii() and ch.isalnum() else "-" for ch in physical)
    if len(slug) > 200:
        raise RuntimeError("the fixture directory exceeds the ordinary provider slug bound")
    transcript = config / "projects" / slug / f"{conversation}.jsonl"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(json.dumps({"type": "user", "sessionId": conversation, "uuid": str(uuid4()),
                                     "message": {"role": "user", "content": "Adoption path witness"}}) + "\n",
                          encoding="utf-8")
    discovery = config / "sessions" / f"{os.getpid()}.json"
    discovery.parent.mkdir(exist_ok=True)
    discovery.write_text(json.dumps({"pid": os.getpid(), "sessionId": conversation,
                                    "procStart": str(created()), "cwd": payload_directory}), encoding="utf-8")
    payload = json.dumps({"cwd": payload_directory, "session_id": conversation,
                          "transcript_path": str(transcript)}).encode()
    command = [se, "__se-claude-adopt", home]
    stdout, stderr = run([*command, "start"], entry, environment, payload)
    if stdout or stderr:
        raise RuntimeError(("unexpected native hook output", stdout, stderr))
    current = agents(se, home, project, root, environment)
    added = current.keys() - previous.keys()
    if should_attach:
        if len(added) != 1:
            raise RuntimeError(f"expected one newly attached agent; saw {len(added)}")
        adopted = current[next(iter(added))]
        if adopted["conversation"]["id"] != conversation:
            raise RuntimeError(("the attached agent lost its provider conversation", adopted["conversation"]))
        stdout, stderr = run([*command, "end"], entry, environment, payload)
        if stdout or stderr:
            raise RuntimeError(("native hook retirement failed", stdout, stderr))
    elif current.keys() != previous.keys():
        raise RuntimeError("the nested repository changed the outer project's agents")
    return {"attached": bool(added), "agent_count_delta": len(added)}


def main():
    se, home, config_arg, root, child, nested, project, output = sys.argv[1:]
    config = Path(config_arg)
    environment = {name: value for name, value in os.environ.items()
                   if not name.upper().startswith(("SE_", "STATEENGINE_", "CLAUDE", "CODEX"))}
    environment.update(HOME=str(config.parent), USERPROFILE=str(config.parent))
    inputs = se, home, config, root, project, environment
    alias = Path(root).parent / "worktree junction"
    evidence = {}
    try:
        run(["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), child], root, environment)
        drive_alias = child[0].swapcase() + child[1:]
        cases = [("root_control", root, root, root, True),
                 ("subfolder", child, child, child, True),
                 ("drive_case", drive_alias, drive_alias, child, True),
                 ("forward_slashes", child.replace("\\", "/"), child.replace("\\", "/"), child, True),
                 ("junction_subfolder", str(alias), str(alias), child, True),
                 ("nested_repository", nested, nested, nested, False)]
        short = short_path(child)
        if short:
            cases.append(("short_name", short, short, child, True))
        else:
            evidence["short_name"] = {"state": "unavailable", "reason": "the runner volume returned no 8.3 alias"}
        for label, entry, payload, physical, should_attach in cases:
            try:
                evidence[label] = check_case(entry, payload, physical, should_attach, inputs)
            except Exception as failure:
                evidence[label] = {"failure": str(failure)}
    except Exception as failure:
        evidence["failure"] = str(failure)
        raise
    finally:
        if alias.exists():
            alias.rmdir()
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(evidence, indent=2))
    raise SystemExit(1 if any("failure" in case for case in evidence.values()) else 0)


if __name__ == "__main__":
    main()
