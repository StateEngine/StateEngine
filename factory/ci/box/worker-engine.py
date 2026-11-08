#!/usr/bin/python3 -I
"""Fixed worker engine door; installed root-owned, callable only as the locked CI worker."""
import os
import json
import pwd
import sys

account = pwd.getpwnam("stateengine-ci")
if os.getuid() != account.pw_uid or account.pw_dir != "/var/lib/stateengine-ci":
    raise SystemExit("dedicated worker identity required")
os.chdir(account.pw_dir)
if sys.argv[1:2] == ["--stateengine-create-transaction"]:
    if sys.argv[2:3] != ["create"]:
        raise SystemExit("transaction admits only fixed container creation")
    print(json.dumps({"pid": os.getpid()}), flush=True)
    # No engine operation occurs until the outside controller durably pins this process.
    if sys.stdin.buffer.readline(8) != b"RUN\n":
        raise SystemExit("creation controller disappeared before custody acknowledgement")
    sys.argv.pop(1)
os.execve("/usr/bin/podman", ["podman", *sys.argv[1:]], {
    "PATH": "/usr/bin:/bin", "HOME": account.pw_dir, "LANG": "C.UTF-8",
    "XDG_RUNTIME_DIR": "/run/user/" + str(account.pw_uid),
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/" + str(account.pw_uid) + "/bus"})
