#!/usr/bin/python3 -I
"""Argument-free guest admission query, installed root-owned outside worker storage."""
import json
import os
import sys

# -I removes cwd, user site and environment imports. The installer owns this directory.
sys.path.insert(0, "/usr/local/lib/stateengine-box-ci/factory/ci/box")
from custody import idle

if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("CI idle query accepts no arguments")
    try:
        # The locked worker may not be able to resolve the guest caller's cwd.
        os.chdir("/")
        print(json.dumps(idle()))
    except Exception:
        raise SystemExit("CI custody unavailable or nonempty; reconcile before guest startup") from None
