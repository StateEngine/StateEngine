"""Private short native socket roots, independent of a redirected test TMPDIR."""
import os
from pathlib import Path
import sys
import tempfile


def private_runtime_directory():
    parent = ("/private/tmp" if sys.platform == "darwin" else "/tmp") if os.name == "posix" else None
    return Path(tempfile.mkdtemp(prefix="se-", dir=parent))
