"""Check pinned license bytes against Git, including Windows-style checkouts."""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def git(*args):
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, stdout=subprocess.PIPE
    ).stdout


class PinnedLicenseBytes(unittest.TestCase):
    def test_index_bytes_survive_autocrlf_checkout(self):
        paths = git("ls-files", "-z", "--", "LICENSE", "scripts/release/licenses").split(b"\0")
        paths = [path.decode("utf-8") for path in paths if path]
        self.assertGreater(len(paths), 0, "pinned release licenses are absent")
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory).as_posix() + "/"
            git("-c", "core.autocrlf=true", "checkout-index", "--force",
                "--prefix=" + prefix, "--", *paths)
            for path in paths:
                with self.subTest(path=path):
                    expected = git("show", ":" + path)
                    self.assertEqual((ROOT / path).read_bytes(), expected,
                                     "working license differs from the Git index")
                    self.assertEqual((Path(directory) / path).read_bytes(), expected,
                                     "autocrlf checkout changed pinned license bytes")


if __name__ == "__main__":
    unittest.main()
