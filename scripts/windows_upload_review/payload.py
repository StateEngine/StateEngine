"""Download the immutable release image without persisting the API credential."""
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import zipfile

OUTER = 'a5a8c0e8ca25edc087e0f7653d4ccc3723093f7baa5432744efa1483926690d8'
INNER = 'd22ca4204cfc40e52fe7b56d61b88f40eb2fc8501343c715be64d250055e2f0c'
IMAGE = '3e42826f684d886b1c91f21b7cae9b46aeb209c8c91e3a7a5cea2c89541001bc'
SIZE = 47_660_032


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    archive = root / 'release-assets.zip'
    with archive.open('wb') as output:
        subprocess.run(['gh', 'api', 'repos/StateEngine/StateEngine/actions/artifacts/14112051489/zip'],
                       stdout=output, check=True, timeout=180)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == OUTER
    with zipfile.ZipFile(archive) as outer:
        matches = [name for name in outer.namelist() if name.endswith('x86_64-pc-windows-msvc-unsigned.zip')]
        assert len(matches) == 1, matches
        data = outer.read(matches[0])
    assert hashlib.sha256(data).hexdigest() == INNER
    with zipfile.ZipFile(io.BytesIO(data)) as inner:
        names = [name for name in inner.namelist() if Path(name).name == 'se.exe']
        assert len(names) == 1, names
        image = inner.read(names[0])
    assert len(image) == SIZE and hashlib.sha256(image).hexdigest() == IMAGE
    (root / 'payload.exe').write_bytes(image)
    archive.unlink()
    print('Pinned 47,660,032-byte release image verified at all three archive boundaries.')


if __name__ == '__main__':
    main()
