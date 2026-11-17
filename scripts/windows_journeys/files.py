"""Bounded private inventories that preserve unreadable versus absent."""
import os
from pathlib import Path
import stat

from harness_matrix.io import require


def plain_files(root):
    root = Path(root)
    for ancestor in [root, *root.parents]:
        info = ancestor.lstat()
        require(not stat.S_ISLNK(info.st_mode)
                and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'Private inventory ancestry contains a link or reparse point')
    pending, count = [root], 0
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'Private inventory root is not a plain directory')
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                require(count <= 25000, 'Private inventory exceeds its finite entry bound')
                info = entry.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(info.st_mode)
                        and not getattr(info, 'st_file_attributes', 0) & 0x400,
                        'Private inventory contains a link or reparse point')
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                else:
                    require(stat.S_ISREG(info.st_mode), 'Private inventory contains a non-file')
                    yield Path(entry.path), info
