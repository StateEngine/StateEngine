"""Publish complete fixture records and wait for JSON, not directory visibility."""
import json
from pathlib import Path
import tempfile
import time


def write_json(path, value):
    path = Path(path)
    staged = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.' + path.name + '.', suffix='.tmp', delete=False) as output:
            staged = Path(output.name)
            json.dump(value, output)
        staged.replace(path)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def read_json(path):
    """None means not yet published or still being written; other I/O errors fail."""
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8'))
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(value, (dict, list)):
        raise AssertionError(f'fixture record must be an object or array: {path}')
    return value


def wait_json(path, seconds=20):
    end = time.monotonic() + seconds
    while True:
        value = read_json(path)
        if value is not None:
            return value
        if time.monotonic() >= end:
            raise AssertionError(f'deadline waiting for a complete JSON fixture record: {path}')
        time.sleep(.03)
