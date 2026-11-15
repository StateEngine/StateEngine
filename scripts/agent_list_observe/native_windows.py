"""Native private-image and provider-family census, bound to process births.

Private image paths and retained birth identities delimit the fixture family.
Unrelated command lines are excluded; unreadable retained identities refuse.
"""
import json
import ntpath
import subprocess
import time
from pathlib import Path

from harness_matrix.io import require, save


def normalized(value):
    return ntpath.normcase(ntpath.normpath(value))


class ImageObserver:
    def __init__(self, home, output):
        self.home, self.output = normalized(str(home)), output
        self.known = set()
        self.sequence = 0

    def census(self):
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
                                 str(Path(__file__).with_name('processes.ps1'))],
                                input=json.dumps(dict(home=self.home, known=[dict(pid=pid,birth=birth) for pid,birth in sorted(self.known)])),
                                capture_output=True, text=True, encoding='utf-8', timeout=30)
        require(result.returncode == 0, 'Native image census failed: ' + result.stderr)
        require(len(result.stdout.encode()) <= 4 * 1024**2, 'Native image census exceeded its bound')
        value = json.loads(result.stdout)
        require(value.get('coverage') == 'complete' and isinstance(value.get('rows'), list),
                'Native image census is incomplete')
        rows = value['rows']
        # Preserve the complete native image/birth inventory. Foreign command
        # lines are excluded at the producer, not printed or used as credentials.
        self.sequence += 1
        save(self.output / f'outside-{self.sequence:04d}.json', value)
        return rows

    def observe(self, pid=None):
        rows = self.census()
        if pid is not None:
            row = next((r for r in rows if r['pid'] == pid), None)
            require(row and row['birth'] and row['image'] and row['command'],
                    'Owned runtime native identity is unreadable')
            require(normalized(row['image']).startswith(self.home + '\\')
                    and row['name'].casefold() == 'se.exe',
                    'Public startup PID is outside the private runtime image scope')
            self.known.add((pid, row['birth']))
        while True:
            parents = {r['pid']: r['birth'] for r in rows if (r['pid'], r['birth']) in self.known}
            descendants = {(r['pid'], r['birth']) for r in rows if r['parent'] in parents
                           and (not r['birth'] or r['birth'] >= parents[r['parent']])}
            require(all(birth for _, birth in descendants), 'Descendant native birth is unreadable')
            if descendants.issubset(self.known):
                break
            self.known.update(descendants)
        selected = []
        for row in rows:
            retained = (row['pid'], row['birth']) in self.known
            image = normalized(row['image']) if row['image'] else None
            private = image is not None and (image == self.home or image.startswith(self.home + '\\'))
            if not retained and not private:
                if row['name'].casefold() == 'se.exe' and image is None:
                    require(row['owner_state'] == 'foreign',
                            'A possible startup runtime image is unreadable: ' + str(row['pid']))
                continue
            require(row['birth'] and row['image'] and row['command'],
                    'Retained startup process identity is unreadable')
            self.known.add((row['pid'], row['birth']))
            selected.append(row)
        return selected
