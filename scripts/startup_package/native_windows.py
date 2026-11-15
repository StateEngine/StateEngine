"""Startup-only native-image census and directly joined public command handles.

This fixture starts no providers or transport helpers. Both CLI and runtime use
its private se.exe; the census also tracks every observed descendant by birth.
Unrelated unreadable command lines are not runtime evidence. An unreadable image
that could be this fixture, or unreadable retained custody, still refuses.
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
            parents = {r['pid'] for r in rows if (r['pid'], r['birth']) in self.known}
            descendants = {(r['pid'], r['birth']) for r in rows if r['parent'] in parents}
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


class Commands:
    def __init__(self, previous):
        self.output, self.home, self.repository = previous.output, previous.home, previous.repository
        self.environment = previous.environment
        self.observer = ImageObserver(self.home, self.output)
        self.sequence = 0

    def run(self, argv, label, terminal=False, timeout=180):
        require(not terminal, 'Startup observation requires explicit noninteractive commands')
        argv = list(map(str, argv))
        self.sequence += 1
        prefix = self.output / f'{self.sequence:04d}-{label}'
        started = time.monotonic()
        failure = None
        with prefix.with_suffix('.stdout').open('xb') as out, prefix.with_suffix('.stderr').open('xb') as err:
            child = subprocess.Popen(argv, cwd=self.repository, env=self.environment,
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            while child.poll() is None:
                if out.tell() + err.tell() > 8 * 1024**2 or time.monotonic()-started >= timeout:
                    failure = 'Owned command exceeded output or time bound'
                    current = next((r for r in self.observer.census() if r['pid'] == child.pid), None)
                    require(current and current['command'] == subprocess.list2cmdline(argv),
                            'Timed-out owned command line is unreadable or changed')
                    # Popen retains the exact native process handle, not a name
                    # or a newly opened PID that could refer to a replacement.
                    child.kill()
                    child.wait(timeout=10)
                    break
                time.sleep(.05)
            code = child.wait(timeout=1)
        save(prefix.with_suffix('.json'), dict(argv=argv, exit=code, failure=failure,
             elapsed_seconds=time.monotonic()-started))
        require(code == 0 and failure is None, label + ' failed; retained command evidence is available')
        require(sum(prefix.with_suffix(s).stat().st_size for s in ('.stdout','.stderr')) <= 8 * 1024**2,
                label + ' exceeded its output bound')
        return prefix.with_suffix('.stdout').read_text(encoding='utf-8')
