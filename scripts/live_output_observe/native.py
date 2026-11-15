"""Native fixture startup and outside process closure for output observation."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'crates/se/tests/judges'))
from harness_matrix.io import census, require, save
from mail_cli import Fixture as MailFixture
from public_ready import PublicReady


class Fixture(MailFixture):
    startup = None

    def ok(self, *args, recipient=False):
        if args != ('up',):
            return super().ok(*args, recipient=recipient)
        scope = SimpleNamespace(output=self.root, repository=self.repo)
        self.startup = PublicReady(scope, [str(self.se), '--home', str(self.home),
                                          '--json', 'up'], self.env)
        return json.loads(self.startup.wait()['stdout'])

    def close(self):
        value = self.ok('down')
        require(value.get('complete') and value.get('witness', {}).get('state') == 'witnessed',
                'Public down did not witness complete closure')
        require(isinstance(value.get('stops'), list) and all(row.get('complete') for row in value['stops']),
                'Public down retained an incomplete stop')
        require(not (self.home / 'endpoint.json').exists(), 'Endpoint survived public down')
        if self.startup is not None:
            self.startup.join()


class NativeObserver:
    def __init__(self, root, output):
        self.root, self.output = str(root), output
        self.known = set()
        self.sequence = 0
        if sys.platform == 'win32':
            from native_windows import ImageObserver
            self.windows = ImageObserver(root, output)

    def observe(self, pid=None):
        if sys.platform == 'win32':
            rows = self.windows.observe()
            if pid is not None:
                row = next((r for r in rows if r['pid'] == pid), None)
                require(row and row['birth'] and row['image'] and row['command'],
                        'Owned Windows process identity is outside the retained family')
                self.windows.known.add((pid, row['birth']))
            return rows
        rows = census()
        if pid is not None:
            row = next((r for r in rows if r['pid'] == pid), None)
            require(row and row['birth'] and row['command'] and self.root in row['command'],
                    'Owned native identity is unreadable or outside this fixture')
            self.known.add((pid, row['birth']))
        selected = [r for r in rows if (r['pid'], r['birth']) in self.known
                    or self.root in (r['command'] or '')]
        self.known.update((r['pid'], r['birth']) for r in selected)
        # The fixture's native image and provider helper arguments carry its
        # private root. Retained identities remain in scope even if arguments
        # change; mismatches are evidence rather than permission to signal.
        for row in selected:
            require(row['birth'] and row['command'], 'Retained native identity is unreadable')
        self.sequence += 1
        save(self.output / f'outside-{self.sequence:04d}.json', dict(
            coverage='complete', rows=selected,
            inventory=[{k: row[k] for k in ('pid', 'parent', 'birth', 'state')} for row in rows]))
        return [r for r in selected if not r['state'].startswith(('Z', 'X', 'x'))]
