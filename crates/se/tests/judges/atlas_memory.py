"""Protects: B4 samples native RSS for attributed SE processes, retaining raw missing reads."""
import json
import hashlib
import os
from pathlib import Path
import threading
import time


def process(pid):
    try:
        directory = Path(f'/proc/{pid}')
        fields = (directory / 'stat').read_text().rsplit(') ', 1)[1].split()
        row = {'pid': pid, 'parent': int(fields[1]), 'state': fields[0], 'birth': fields[19]}
        try:
            row['image'] = os.readlink(directory / 'exe')
        except OSError as error:
            row.update(image=None, image_error=str(error))
        return row
    except FileNotFoundError:
        return {'pid': pid, 'state': 'absent', 'birth': None}


class MemoryMonitor:
    def __init__(self, image, host, output):
        self.image, self.host, self.output = str(image), host, output
        self.stage, self.provider = 'starting', None
        self.samples, self.errors = [], []
        with Path(image).open('rb') as source:
            self.image_hash = hashlib.file_digest(source, 'sha256').digest()
        self.image_classes = {}
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def sample(self):
        stage = self.stage
        sampled_at = time.monotonic()
        native = {}
        for directory in Path('/proc').iterdir():
            if not directory.name.isdigit():
                continue
            try:
                # Same-user inventory includes helpers which do not use se's image.
                if directory.stat().st_uid != os.getuid():
                    continue
                row = process(int(directory.name))
                if row['state'] != 'absent':
                    native[row['pid']] = row
            except (FileNotFoundError, ProcessLookupError):
                pass
            except PermissionError as error:
                self.errors.append({'pid': directory.name, 'reason': str(error)})
        selected = {self.host} | {pid for pid, row in native.items()
                                  if row.get('image') == self.image}
        while True:
            children = {pid for pid, row in native.items() if row['parent'] in selected}
            if children <= selected:
                break
            selected |= children
        records, errors = [], []
        for pid in selected:
            row = native.get(pid)
            if row is None:
                errors.append({'pid': pid, 'reason': 'selected native process absent or unreadable'})
                continue
            if row['state'] == 'Z':
                records.append(row | {'rss_bytes': None, 'observation': 'exited-awaiting-reap'})
                continue
            try:
                text = Path(f'/proc/{pid}/smaps_rollup').read_text()
                rss = next(int(line.split()[1]) * 1024 for line in text.splitlines()
                           if line.startswith('Rss:'))
                after = process(pid)
                assert after['birth'] == row['birth'], 'PID changed during RSS read'
                records.append(row | {'rss_bytes': rss})
            except (OSError, StopIteration, AssertionError) as error:
                after = process(pid)
                if after['state'] in ['absent', 'Z'] or after['birth'] != row['birth']:
                    records.append(row | {'rss_bytes': None, 'observation': 'exited-during-read',
                                          'outside': after})
                else:
                    errors.append({'pid': pid, 'birth': row['birth'], 'reason': str(error)})
        self.samples.append({'at_monotonic': sampled_at, 'stage': stage,
                             'processes': records, 'errors': errors})

    def run(self):
        while not self.done.is_set():
            try:
                self.sample()
            except Exception as error:
                self.errors.append(str(error))
            self.done.wait(.05)

    def stop(self):
        self.done.set()
        self.thread.join(10)
        assert not self.thread.is_alive(), 'native memory monitor did not close'
        self.output.write_text(json.dumps({'samples': self.samples, 'errors': self.errors}, indent=2))

    def budget(self):
        phases = {}
        for sample in self.samples:
            provider_tree = set()
            if self.provider and any(row['pid'] == self.provider['pid']
                    and row['birth'] == self.provider['birth'] for row in sample['processes']):
                provider_tree.add(self.provider['pid'])
                while True:
                    children = {row['pid'] for row in sample['processes']
                                if row['parent'] in provider_tree}
                    if children <= provider_tree:
                        break
                    provider_tree |= children
            charged, classification_errors = [], []
            for row in sample['processes']:
                if row['rss_bytes'] is None:
                    continue
                if row['pid'] not in provider_tree or row['image'] == self.image:
                    charged.append(row)
                elif row['pid'] != self.provider['pid']:
                    # A provider's MCP child can be the protected copy of se,
                    # rather than the original path. Classify by complete bytes.
                    path = row['image']
                    if path not in self.image_classes:
                        try:
                            with Path(path).open('rb') as image:
                                self.image_classes[path] = hashlib.file_digest(image, 'sha256').digest() == self.image_hash
                        except (OSError, TypeError):
                            self.image_classes[path] = None
                    engine = self.image_classes[path]
                    if engine is not False:
                        charged.append(row)
                    if engine is None:
                        classification_errors.append({'image': path, 'reason': 'provider descendant image unclassified'})
            total = sum(row['rss_bytes'] for row in charged if row['rss_bytes'] is not None)
            phases.setdefault(sample['stage'], []).append({'bytes': total,
                                                           'errors': sample['errors'] + classification_errors})
        settled = phases.get('settled-one-session', [])
        return {'qualified': bool(settled) and not self.errors
                and not any(row['errors'] for row in settled)
                and max(row['bytes'] for row in settled) <= 64_000_000,
                'complete': bool(settled) and not self.errors
                and not any(row['errors'] for row in settled),
                'ceiling_bytes': 64_000_000,
                'settled_max_bytes': max((row['bytes'] for row in settled), default=None),
                'sampled_peaks_by_stage': {stage: max(row['bytes'] for row in rows)
                                           for stage, rows in phases.items()},
                'source': '/proc/PID/smaps_rollup Rss; exact birth readback',
                'provider_excluded': self.provider,
                'missing_reads': self.errors,
                'errors_by_stage': {stage: [error for row in rows for error in row['errors']]
                                    for stage, rows in phases.items()},
                'scope': 'sampled peaks; no paid-model or Windows/macOS qualification'}
