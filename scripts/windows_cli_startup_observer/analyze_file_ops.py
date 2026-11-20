"""Summarize traced file operations and sampled product call stacks."""
import collections
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
trace = json.loads((root / 'etw.json').read_text())
if trace['events_lost']:
    raise ValueError('Native trace lost events')
windows = {(w['pid'], w['spawn']): w for w in trace['windows'] if w['kind'] == 'product'}
if len(windows) != 400:
    raise ValueError('Expected 400 product processes')


def image_base(mappings, pid, timestamp):
    entries = [row for row in mappings if row.get('pid', pid) == pid
               and row['name'].lower() == 'product.exe' and row['at'] <= timestamp]
    if not entries:
        return None
    row = max(entries, key=lambda value: value['at'])
    return row['base'], row['bytes']


def rvas(frames, image):
    if image is None:
        return ()
    base, size = image
    return tuple(hex(ip - base) for ip in frames if base <= ip < base + size)


def matching_stacks(samples, stacks, image_for, phase_for):
    by_key = collections.defaultdict(list)
    for stack in stacks:
        by_key[(stack['pid'], stack['tid'], stack['at'])].extend(stack['frames'])
    groups = collections.Counter()
    matched = 0
    for sample in samples:
        frames = by_key.get((sample['pid'], sample['tid'], sample['at']))
        if not frames:
            continue
        matched += 1
        offsets = rvas(frames, image_for(sample))
        if offsets:
            groups[(phase_for(sample), offsets)] += 1
    return matched, [{'phase': phase, 'rvas': list(offsets), 'samples': count}
                     for (phase, offsets), count in groups.most_common()]


result = {}
for clients in (1, 8):
    cohort = json.loads((root / 'product' / f'cohort-{clients}.json').read_text())
    if not cohort['complete'] or cohort['observed_peak'] != clients:
        raise ValueError('Incomplete cohort')
    client_ops = collections.Counter()
    client_stacks = collections.Counter()
    client_samples = client_matched = 0
    cohort_windows = []
    for sample in cohort['samples']:
        if not sample['verified']:
            raise ValueError('Unverified send')
        window = windows.pop((sample['pid'], sample['spawned_us']))
        cohort_windows.append(window)
        client_ops.update((op['op'], op['class']) for op in window['file_ops'])
        a = sample['phases']['cli_us']
        def phase_for(event):
            at = event['at']
            for name, lower, upper in (('before_main', window['spawn'], a[0]),
                                       ('bootstrap', a[0], a[2]), ('store_open', a[2], a[3]),
                                       ('caller', a[3], a[4]), ('selection', a[4], a[5]),
                                       ('route', a[5], a[6]), ('restore', a[6], a[7]),
                                       ('pre_connect', a[7], a[8]), ('connect', a[8], a[9]),
                                       ('exchange', a[10], a[11]), ('after_exchange', a[11], window['exit'])):
                if lower <= at < upper:
                    return name
            return 'other'
        samples = window['samples']
        client_samples += len(samples)
        matched, groups = matching_stacks(samples, window['stacks'],
            lambda sample: image_base(window['images'], sample['pid'], sample['at']), phase_for)
        client_matched += matched
        for group in groups:
            client_stacks[(group['phase'], tuple(group['rvas']))] += group['samples']
    begin = min(w['spawn'] for w in cohort_windows)
    end = max(w['exit'] for w in cohort_windows)
    hosts = {w['host_pid'] for w in cohort_windows}
    if len(hosts) != 1:
        raise ValueError('Host PID changed within cohort')
    host_pid = next(iter(hosts))
    host_ops = collections.Counter((op['op'], op['class']) for op in trace['host_file_ops']
                                   if op['pid'] == host_pid and begin <= op['at'] <= end)
    host_samples = [sample for sample in trace['host_samples']
                    if sample['pid'] == host_pid and begin <= sample['at'] <= end]
    matched, host_stacks = matching_stacks(host_samples, trace['host_stacks'],
        lambda sample: image_base(trace['mappings'], sample['pid'], sample['at']), lambda _: 'host')
    if client_matched == 0 or matched == 0:
        raise ValueError('No sampled stacks matched the measured cohort')
    count = len(cohort['samples'])
    def op_report(counter):
        return [{'operation': op, 'class': kind, 'count': value, 'mean_per_send': value / count}
                for (op, kind), value in counter.most_common()]
    result[str(clients)] = {
        'completed_sends': count, 'client_file_operations': op_report(client_ops),
        'host_cohort_file_operations': op_report(host_ops),
        'client_profile_samples': client_samples, 'client_stacks_matched': client_matched,
        'host_profile_samples': len(host_samples), 'host_stacks_matched': matched,
        'client_product_stacks': [{'phase': phase, 'rvas': list(offsets), 'samples': value}
                                  for (phase, offsets), value in client_stacks.most_common()],
        'host_product_stacks': host_stacks,
    }
if windows:
    raise ValueError('Unmatched process windows')
print(json.dumps(result, indent=2))
