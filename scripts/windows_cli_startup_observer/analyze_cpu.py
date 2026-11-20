"""Summarize matched scheduling, process CPU and sampled instruction locations."""
import collections
import json
import math
import statistics
import sys
from pathlib import Path

root = Path(sys.argv[1])
trace = json.loads((root / 'etw.json').read_text())
if trace['events_lost']:
    raise ValueError('Native trace lost events')
windows = {(w['pid'], w['spawn']): w for w in trace['windows'] if w['kind'] == 'product'}
if len(windows) != 400:
    raise ValueError('Expected 400 product processes')


def stats(values):
    values = sorted(values)
    return {'n': len(values), 'mean': statistics.mean(values), 'p50': statistics.median(values),
            'p95': values[math.ceil(len(values) * .95) - 1]}


def main_thread_states(window, begin, end):
    # The entry timestamp is taken by the main thread itself, so it is running.
    state, previous = 'running', begin
    totals = collections.Counter()
    for event in sorted(window['main_thread_events'], key=lambda row: row['at']):
        at = event['at']
        if at <= begin or at >= end:
            continue
        totals[state] += at - previous
        previous = at
        if event['event'] == 'in':
            state = 'running'
        elif event['event'] == 'ready':
            if state != 'running':
                state = 'ready'
        elif event['event'] == 'out':
            native = event['state'].casefold()
            state = 'ready' if native in ('ready', 'standby', 'deferredready') else (
                'blocked' if native in ('waiting', 'gatewait') else 'unknown')
        else:
            state = 'unknown'
    totals[state] += end - previous
    return {name: totals[name] / 1000 for name in ('running', 'ready', 'blocked', 'unknown')}


def locate(sample, images, global_images):
    ip, pid = sample['ip'], sample['pid']
    # Prefer the process's image maps; kernel maps use the shared system PID.
    eligible = [i for i in images if i['base'] <= ip < i['base'] + i['bytes']]
    if not eligible:
        eligible = [i for i in global_images if i['pid'] in (pid, 0, 4)
                    and i['base'] <= ip < i['base'] + i['bytes']]
    if not eligible:
        return ('unmapped', None)
    image = max(eligible, key=lambda row: row['at'])
    return (image['name'].lower(), ip - image['base'])


report = {}
for clients in (1, 8):
    cohort = json.loads((root / 'product' / f'cohort-{clients}.json').read_text())
    if not cohort['complete'] or cohort['observed_peak'] != clients:
        raise ValueError('Incomplete cohort')
    values = collections.defaultdict(list)
    client_modules, client_product_ips = collections.Counter(), collections.Counter()
    cohort_windows = []
    for sample in cohort['samples']:
        if not sample['verified']:
            raise ValueError('Unverified send')
        phase = sample['phases']
        window = windows.pop((sample['pid'], sample['spawned_us']))
        begin, end = phase['cli_us'][0], phase['cli_us'][10]
        states = main_thread_states(window, begin, end)
        if abs(sum(states.values()) - (end - begin) / 1000) > .01:
            raise ValueError('Thread state coverage does not match interval')
        for name, duration in states.items():
            values['main_to_exchange_' + name + '_ms'].append(duration)
        values['main_to_exchange_ms'].append((end - begin) / 1000)
        values['client_user_cpu_ms'].append(phase['user_cpu_us'] / 1000)
        values['client_kernel_cpu_ms'].append(phase['kernel_cpu_us'] / 1000)
        for profile in window['samples']:
            module, rva = locate(profile, window['images'], trace['mappings'])
            client_modules[module] += 1
            if module == 'product.exe' and rva is not None:
                client_product_ips[hex(rva)] += 1
        cohort_windows.append(window)
    begin = min(w['spawn'] for w in cohort_windows)
    end = max(w['exit'] for w in cohort_windows)
    hosts = {w['host_pid'] for w in cohort_windows}
    if len(hosts) != 1:
        raise ValueError('Host PID changed within cohort')
    host_pid = next(iter(hosts))
    host_modules, host_product_ips = collections.Counter(), collections.Counter()
    for profile in trace['host_samples']:
        if profile['pid'] != host_pid or not begin <= profile['at'] <= end:
            continue
        module, rva = locate(profile, [], trace['mappings'])
        host_modules[module] += 1
        if module == 'product.exe' and rva is not None:
            host_product_ips[hex(rva)] += 1
    cpu = cohort['host_cpu']
    if not cpu or cpu['completions'] != len(cohort['samples']):
        raise ValueError('Missing host process CPU samples')
    report[str(clients)] = {
        'metrics': {name: stats(rows) for name, rows in values.items()},
        'host_cpu_ms_per_send': {'user': cpu['user_ms'] / cpu['completions'],
                                 'kernel': cpu['kernel_ms'] / cpu['completions']},
        'client_profile_modules': client_modules.most_common(),
        'host_profile_modules': host_modules.most_common(),
        'client_product_instruction_rvas': client_product_ips.most_common(),
        'host_product_instruction_rvas': host_product_ips.most_common(),
    }
if windows:
    raise ValueError('Unmatched process windows')
print(json.dumps(report, indent=2))
