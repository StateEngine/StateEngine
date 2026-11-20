"""Summarize matched native process events and application markers."""
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

def quantiles(values):
    values = sorted(values)
    return {'n': len(values), 'p50': statistics.median(values),
            'p95': values[math.ceil(len(values) * .95) - 1]}

def scheduled(spans, low, high):
    parts = sorted((max(low, x['start']), min(high, x['end'])) for x in spans
                   if x['start'] < high and x['end'] > low)
    total, end = 0, low
    for start, stop in parts:
        if stop > end:
            total += stop - max(start, end)
            end = stop
    return total / 1000

windows = {(w['kind'], w['pid'], w['spawn']): w for w in trace['windows'] if w['clients']}
assert len(windows) == 800
report = {}
for kind in ('product', 'minimal'):
    report[kind] = {}
    for clients in (1, 8):
        cohort = json.loads((root / kind / f'cohort-{clients}.json').read_text())
        assert cohort['complete'] and cohort['observed_peak'] == clients
        measures = collections.defaultdict(list)
        modules = collections.Counter()
        missing_stop = 0
        for s in cohort['samples']:
            assert s['verified']
            w = windows.pop((kind, s['pid'], s['spawned_us']))
            assert len(w['starts']) == 1 and w['images'] and w['cpu']
            spawn, start, entry, exit = w['spawn'], w['starts'][0], w['entry'], w['exit']
            assert spawn <= start <= entry <= exit
            cpu = w['cpu']
            values = {'spawn_to_process_start_ms': (start-spawn)/1000,
                      'process_start_to_main_ms': (entry-start)/1000,
                      'pre_main_scheduled_ms': scheduled(cpu, start, entry),
                      'pre_main_not_scheduled_ms': (entry-start)/1000 - scheduled(cpu, start, entry),
                      'total_ms': s['duration_ms']}
            dlls = [i for i in w['images'] if i['name'].lower().endswith('.dll') and i['at'] <= entry]
            modules.update(i['name'] for i in dlls)
            values['dlls_before_main'] = len(dlls)
            if dlls:
                values['dll_mapping_span_ms'] = (max(i['at'] for i in dlls)-min(i['at'] for i in dlls))/1000
            values['hard_faults_before_main'] = sum(i['at'] <= entry for i in w['faults'])
            if kind == 'product':
                a = s['phases']['cli_us']
                assert len(a) == 13 and all(a[i] <= a[i+1] for i in range(12))
                values.update({'main_to_exchange_ms': (a[10]-entry)/1000,
                               'before_bootstrap_ms': (a[2]-entry)/1000,
                               'store_open_ms': (a[3]-a[2])/1000,
                               'caller_ms': (a[4]-a[3])/1000,
                               'selection_ms': (a[5]-a[4])/1000,
                               'before_restore_ms': (a[6]-a[5])/1000,
                               'restore_ms': (a[7]-a[6])/1000,
                               'before_connect_ms': (a[8]-a[7])/1000,
                               'connect_ms': (a[9]-a[8])/1000,
                               'exchange_ms': (a[11]-a[10])/1000,
                               'exchange_to_last_marker_ms': (a[12]-a[11])/1000,
                               'last_marker_to_observed_exit_ms': (exit-a[12])/1000,
                               'last_marker_to_exit_scheduled_ms': scheduled(cpu,a[12],exit)})
                stop_from = a[12]
            else:
                values['main_to_observed_exit_ms'] = (exit-entry)/1000
                values['main_to_exit_scheduled_ms'] = scheduled(cpu,entry,exit)
                stop_from = entry
            stops = [v for v in w['stops'] if stop_from <= v <= exit]
            if len(stops) == 1:
                values['last_marker_to_native_stop_ms'] = (stops[0]-stop_from)/1000
                values['native_stop_to_observed_exit_ms'] = (exit-stops[0])/1000
            else:
                missing_stop += 1
            for name, value in values.items():
                measures[name].append(value)
        report[kind][str(clients)] = {'metrics': {k: quantiles(v) for k,v in measures.items()},
                                      'missing_or_ambiguous_process_stop': missing_stop,
                                      'common_pre_main_dlls': modules.most_common(20)}
assert not windows
print(json.dumps(report, indent=2))
