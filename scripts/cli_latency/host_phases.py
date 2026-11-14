"""Validate complete synchronous span trees and explicit pool hit/miss counts.

Exclusive remainders subtract direct children within each call, never percentiles.
A root's log formatting/write is outside its measured interval and remains overhead.
"""
from support import percentile, require

COMMON = {'total', 'pool_checkout', 'pool_slot', 'pool_lock_pop',
          'pool_identity_before', 'pool_identity_connected', 'pool_identity_snapshot',
          'snapshot_begin', 'snapshot_header', 'snapshot_identity', 'generation_lookup',
          'snapshot_scope', 'message_lookup', 'message_row', 'response_budget',
          'actor_reference', 'notification_materialize', 'read_close',
          'pool_recycle', 'pool_identity_recycle'}
REQUIRED = {'admission': COMMON | {'operation_admit', 'caller_authority', 'host_plan',
                                  'message_read_plan', 'marker_plan', 'marker_receipt_lookup'},
            'readback': COMMON | {'message_committed', 'committed_marker_event'}}


def parse(pair, pid):
    require(pair['host_pid'] == pid, 'Host PID changed in raw trace')
    scopes = {name: dict(spans={}, counts={}) for name in REQUIRED}
    for line in pair['host_phase_lines']:
        fields = line.split()
        require(len(fields) == 7 and fields[0] in ('host.phase', 'host.count')
                and fields[1] == str(pid) and fields[2] in scopes
                and all(fields[i].isdecimal() for i in (4, 5, 6)),
                'Malformed, unattributed or foreign host diagnostic')
        kind, _, scope, name, value, identity, parent = fields
        row = scopes[scope]
        if kind == 'host.count':
            require(name in {'pool_hit', 'pool_miss', 'unclosed_spans'}
                    and name not in row['counts'] and identity == parent == '0',
                    'Missing, repeated or failed trace count')
            row['counts'][name] = int(value)
        else:
            identity, parent = int(identity), int(parent)
            require(identity not in row['spans'], 'Repeated host span identity')
            row['spans'][identity] = dict(name=name, ns=int(value), parent=parent)
    observed = {}
    for scope, row in scopes.items():
        spans, counts = row['spans'], row['counts']
        require(set(counts) == {'pool_hit', 'pool_miss', 'unclosed_spans'}
                and counts['pool_hit'] in (0, 1) and counts['pool_miss'] in (0, 1)
                and counts['pool_hit'] + counts['pool_miss'] == 1
                and counts['unclosed_spans'] == 0, 'Unwitnessed pool count or incomplete span tree')
        require(0 in spans and spans[0]['name'] == 'total' and spans[0]['parent'] == 0,
                'Missing host root span')
        names = {span['name'] for span in spans.values()}
        require(REQUIRED[scope].issubset(names), 'Required host span absent: '
                + ','.join(sorted(REQUIRED[scope] - names)))
        require(('pool_connect' in names) == bool(counts['pool_miss']),
                'Physical connection span disagrees with witnessed pool miss')
        require(sum(span['name'] == 'pool_checkout' for span in spans.values()) == 1,
                'Unexpected checkout count')
        for identity, span in spans.items():
            if identity:
                require(span['parent'] in spans and span['parent'] < identity,
                        'Span parent is absent or cyclic')
            direct_children = [child['ns'] for child_id, child in spans.items()
                               if child_id and child['parent'] == identity]
            remainder = span['ns'] - sum(direct_children)
            require(remainder >= 0, 'Child durations exceed parent interval')
            for kind, ns in [('inclusive', span['ns']), ('exclusive', remainder)]:
                key = scope + '.' + kind + '.' + span['name']
                observed.setdefault(key, []).append(ns / 1e6)
    return {key: sum(values) for key, values in observed.items()}, scopes


def profile(pairs, pid):
    values = {}
    counts = {scope: dict(hits=0, misses=0, checkouts=0) for scope in REQUIRED}
    # Validate the first timed call too, but keep it separate from warm statistics.
    first, _ = parse(pairs[0], pid)
    for pair in pairs[1:]:
        measured, scopes = parse(pair, pid)
        for key, value in measured.items():
            values.setdefault(key, []).append(value)
        for scope, row in scopes.items():
            counts[scope]['hits'] += row['counts']['pool_hit']
            counts[scope]['misses'] += row['counts']['pool_miss']
            counts[scope]['checkouts'] += 1
    return dict(scope='Inclusive and exclusive times include observer overhead; parent log '
                      'format/write is outside root; pool counters are explicit, not inferred',
                host_pid=pid, first_timed_ms=first, warm_pool=counts,
                phases={key: dict(measured_calls=len(samples), p50_ms=percentile(samples, .5),
                                  p95_ms=percentile(samples, .95), min_ms=min(samples),
                                  max_ms=max(samples)) for key, samples in sorted(values.items())})
