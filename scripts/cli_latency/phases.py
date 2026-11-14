"""Check complete per-call observations before summarizing diagnostic spans.

Inclusive durations overlap. Derived remainders subtract children per call,
never percentiles; signed values stay visible rather than being clamped.
"""
import json

from support import percentile, require

AUTH = {'ipc_self_prewarm', 'ipc_native_connect', 'ipc_challenge_read',
        'ipc_challenge_decode', 'ipc_self_mac_observation', 'ipc_nonce',
        'ipc_owner_mac', 'ipc_hello_write', 'ipc_hello_read', 'ipc_hello_decode'}
EXCHANGE = {'ipc_call_encode', 'ipc_request_write', 'ipc_reply_read', 'ipc_response_decode'}
REQUIRED = AUTH | EXCHANGE | {
    'cli_main', 'cli_file_owner', 'cli_parse', 'cli_bootstrap', 'cli_config',
    'cli_registry_open', 'cli_state_files', 'cli_caller_observation',
    'cli_project_selection', 'cli_dispatch', 'cli_endpoint_discovery', 'cli_credential',
    'cli_forwarding_options', 'cli_writer_lease', 'cli_ipc_forward',
    'cli_ipc_authenticate', 'cli_ipc_exchange', 'cli_ipc_operation',
    'cli_ipc_decode_output', 'cli_output_at', 'cli_output',
}


def parse(sample):
    observed, events = {}, {}
    for line in sample['stderr'].splitlines():
        fields = line.split()
        if fields and fields[0] == 'cli.phase':
            require(len(fields) == 3 and fields[2].isdecimal(), 'Malformed CLI phase')
            observed.setdefault(fields[1], []).append(int(fields[2]) / 1e6)
        elif fields and fields[0] == 'cli.event':
            require(len(fields) == 3 and fields[2].isdecimal() and fields[1] not in events,
                    'Malformed or repeated CLI clock event')
            events[fields[1]] = int(fields[2])
    require(REQUIRED.issubset(observed), 'Required CLI span absent; no zero substituted: '
            + ','.join(sorted(REQUIRED - observed.keys())))
    require(set(events) == {'main_enter', 'main_exit'}, 'Main clock anchor absent')
    require(sample['wall_started_ns'] <= events['main_enter'] <= events['main_exit']
            <= sample['wall_ended_ns'], 'Process clocks exceed parent bounds')
    return {key: sum(values) for key, values in observed.items()}, events, observed


def profile(pairs):
    values, counts = {}, {}
    for pair in pairs[1:]:
        sample = pair['samples']['head']
        measured, events, occurrences = parse(sample)
        require('cli.phase ' not in pair['samples']['base']['stderr']
                and 'cli.event ' not in pair['samples']['base']['stderr'],
                'Plain control unexpectedly contains instrumentation')
        for key, value in measured.items():
            values.setdefault(key, []).append(value)
            counts.setdefault(key, set()).add(len(occurrences[key]))
        derived = {
            'spawn_to_main': (events['main_enter'] - sample['wall_started_ns']) / 1e6,
            'main_exit_to_eof_and_join': (sample['wall_ended_ns'] - events['main_exit']) / 1e6,
            'bootstrap_except_config': measured['cli_bootstrap'] - measured['cli_config'],
            'registry_except_state_files': measured['cli_registry_open'] - measured['cli_state_files'],
            'authenticate_except_named_children': measured['cli_ipc_authenticate']
                - sum(measured[key] for key in AUTH),
            'exchange_except_named_children': measured['cli_ipc_exchange']
                - sum(measured[key] for key in EXCHANGE),
        }
        value = json.loads(sample['stdout'])
        host = value['diagnostics']['host_phases']
        require(host['admitted_to_encode_us'] > 0, 'Reported host duration absent')
        derived['reported_host_admission_to_encode'] = host['admitted_to_encode_us'] / 1000
        derived['reply_wait_except_reported_host'] = measured['ipc_reply_read'] \
            - derived['reported_host_admission_to_encode']
        for stage in ('admission', 'submission', 'continuation'):
            require(host[stage]['jobs'] >= 1, 'Required host work did not execute')
            for field in ('queue_us', 'work_us', 'resume_us'):
                require(type(host[stage][field]) is int and host[stage][field] >= 0,
                        'Required host stage duration is unreadable')
                derived[f'reported_host_{stage}_{field}'] = host[stage][field] / 1000
        derived['reported_host_completion_wait'] = host['completion_wait_us'] / 1000
        for key, value in derived.items():
            values.setdefault('derived.' + key, []).append(value)
    return dict(scope='Inclusive nested spans with observer overhead; host receipt times are '
                      'a separate reported clock; signed remainders subtract within each call; '
                      'no p95 values are summed; instrumentation is not an optimization',
                phases={key: dict(measured_calls=len(samples),
                                  occurrences_per_call=sorted(counts[key]) if key in counts else None,
                                  p50_ms=percentile(samples, .5), p95_ms=percentile(samples, .95),
                                  min_ms=min(samples), max_ms=max(samples))
                        for key, samples in sorted(values.items())})
