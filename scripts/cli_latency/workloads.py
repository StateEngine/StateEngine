"""Public command inputs and output checks, outside all measured intervals.

Reads mark a different owner-addressed message each time. Resume measures owner
inspection of an empty saved agent, not a bound provider's context or restart.
"""
import hashlib
import json

from support import ROUNDS, require

ACTIONS = ('msg-list', 'msg-send', 'msg-read')


def body(index):
    return f'Measurement message {index:03d}: complete UTF-8 body with café and "quotes".'


def receipt(value, smoke, text, recipient):
    require(value.get('schema') == 'se.message-receipt/v1'
            and value.get('state') == 'committed', 'Send did not commit a new message')
    require(value['project']['id'] == smoke.project
            and value['from']['id'] == smoke.owner and value['to']['id'] == recipient
            and value['kind'] == 'note', 'Send identity or kind changed')
    require(value['body'] == dict(bytes=len(text.encode()),
                                 sha256=hashlib.sha256(text.encode()).hexdigest()),
            'Send body digest changed')
    require(value['notification']['intent'] == 'quiet', 'Wake was not suppressed')
    require(value['message_id'] and value['event_id'] and value['idempotency_key']
            and value['recorded_at'], 'Commit identity is absent')
    writer(value)


def writer(value):
    observed = value['writer']
    generation = observed.get('host_generation')
    require(observed.get('mode') == 'host' and isinstance(generation, str)
            and generation.isdecimal() and int(generation) > 0,
            'Receipt lacks an observed host generation')
    return generation


def row(value, smoke, text, recipient, disposition):
    require(value['from']['id'] == smoke.owner and value['to']['id'] == recipient
            and value['kind'] == 'note' and value['unreadable'] is None
            and value['disposition']['state'] == disposition,
            'Message identity, readability or disposition changed')
    require(value['body']['complete'] is True and value['body']['text'] == text
            and value['body']['bytes'] == len(text.encode()), 'Full message body changed')


def complete_page(value):
    require(value.get('schema') == 'se.message-page/v1', 'Wrong message page family')
    require(value['window']['complete'] is True and value['next'] is None
            and value['window']['omitted'] == dict(count=0, reason=None),
            'Message page is incomplete')


def setup(smoke, action):
    state = dict(ids=[], bodies=[], recipient=smoke.owner if action == 'msg-read' else smoke.agent)
    count = ROUNDS + 1 if action == 'msg-read' else 20 if action == 'msg-list' else 0
    for index in range(count):
        text = body(index)
        sent = smoke.call(['msg', 'send', state['recipient'], text, '--no-wake'],
                          f'seed-{index:03d}')
        receipt(sent, smoke, text, state['recipient'])
        state['ids'].append(sent['message_id'])
        state['bodies'].append(text)
    require(len(set(state['ids'])) == count, 'Setup reused message identities')
    return state


def arguments(smoke, action, state, index):
    if action == 'msg-list':
        return ['msg', 'list', '--to', smoke.agent, '--all', '--full', '--limit', '100']
    if action == 'msg-send':
        return ['msg', 'send', smoke.agent, body(index), '--no-wake']
    if action == 'msg-read':
        return ['msg', 'read', state['ids'][index]]
    require(action == 'resume-preview', 'Unknown measurement workload')
    return ['resume', '--preview', smoke.agent]


def validate(sample, smoke, action, state, index):
    require(sample['exit'] == 0 and sample['error'] is None, 'Measured command failed')
    value = json.loads(sample['stdout'])
    require(value.get('ok') is not False, 'Measured command returned a refusal')
    if action == 'msg-list':
        complete_page(value)
        require(value['unread_total'] == 20 and len(value['items']) == 20,
                'List population or unread count changed')
        expected = dict(zip(state['ids'], state['bodies']))
        require({item['id'] for item in value['items']} == set(expected), 'List identities changed')
        for item in value['items']:
            row(item, smoke, expected[item['id']], smoke.agent, 'unread')
    elif action == 'msg-send':
        receipt(value, smoke, body(index), smoke.agent)
    elif action == 'msg-read':
        require(value.get('schema') == 'se.message-read/v1'
                and value['marked_read'] is True and value['inspection'] is False
                and value['state'] == 'committed' and value['marker'] == 'new'
                and value['disposition'] == 'read' and value['by']['id'] == smoke.owner
                and value['message_id'] == state['ids'][index]
                and value['message']['id'] == state['ids'][index],
                'Read did not create an actual recipient marker')
        row(value['message'], smoke, state['bodies'][index], smoke.owner, 'read')
        require(value['request_identity'] == dict(kind='natural', recipient=smoke.owner,
                                                 message_id=state['ids'][index], marker='read'),
                'Read marker belongs to another recipient or message')
        writer(value)
    else:
        require(value.get('schema') == 'se.resume/v1' and value['schema_version'] == 1
                and value['resume_status'] == 'ready' and value['complete'] is True,
                'Resume preview is incomplete or unreadable')
        principal = value['principal']
        require(principal['project']['id'] == smoke.project
                and principal['agent'] == dict(id=smoke.agent, name='reader-00')
                and principal['preview'] is True and principal['session_id'] is None,
                'Resume preview identity changed')
        require(value['since'] is None and value['cursor']
                and value['working_state']['state'] == 'absent'
                and value['unread']['items'] == [] and value['unread']['next'] is None
                and value['unread']['window']['complete'] is True
                and value['unread']['window']['omitted'] == dict(count=0, reason=None)
                and value['required_reads'] == [] and value['recent_turns'] == []
                and value['omissions'] == [] and value['attention'] == [],
                'Empty saved context changed or hid an unreadable source')
        require(value['budget']['limit_bytes'] == 4096
                and 0 < value['budget']['used_bytes'] <= 4096,
                'Resume packet exceeded its declared budget')
    return value


def readback(smoke, action, state, values):
    """Witness each write through a later complete public inbox read."""
    if action == 'resume-preview':
        return dict(state='not-applicable', reason='Read-only empty owner preview')
    recipient = state['recipient']
    if action == 'msg-send':
        ids = [value['message_id'] for value in values]
        expected = dict(zip(ids, map(body, range(ROUNDS + 1))))
        require(len(set(ids)) == ROUNDS + 1
                and len({v['event_id'] for v in values}) == ROUNDS + 1
                and len({v['idempotency_key'] for v in values}) == ROUNDS + 1,
                'Fresh sends reused a durable identity')
    else:
        expected = dict(zip(state['ids'], state['bodies']))
    if action in ('msg-send', 'msg-read'):
        require(len({writer(value) for value in values}) == 1,
                'Serving host generation changed between writes')
    rows = smoke.pages(['msg', 'list', '--to', recipient, '--all', '--full', '--limit', '100'],
                       'committed-mail-readback')
    require(len(rows) == len(expected) and {item['id'] for item in rows} == set(expected),
            'Public readback omitted, duplicated or invented committed mail')
    disposition = 'read' if action == 'msg-read' else 'unread'
    for item in rows:
        row(item, smoke, expected[item['id']], recipient, disposition)
    unread = smoke.call(['msg', 'list', '--to', recipient, '--limit', '100'], 'unread-readback')
    require(unread['unread_total'] == (0 if action == 'msg-read' else len(expected)),
            'Final unread total differs from witnessed marker state')
    if action == 'msg-read':
        complete_page(unread)
        require(unread['items'] == [], 'A completed recipient read remained unread')
    return dict(state='witnessed', rows=len(rows), disposition=disposition)
