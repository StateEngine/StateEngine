"""Independent controls for request membership changes across status publication."""
from copy import deepcopy
import unittest

from test_check import checker, digests
from test_run_scope import OpenPulls
import test_run_scope as scope


class MovingPulls(OpenPulls):
    """Change API-visible state after a real success status has been written."""

    def __init__(self, when='success', change='shared'):
        super().__init__()
        # A is unsigned; B is signed. Their distinct initial heads are checked
        # in order, so A can try borrowing B's just-published success.
        self.comments[1] = []
        self.comments[2] = [{
            'user': self.second,
            'body': checker.individual_statement(
                self.second['login'], digests()['individual']),
        }]
        self.when, self.change = when, change
        self.b_succeeded = self.moved = False

    def move(self):
        self.moved = True
        if self.change == 'shared':
            self.pulls[1]['head']['sha'] = self.pulls[2]['head']['sha']
        elif self.change == 'base':
            self.pulls[2]['base']['sha'] = 'c' * 40
        elif self.change == 'new-head':
            self.pulls[1]['head']['sha'] = 'd' * 40
        elif self.change == 'closed':
            self.pulls[2]['state'] = 'closed'
        else:
            raise AssertionError('unknown fixture transition')

    def status(self, head, state, description):
        super().status(head, state, description)
        if head == self.pulls[2]['head']['sha'] and state == 'success':
            self.b_succeeded = True
            if self.when == 'success' and not self.moved:
                self.move()

    def request(self, path, payload=None):
        if (self.when == 'subject-read' and path == 'pulls/1'
                and self.b_succeeded and not self.moved):
            self.move()
        return super().request(path, payload)

    def pages(self, path):
        if path == 'pulls' and self.when == 'unreadable' and self.b_succeeded:
            raise OSError('synthetic membership API failure')
        return super().pages(path)


class MembershipRace(unittest.TestCase):
    def event(self, api, subject=1, kind='pull_request_target'):
        if kind == 'issue_comment':
            event = {'issue': {'number': subject, 'pull_request': {
                'url': f'https://api.example.invalid/pulls/{subject}'}}}
        elif kind == 'push':
            event = {'ref': 'refs/heads/main'}
        else:
            event = {'pull_request': deepcopy(api.pulls[subject])}
        return scope.RunScope.run_event(self, api, kind, event)

    def latest_b(self, api):
        return api.latest[(api.pulls[2]['head']['sha'], checker.CONTEXT)]

    def test_unsigned_a_cannot_borrow_b_success_after_publication(self):
        api = MovingPulls()
        self.assertEqual(self.event(api), 1)
        self.assertTrue(api.moved)
        self.assertIn((api.pulls[2]['head']['sha'], 'success'), api.statuses)
        self.assertEqual(self.latest_b(api), 'failure')

    def test_subject_b_also_refuses_a_new_unsigned_shared_head_peer(self):
        api = MovingPulls()
        self.assertEqual(self.event(api, subject=2), 1)
        self.assertEqual(self.latest_b(api), 'failure')

    def test_comment_event_cannot_borrow_b_success(self):
        api = MovingPulls()
        self.assertEqual(self.event(api, kind='issue_comment'), 1)
        self.assertEqual(self.latest_b(api), 'failure')

    def test_push_refresh_revokes_b_success_after_new_shared_peer(self):
        api = MovingPulls()
        self.assertEqual(self.event(api, kind='push'), 1)
        self.assertEqual(self.latest_b(api), 'failure')

    def test_subject_read_detects_move_after_final_membership_snapshot(self):
        api = MovingPulls(when='subject-read')
        self.assertEqual(self.event(api), 1)
        self.assertTrue(api.moved)
        self.assertEqual(self.latest_b(api), 'failure')

    def test_base_move_invalidates_prior_validation(self):
        api = MovingPulls(change='base')
        self.assertEqual(self.event(api, subject=2), 1)
        self.assertEqual(self.latest_b(api), 'failure')

    def test_new_head_gets_failure_without_borrowing_any_prior_result(self):
        api = MovingPulls(change='new-head')
        self.assertEqual(self.event(api), 1)
        self.assertEqual(api.latest.get(('d' * 40, checker.CONTEXT)), 'failure',
                         'the newly observed head needs an explicit failure status')

    def test_unreadable_final_membership_fails_all_known_heads(self):
        api = MovingPulls(when='unreadable')
        with self.assertRaisesRegex(ValueError, 'membership is unreadable'):
            self.event(api, subject=2)
        self.assertEqual(self.latest_b(api), 'failure')
        self.assertEqual(api.latest[(api.head, checker.CONTEXT)], 'failure')

    def test_closed_subject_finishes_after_refreshing_other_heads(self):
        api = MovingPulls(change='closed')
        self.assertEqual(self.event(api, subject=2), 0)
        self.assertTrue(api.moved)
        self.assertEqual(self.latest_b(api), 'failure')

    def test_stable_signed_subject_stays_success_beside_unsigned_other_head(self):
        api = MovingPulls(when='never')
        self.assertEqual(self.event(api, subject=2), 0)
        self.assertEqual(self.latest_b(api), 'success')
        self.assertEqual(api.latest[(api.head, checker.CONTEXT)], 'failure')


if __name__ == '__main__':
    unittest.main()
