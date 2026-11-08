"""Bind run/attempt and actual checkout independently, including empty PR associations."""
import base64
import copy
import hashlib
import unittest
from unittest.mock import Mock

from dispatch_binding import bind

HEAD, CHECKOUT = 'a'*40, 'b'*40
REPO = dict(id=1, full_name='StateEngine/StateEngine', fork=False)


class Requests(unittest.TestCase):
    def fixture(self):
        run = dict(id=2, run_attempt=3, workflow_id=4, path='.github/workflows/ci.yml',
                   repository=REPO.copy(), head_repository=REPO.copy(), status='in_progress',
                   event='pull_request', pull_requests=[], head_sha=HEAD, head_branch='topic')
        pr = dict(number=5, state='open', head=dict(repo=REPO.copy(), sha=HEAD, ref='topic'),
                  base=dict(repo=REPO.copy()), merge_commit_sha=CHECKOUT)
        rows = dict(total_count=2, jobs=[dict(id=6, name='changes', conclusion='success'),
                                       dict(id=7, name='linux-route', status='in_progress')])
        def get(path, **kwargs):
            if path=='actions/runs/2':return run
            if path.startswith('pulls?'):return [pr]
            if path=='pulls/5':return pr
            if path=='actions/runs/2/attempts/3/jobs?per_page=100':return rows
            if path=='actions/jobs/6/logs':return ('time git log -1 --format=%H\ntime '+CHECKOUT+'\n').encode()
            if path.startswith('git/trees/'):return dict(truncated=False,tree=[dict(path='Cargo.toml',type='blob')])
            if path.startswith('contents/Cargo.toml'):return dict(content=base64.b64encode(b'trusted').decode())
            raise AssertionError('unexpected API path '+path)
        api=Mock();api.get.side_effect=get
        return api,run,pr,rows

    def test_empty_run_association_still_binds_exact_current_open_pr(self):
        api,*_=self.fixture()
        request=bind(api,2,3,1,4,{'Cargo.toml':hashlib.sha256(b'trusted').hexdigest()})
        self.assertEqual(request.identity['checkout'],CHECKOUT)
        self.assertEqual(request.identity['head'],HEAD)
        self.assertEqual(request.number,5)

    def test_fork_stale_attempt_and_workflow_refuse_before_source_fetch(self):
        for key,value in [('run_attempt',4),('workflow_id',99),('head_repository',dict(REPO,fork=True))]:
            api,run,*_=self.fixture();run[key]=value
            with self.assertRaises(ValueError):bind(api,2,3,1,4,{})
            self.assertFalse(any(str(c.args[0]).startswith('tarball/') for c in api.get.call_args_list))

    def test_moved_head_checkout_and_policy_do_not_start_work(self):
        api,run,pr,rows=self.fixture();pr['head']['sha']='c'*40
        with self.assertRaises(ValueError):bind(api,2,3,1,4,{})
        api,run,pr,rows=self.fixture();pr['merge_commit_sha']='c'*40
        with self.assertRaises(ValueError):bind(api,2,3,1,4,{})
        api,*_=self.fixture()
        with self.assertRaises(ValueError):bind(api,2,3,1,4,{'Cargo.toml':'0'*64})

    def test_new_critical_policy_path_refuses_even_if_old_digests_match(self):
        api,*_=self.fixture()
        with self.assertRaisesRegex(ValueError,'footprint'):
            bind(api,2,3,1,4,{})
