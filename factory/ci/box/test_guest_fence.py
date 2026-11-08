"""Apply the delivered patch to a private copy and exercise both shared admission readers."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('STATEENGINE_GUEST_OWNER_SOURCE', ''))


@unittest.skipUnless(SOURCE.is_file(), 'requires the existing box guest-owner source for patch integration')
class GuestFence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        shutil.copyfile(SOURCE,self.root/'guest_owner.py')
        subprocess.run(['patch','--batch','--fuzz=0','-p1','-d',str(self.root),'-i',
                        str(Path(__file__).with_name('guest-owner-ci-fence.patch').resolve())],
                       check=True,capture_output=True)
        spec=importlib.util.spec_from_file_location('guest_owner_candidate',self.root/'guest_owner.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)

    def tearDown(self):self.temp.cleanup()

    def store(self,guest,tag=''):
        folder=self.root/(guest+tag);folder.mkdir(mode=0o700)
        store=self.module.Store(folder,{guest:folder/'guest'})
        store.initialize()
        record=store.admit('fixture',os.getpid(),guest,16,'reader integration fixture','msg-'+'a'*24)
        return store,record

    def test_both_guest_readers_refuse_failed_malformed_and_missing_helper(self):
        for index,(code,output) in enumerate([(1,''),(0,'{}'),(0,'not-json'),(0,json.dumps({'schema':'stateengine-ci-idle/v1','idle':1}))]):
            for name in ('stateengine-winvm','secode-winvm'):
                store,record=self.store(name,str(index))
                answer=subprocess.CompletedProcess([],code,output,'')
                with patch('subprocess.run',return_value=answer):
                    with self.assertRaisesRegex(RuntimeError,'CI custody'):
                        store.before_boot(store.roots[name],16,record['generation'])
                self.assertEqual(store.read()['phase'],'admitted')

    def test_both_guest_readers_consume_only_the_exact_idle_proof(self):
        for name in ('stateengine-winvm','secode-winvm'):
            store,record=self.store(name)
            answer=subprocess.CompletedProcess([],0,json.dumps({'schema':'stateengine-ci-idle/v1','idle':True}),'')
            with patch('subprocess.run',return_value=answer),patch.object(self.module,'available_memory',return_value=64*1024**3):
                self.assertEqual(store.before_boot(store.roots[name],16,record['generation']),record['generation'])
            self.assertEqual(store.read()['phase'],'booting')

    def test_timeout_is_a_named_refusal_before_boot(self):
        store,record=self.store('stateengine-winvm')
        with patch('subprocess.run',side_effect=subprocess.TimeoutExpired('idle',30)):
            with self.assertRaisesRegex(RuntimeError,'CI custody'):
                store.before_boot(store.roots['stateengine-winvm'],16,record['generation'])
        self.assertEqual(store.read()['phase'],'admitted')
