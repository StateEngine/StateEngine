"""Real-process fixed-slot custody and lease controls; no engine activation."""
import fcntl, json, multiprocessing as mp, os, sys, tempfile, time, unittest
from pathlib import Path
from unittest.mock import patch
import custody, runner_slot, workload
NAME_A = 'se-ci-' + 'a' * 32
NAME_B = 'se-ci-' + 'b' * 32
CID_A = 'c' * 64
CID_B = 'd' * 64

def actor(directory, config, slot, name, pipe):
    try:
        with runner_slot.venue(runner_slot.select(config, slot)):
            journal = custody.Journal(Path(directory), slot=slot)
            journal.intent(name)
            journal.write(name, dict(name=name, id=CID_A if slot == 'primary' else CID_B, native=dict(processes=[custody.pin(os.getpid())], cgroup=None)))
            pipe.send(('ready', os.getpid()))
            action = pipe.recv()
            if action == 'crash':
                os._exit(31)
    except BaseException as error:
        pipe.send(('error', repr(error)))
        raise
    finally:
        pipe.close()

class Controls(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='runner-slots-')
        self.root = Path(self.temp.name)
        self.journal = self.root / 'journal'
        self.journal.mkdir(mode=448)
        self.config = {'ci_lock': str(self.root / 'ci.lock'), 'slots': {}}
        (self.root / 'ci.lock').touch(mode=384)
        for slot in runner_slot.SLOTS:
            state = self.root / (slot + '-state')
            work = self.root / (slot + '-work')
            lock = self.root / (slot + '.lock')
            state.mkdir(mode=448)
            work.mkdir(mode=448)
            lock.touch(mode=416)
            self.config['slots'][slot] = dict(state=str(state), runner_work=str(work), slot_lock=str(lock))
        self.children = []

    def tearDown(self):
        for child, pipe in self.children:
            if child.is_alive():
                observed = Path(f'/proc/{child.pid}/cmdline').read_bytes()
                self.assertTrue(observed)
                try:
                    pipe.send('exit')
                except (BrokenPipeError, EOFError):
                    pass
                child.join(5)
                if child.is_alive():
                    child.terminate()
                    child.join(5)
            self.assertFalse(child.is_alive())
            pipe.close()
        self.temp.cleanup()

    def start(self, slot, name):
        parent, child = mp.Pipe()
        proc = mp.get_context('fork').Process(target=actor, args=(str(self.journal), self.config, slot, name, child))
        proc.start()
        child.close()
        self.children.append((proc, parent))
        self.assertTrue(parent.poll(5))
        self.assertEqual(parent.recv(), ('ready', proc.pid))
        return (proc, parent)

    def test_real_crash_recovers_only_failed_slot_and_preserves_live_other_slot(self):
        a, pa = self.start('primary', NAME_A)
        b, pb = self.start('secondary', NAME_B)
        before = custody.pin(b.pid)
        with self.assertRaises(BlockingIOError):
            with runner_slot.venue(runner_slot.select(self.config, 'primary')):
                pass
        with open(self.config['ci_lock']) as lock:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pa.send('crash')
        a.join(5)
        self.assertEqual(a.exitcode, 31)
        with runner_slot.venue(runner_slot.select(self.config, 'primary')):
            with patch('custody.inventory', return_value=[]):
                custody.Journal(self.journal, slot='primary').reconcile()
        rows = custody.read_records(self.journal)
        self.assertEqual([r['name'] for _, r in rows], [NAME_B])
        self.assertEqual(custody.pin(b.pid), before)
        self.assertTrue(b.is_alive())
        with patch('custody.inventory', return_value=[]):
            with self.assertRaisesRegex(RuntimeError, 'native'):
                custody.idle(self.journal)
        pb.send('exit')
        b.join(5)
        self.assertEqual(b.exitcode, 0)
        with patch('custody.inventory', return_value=[]):
            custody.Journal(self.journal, slot='secondary').reconcile()
            self.assertTrue(custody.idle(self.journal)['idle'])

    def test_all_known_inventory_is_validated_but_other_slot_is_never_removed(self):
        a = custody.Journal(self.journal, slot='primary')
        b = custody.Journal(self.journal, slot='secondary')
        a.intent(NAME_A)
        b.intent(NAME_B)
        rows = [dict(Names=[NAME_A], Id=CID_A), dict(Names=[NAME_B], Id=CID_B)]
        removed = []

        def command(*args):
            if args[0] == 'inspect':
                return json.dumps([dict(Name=NAME_A, Id=CID_A, State={'Pid': 0})]).encode()
            self.assertEqual(args, ('rm', '--force', '--time=5', CID_A))
            removed.append(args[-1])
            rows[:] = [r for r in rows if r['Id'] != CID_A]
            return b''
        with patch('custody.inventory', side_effect=lambda: list(rows)), patch('custody.command', side_effect=command):
            a.reconcile()
        self.assertEqual(removed, [CID_A])
        self.assertEqual([r['name'] for _, r in custody.read_records(self.journal)], [NAME_B])

    def test_unknown_unreadable_and_unassigned_inventory_refuse(self):
        a = custody.Journal(self.journal, slot='primary')
        a.intent(NAME_A)
        with patch('custody.command') as command, patch('custody.inventory', return_value=[dict(Names=['unknown'], Id=CID_B)]):
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                a.reconcile()
            command.assert_not_called()
        with patch('custody.inventory', side_effect=RuntimeError('unreadable')):
            with self.assertRaisesRegex(RuntimeError, 'unreadable'):
                a.reconcile()
        custody.Journal(self.journal).intent(NAME_B)
        with patch('custody.inventory') as inventory:
            with self.assertRaisesRegex(RuntimeError, 'unassigned'):
                a.reconcile()
            inventory.assert_not_called()

    def test_real_maintenance_exclusion_covers_both_leases(self):
        first = runner_slot.select(self.config, 'primary')
        second = runner_slot.select(self.config, 'secondary')
        with runner_slot.venue(first), runner_slot.venue(second):
            with open(self.config['ci_lock']) as lock:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with open(self.config['ci_lock']) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for config in (first, second):
                with self.assertRaises(BlockingIOError):
                    with runner_slot.venue(config):
                        pass

    def test_slot_paths_reject_symlink_overlap_and_unknown_names(self):
        config = json.loads(json.dumps(self.config))
        target = Path(config['slots']['secondary']['runner_work'])
        target.rmdir()
        target.symlink_to(config['slots']['primary']['runner_work'], target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'separate'):
            runner_slot.select(config, 'primary')
        with self.assertRaisesRegex(ValueError, 'fixed'):
            runner_slot.select(self.config, 'other')

    def test_journal_lock_rejects_aliases_and_unknown_entries(self):
        original = self.journal / 'other'
        original.touch()
        (self.journal / '.lock').symlink_to(original)
        with self.assertRaises(OSError):
            custody.read_records(self.journal)
        (self.journal / '.lock').unlink()
        original.unlink()
        (self.journal / 'unknown').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'unknown entry'):
            custody.read_records(self.journal)

    def test_paired_caps_are_fixed_and_forwarded_to_container_and_runner(self):
        import threading
        for limits in [(10 * 1024 ** 3, 4, 4), (12 * 1024 ** 3, 5, 4), (12 * 1024 ** 3, 4, 8)]:
            with self.assertRaisesRegex(ValueError, 'fixed'):
                workload.Cohort({}, None, None, None, self.root, threading.Event(), memory=limits[0], cpus=limits[1], workers=limits[2])
        seen = []

        class Box:

            def __init__(self, image, **kw):
                seen.append(kw)
                self.proof = {'seccomp_profile_sha256': 'approved'}
        source = self.root / 'source'
        source.write_bytes(b'synthetic archive')
        cohort = workload.Cohort({'image': 'fixed', 'seccomp_sha256': 'approved'}, None, source, None, self.root, threading.Event(), memory=12 * 1024 ** 3, cpus=4, workers=4)

        def execute(box, args, log, **kw):
            if args[-2:] == ['run', 'fmt']:
                self.assertIn(['--jobs', '4'], [args[i:i + 2] for i in range(len(args) - 1)])
                log.write_text('Ran 1 test in 0.001s\n\nOK\n')
            return {'success': True, 'exit_code': 0}
        with patch('workload.Tracked', Box), patch('workload.execute', side_effect=execute):
            self.assertTrue(cohort.stage('fmt'))
        self.assertEqual(seen[0]['memory'], 12 * 1024 ** 3)
        self.assertEqual(seen[0]['cpus'], 4)
if __name__ == '__main__':
    unittest.main(verbosity=2)
