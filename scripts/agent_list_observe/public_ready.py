"""Time flushed public readiness, retaining a foreground command until down."""
import json
import subprocess
import threading
import time

from harness_matrix.io import require, save


class PublicReady:
    def __init__(self, smoke, argv, environment):
        self.smoke = smoke
        self.output = smoke.output
        self.stdout, self.stderr = bytearray(), bytearray()
        self.failure = None
        self.ready = threading.Event()
        self.observed_ns = None
        self.returned_ns = None
        self.started_ns = time.perf_counter_ns()
        self.child = subprocess.Popen(argv, cwd=smoke.repository, env=environment,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        self.threads = [threading.Thread(target=self.read, args=(stream, data, public))
                        for stream, data, public in ((self.child.stdout, self.stdout, True),
                                                    (self.child.stderr, self.stderr, False))]
        for thread in self.threads:
            thread.start()

    def read(self, stream, data, public):
        try:
            while chunk := stream.read1(65536):
                if len(data) + len(chunk) > 8 * 1024**2:
                    self.failure = 'Public startup output exceeded its retained bound'
                    self.ready.set()
                    # Continue draining to preserve shutdown; report the bound
                    # failure explicitly rather than treating a prefix as full.
                    continue
                data.extend(chunk)
                if public and self.observed_ns is None:
                    try:
                        value = json.loads(data)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if isinstance(value, dict) and value.get('state') == 'running':
                        self.observed_ns = time.perf_counter_ns()
                        self.ready.set()
        except BaseException as error:
            self.failure = str(error)
            self.ready.set()
        finally:
            stream.close()
            if public:
                self.ready.set()

    def receipt(self):
        return dict(pid=self.child.pid, stdout=self.stdout.decode(errors='replace'),
                    stderr=self.stderr.decode(errors='replace'), failure=self.failure,
                    ready_ms=None if self.observed_ns is None else
                    (self.observed_ns-self.started_ns)/1e6,
                    exit=self.child.poll(), qualification='Parent-side pipe read upper bound on flushed public running JSON; includes command spawn and reader scheduling')

    def wait(self):
        arrived = self.ready.wait(30)
        value = self.receipt()
        save(self.output / 'public-ready.json', value)
        require(arrived and self.observed_ns is not None and self.failure is None,
                'Public running JSON was not observed: ' + str(value))
        return dict(ms=value['ready_ms'], stdout=value['stdout'], stderr=value['stderr'],
                    exit=None, command_return=dict(state='pending'), timing=value['qualification'])

    def join(self):
        code = self.child.wait(timeout=30)
        self.returned_ns = time.perf_counter_ns()
        for thread in self.threads:
            thread.join(timeout=10)
        require(all(not thread.is_alive() for thread in self.threads),
                'Owned startup output readers did not join after down')
        value = self.receipt()
        fallback = 'Windows prevented detached startup' in value['stderr']
        value['command_return'] = (dict(state='unavailable', reason="Runner job object forbids detached breakaway; foreground command returns only after public down")
                                   if fallback else dict(state='unmeasured', reason='Readiness mode observes pipe receipt, not command-return time'))
        value['owned_command_joined_after_down'] = True
        save(self.output / 'public-ready-final.json', value)
        require(code == 0 and self.failure is None, 'Owned foreground command failed after down')
        return value
