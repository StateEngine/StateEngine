"""Keep the hosted journey's public foreground host in the runner's job."""
import json
import subprocess
import time

from harness_matrix.io import require


DETACHED_HOST_COVERAGE = {'hosted': 'NOT RUN', 'witness_required_on': 'native-windows-vm'}
FOREGROUND_PHASES = ('J2', 'J3', 'J5')


class ForegroundRuntime:
    def __init__(self, commands, binary, state):
        self.commands = commands
        self.argv = [str(binary), 'up', '--foreground', '--home', str(state), '--json', '--no-color']
        self.child = None
        self.current = None
        self.receipts = {}

    def start(self, phase):
        require(self.child is None, 'The previous foreground host exit has not been observed')
        label = 'foreground-host-' + phase.lower()
        prefix = self.commands.evidence_prefix(label)
        stdout, stderr = prefix.with_suffix('.stdout'), prefix.with_suffix('.stderr')
        row = self.receipts[phase] = dict(readiness='starting')
        try:
            with stdout.open('xb') as out, stderr.open('xb') as err:
                self.child = subprocess.Popen(self.argv, cwd=self.commands.repository,
                                              env=self.commands.environment, stdin=subprocess.DEVNULL,
                                              stdout=out, stderr=err)
                self.current = row
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                with stdout.open('rb') as stream:
                    line = stream.readline(65537)
                require(len(line) <= 65536, 'Foreground host readiness exceeds its output bound')
                if line.endswith(b'\n'):
                    receipt = json.loads(line)
                    require(receipt.get('schema') == 'se.runtime-start/v1'
                            and receipt.get('state') == 'running'
                            and receipt.get('process', {}).get('pid') == self.child.pid
                            and type(receipt.get('generation')) is int and receipt['generation'] > 0,
                            'Foreground startup did not identify the owned host')
                    self.commands.observer.observe(self.child.pid, expected_exe=self.argv[0])
                    row.update(readiness='witnessed', startup=receipt)
                    return
                require(self.child.poll() is None, 'Foreground host exited before readiness')
                time.sleep(.05)
            raise RuntimeError('Foreground host readiness deadline expired')
        except BaseException as error:
            row.update(readiness='failed')
            self.commands.record_failure(prefix, label, self.argv, self.argv,
                                         self.child.poll() if self.child else None, str(error))
            raise

    def observe_exit(self):
        if self.child is None:
            return
        code = self.child.wait(timeout=30)
        self.current['exit'] = code
        self.child = None
        self.current = None
        require(code == 0, 'Foreground host exited unsuccessfully')

    def complete(self):
        return (set(self.receipts) == set(FOREGROUND_PHASES)
                and all(row.get('readiness') == 'witnessed' and row.get('exit') == 0
                        for row in self.receipts.values()))
