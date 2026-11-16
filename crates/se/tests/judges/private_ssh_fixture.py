"""Real loopback OpenSSH with private keys, configuration and remote home.

Requires a disposable Linux runner with passwordless sudo and openssh-server.
It neither reads nor changes the runner's SSH configuration or credentials.
"""
import json
import os
from pathlib import Path
import pwd
import shlex
import socket
import subprocess
import time


def identity(pid):
    try:
        directory = Path('/proc') / str(pid)
        fields = (directory / 'stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': pid, 'birth': fields[19], 'parent': int(fields[1]),
                'state': fields[0], 'command': (directory / 'cmdline').read_bytes().replace(b'\0', b' ').decode()}
    except FileNotFoundError:
        return None


class PrivateSsh:
    def __init__(self, root, remote_home, environment):
        self.root = root.resolve()
        self.root.mkdir(mode=0o700)
        self.process = None
        self.daemon = None
        self.known = {}
        self.log = (root / 'server.log').open('wb')
        self.client_key = root / 'client-key'
        self.server_key = root / 'server-key'
        for key in (self.client_key, self.server_key):
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                           stdin=subprocess.DEVNULL, check=True, timeout=15)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.port = reservation.getsockname()[1]
        config = root / 'client-config'
        known_hosts = root / 'known-hosts'
        public = self.server_key.with_suffix('.pub').read_text().split()
        known_hosts.write_text(f'[127.0.0.1]:{self.port} {public[0]} {public[1]}\n')
        config.write_text('\n'.join([
            'Host isolated-peer', '  HostName 127.0.0.1', f'  Port {self.port}',
            '  User ' + pwd.getpwuid(os.getuid()).pw_name,
            '  IdentityFile ' + shlex.quote(str(self.client_key)),
            '  UserKnownHostsFile ' + shlex.quote(str(known_hosts)),
            '  GlobalKnownHostsFile /dev/null', '  StrictHostKeyChecking yes',
            '  IdentitiesOnly yes', '  IdentityAgent none', '  BatchMode yes',
            '  ConnectTimeout 10', '  ControlMaster no', '  ControlPath none', '']))
        wrapper = root / 'remote-command.py'
        wrapper.write_text('#!/usr/bin/python3\nimport os,subprocess\n'
            + 'environment=' + repr(environment) + '\n'
            + 'command=os.environ["SSH_ORIGINAL_COMMAND"]\n'
            + 'os.chdir(' + repr(str(remote_home)) + ')\n'
            + 'raise SystemExit(subprocess.run(["/bin/sh","-c",command],env=environment).returncode)\n')
        wrapper.chmod(0o700)
        server_config = root / 'server-config'
        server_config.write_text('\n'.join([
            f'Port {self.port}', 'ListenAddress 127.0.0.1',
            'HostKey ' + str(self.server_key), 'PidFile ' + str(root / 'server.pid'),
            'AuthorizedKeysFile ' + str(self.client_key.with_suffix('.pub')),
            'StrictModes no', 'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
            'PubkeyAuthentication yes', 'UsePAM yes', 'PermitRootLogin no',
            'AllowUsers ' + pwd.getpwuid(os.getuid()).pw_name,
            'AllowTcpForwarding yes', 'GatewayPorts no', 'PermitUserEnvironment no',
            'Subsystem sftp /usr/lib/openssh/sftp-server',
            'ForceCommand ' + str(wrapper), 'LogLevel VERBOSE', '']))
        subprocess.run(['sudo', '-n', '/usr/sbin/sshd', '-t', '-f', str(server_config)], check=True)
        self.process = subprocess.Popen(['sudo', '-n', '/usr/sbin/sshd', '-D', '-e', '-f', str(server_config)],
                                        stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        until = time.monotonic() + 15
        while not (root / 'server.pid').exists():
            assert self.process.poll() is None, 'private SSH server exited'
            assert time.monotonic() < until, 'private SSH server did not publish its PID'
            time.sleep(.05)
        self.daemon = identity(int((root / 'server.pid').read_text()))
        assert self.daemon and str(server_config) in self.daemon['command'], self.daemon
        self.known[self.daemon['pid']] = self.daemon
        self.bin = root / 'bin'
        self.bin.mkdir()
        for program in ('ssh', 'sftp'):
            path = self.bin / program
            path.write_text('#!/bin/sh\nexec /usr/bin/' + program + ' -F ' + shlex.quote(str(config)) + ' "$@"\n')
            path.chmod(0o700)
        probe = subprocess.run([str(self.bin / 'ssh'), 'isolated-peer', 'pwd'],
                               capture_output=True, text=True, timeout=20)
        (root / 'probe.stdout').write_text(probe.stdout)
        (root / 'probe.stderr').write_text(probe.stderr)
        assert probe.returncode == 0 and probe.stdout.strip() == str(remote_home), (probe.returncode, probe.stdout, probe.stderr)
        self.census()

    def census(self):
        processes = []
        for path in Path('/proc').iterdir():
            if path.name.isdecimal():
                value = identity(int(path.name))
                if value:
                    processes.append(value)
        changed = True
        while changed:
            changed = False
            for value in processes:
                if value['pid'] not in self.known and value['parent'] in self.known:
                    parent = identity(value['parent'])
                    if parent and parent['birth'] == self.known[value['parent']]['birth']:
                        self.known[value['pid']] = value
                        changed = True
        (self.root / 'native-identities.json').write_text(json.dumps(list(self.known.values()), indent=2) + '\n')

    def close(self):
        self.census()
        current = identity(self.daemon['pid']) if self.daemon else None
        if current and current['birth'] == self.daemon['birth']:
            assert current['command'] == self.daemon['command'], current
            subprocess.run(['sudo', '-n', 'kill', '-TERM', str(current['pid'])], check=True)
        if self.process:
            self.process.wait(timeout=15)
        until = time.monotonic() + 15
        remaining = []
        while True:
            remaining = [value for value in self.known.values()
                         if (now := identity(value['pid'])) and now['birth'] == value['birth'] and now['state'] != 'Z']
            if not remaining or time.monotonic() >= until:
                break
            time.sleep(.05)
        self.log.close()
        # These keys authenticate only to this now-closed private listener.
        for path in (self.client_key, self.server_key):
            path.unlink(missing_ok=True)
        assert not remaining, ('owned SSH processes survived closure', remaining)
        return {'witnessed': True, 'native_identities': list(self.known.values()), 'ephemeral_private_keys_removed': True}
