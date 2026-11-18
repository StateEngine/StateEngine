"""Run the shared real-provider journeys against one pinned native macOS package."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys

from common import binding, digest, require
from package import verify
from smoke import terminal_receipt

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path[:0] = [str(SCRIPTS), str(SCRIPTS / 'ci')]
from harness_matrix.inputs import preflight
from harness_matrix.io import InterruptedRun
from windows_journeys.credentials import present, protect
from windows_journeys.flow import JOURNEYS, Journeys
from windows_nightly_providers import (KEYS, PROVIDERS, clean_environment, failure_evidence,
                                       prepared, provision, require_safe_output)


class MacJourneys(Journeys):
    def __init__(self, output, package, entry, settings, inherited, release):
        super().__init__(output, package, entry, settings, inherited, release=release)
        self.login_path = inherited['PATH']
        self.commands.environment.update(SHELL='/bin/zsh', LANG='en_US.UTF-8', LC_ALL='en_US.UTF-8',
                                         USER=inherited.get('USER', ''), LOGNAME=inherited.get('LOGNAME', ''))
        self.record.update(schema='se.macos-provider-journeys/v1',
                           qualification='Real hosted native provider journeys')

    def shell(self, label):
        command = 'printf "HOME=%s\\nPATH=%s\\nSE=%s\\n" "$HOME" "$PATH" "$(command -v se || :)"'
        text = self.commands.run(['/usr/bin/env', 'PATH=' + self.login_path, '/bin/zsh', '-lc', command], label)
        values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
        require(values.get('HOME') == str(self.home) and 'PATH' in values and 'SE' in values,
                'Fresh terminal did not expose the private home and executable discovery')
        return values

    def user_path(self):
        return self.shell('user-path')['PATH']

    def install(self):
        before = self.shell('terminal-before-install')
        require(before['SE'] == '', 'The disposable runner already discovers StateEngine')
        self.original_path = before['PATH']
        self.commands.run(['/bin/sh', self.package / 'install.sh'], 'install')
        after = self.shell('fresh-terminal-discovery')
        build = json.loads((self.package / 'build.json').read_bytes())
        require(after['SE'] and Path(after['SE']).resolve(strict=True) == self.binary.resolve(strict=True),
                'Fresh terminal did not discover the installed executable')
        installed_sha256 = digest(self.binary)
        require(installed_sha256 == build['files']['se'], 'Installed binary differs from the native package')
        version = self.commands.run([self.binary, '--version'], 'installed-version').strip()
        require(version == build['version_stdout'], 'Installed version differs from the native build')
        return dict(download=self.record['release'], installed_sha256=installed_sha256,
                    discovery=dict(image=after['SE'], version=version))

    def decode_reply(self, output, terminal):
        return terminal_receipt(output)[0] if terminal else super().decode_reply(output, terminal)

    def uninstall(self):
        value = self.call(['uninstall', '--yes'], 'uninstall', terminal=True, project=False)
        require(value.get('schema') == 'se.uninstall/v1' and value.get('complete') is True
                and value.get('issues', []) == [], 'Public uninstall did not complete all obligations')
        require(self.shell('terminal-after-uninstall')['SE'] == '', 'Fresh terminal still discovers StateEngine')


def real_run(args, output, nightly):
    environment = clean_environment()
    subprocess.run([sys.executable, '-B', str(args.account_registration), 'check'],
                   env=environment, check=True, stdin=subprocess.DEVNULL, timeout=30)
    package, metadata = verify(args.package, args.package_sha256, output / 'package')
    require(metadata['nightly'] == nightly, 'Transferred package is bound to another nightly')
    archive = args.package.resolve() / metadata['archive']
    release = dict(origin='bundled', archive_sha256=metadata['archive_sha256'],
                   source_commit=nightly['product_commit'], build_sha256=metadata['build_sha256'])
    seed_root = output / 'seed'
    seed_root.mkdir(mode=0o700)
    protect(seed_root)
    provider = args.surface
    seed = provision(provider, PROVIDERS[provider][2], seed_root)
    config, _ = prepared(provider, output, archive, metadata['archive_sha256'],
                         nightly['product_commit'], seed, platform='darwin')
    manifest = json.loads(config.read_bytes())
    entry, = manifest['harnesses']
    settings, observed = preflight(entry)
    journey = output / 'journey'
    journey.mkdir(mode=0o700)
    runner = MacJourneys(journey, package, entry, settings, environment, release)
    runner.record.update(nightly=nightly, package_metadata_sha256=args.package_sha256,
                         inputs=observed)
    try:
        result = runner.run()
    except (InterruptedRun, KeyboardInterrupt):
        result = runner.record
        result.update(result='INCOMPLETE', interrupted=True)
    if result['result'] == 'PASS':
        closure = result.get('credential_closure')
        if not (isinstance(closure, dict) and closure.get('private_copy_absent') is True
                and closure.get('refresh_tokens_copied') is False and result.get('process_closure') == []
                and all(result['phases'][name]['result'] == 'PASS' for name in JOURNEYS)
                and all(result['phases'][name]['tokens']['state'] == 'observed' for name in ('J2', 'J3', 'J4'))):
            result.update(result='FAIL', qualification_error='Native usage or closure proof is incomplete')
    return result


def stage_receipt(path, report, keys, interruption):
    if interruption is not None:
        report = dict(report, interrupted=True, interruption_signal=interruption)
        if report['result'] == 'PASS':
            report['result'] = 'INCOMPLETE'
    encoded = (json.dumps(report, indent=2, allow_nan=False) + '\n').encode('utf-8')
    require(len(encoded) <= 16 * 1024**2, 'Published provider receipt exceeds its finite bound')
    require_safe_output([encoded], keys)
    path.write_bytes(encoded)
    return report['result']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--surface', choices=tuple(PROVIDERS), required=True)
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--account-registration', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'darwin' and platform.machine() == 'arm64'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('GITHUB_ACTIONS') == 'true', 'A disposable hosted arm64 macOS runner is required')
    nightly = binding(json.loads(args.binding.read_bytes()))
    output = args.out.resolve()
    output.mkdir(mode=0o700)
    protect(output)
    active = False
    accepts_cancellation = True
    interruption = None

    def interrupt(signum, _frame):
        nonlocal interruption
        if accepts_cancellation and interruption is None:
            interruption = signum
            if active:
                raise InterruptedRun('Provider journey interrupted by signal ' + str(signum))

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    seed_root = output / 'seed'
    try:
        try:
            active = True
            if interruption is not None:
                raise InterruptedRun('Provider journey interrupted by signal ' + str(interruption))
            report = real_run(args, output, nightly)
        finally:
            # A first signal can interrupt the run; cleanup and evidence must finish.
            active = False
    except (InterruptedRun, KeyboardInterrupt, Exception) as error:
        report = dict(result='INCOMPLETE', reason=str(error), nightly=nightly, platform=sys.platform,
                      schema='se.macos-provider-journeys/v1',
                      phases={name: dict(result='NOT RUN') for name in JOURNEYS})
        if isinstance(error, (InterruptedRun, KeyboardInterrupt)):
            report['interrupted'] = True
    finally:
        try:
            if present(seed_root):
                shutil.rmtree(seed_root)
            seed_cleanup_failed = present(seed_root)
        except OSError:
            seed_cleanup_failed = True
    if seed_cleanup_failed:
        report.update(result='FAIL', seed_cleanup='Private seed cleanup is incomplete')
    report['provider'] = args.surface
    keys = [os.environ[name] for name in KEYS if os.environ.get(name)]
    if report['result'] != 'PASS':
        try:
            failed = failure_evidence(output / 'journey', keys)
            if failed is not None:
                report['failed_command'] = failed
        except (OSError, RuntimeError, TypeError, ValueError):
            report['failed_command_state'] = 'unreadable'
    publish = output / 'publish'
    publish.mkdir(mode=0o700)
    temporary = publish / 'results.json.partial'
    staged_interruption = interruption
    result = stage_receipt(temporary, report, keys, staged_interruption)
    # Freeze the outcome after staging and before atomic publication. A signal
    # delivered while staging must be included before the receipt becomes visible.
    accepts_cancellation = False
    if staged_interruption != interruption:
        result = stage_receipt(temporary, report, keys, interruption)
    temporary.rename(publish / 'results.json')
    print(json.dumps(dict(provider=args.surface, result=result)))
    return 0 if result == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
