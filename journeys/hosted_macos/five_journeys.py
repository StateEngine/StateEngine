#!/usr/bin/env python3
"""Portable five-row entry: credential-free macOS smoke or explicit provider non-execution.

Provider execution is deliberately not enabled before the hosted-credential decision.
No normal account credential file, provider token or external provider is accessed.
"""
import argparse
import json
from pathlib import Path
import platform
import sys
from common import binding, require, save, unread_provider


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('account-free', 'provider-not-run'), required=True)
    parser.add_argument('--surface', choices=('codex', 'claude'), required=True)
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--package-sha256')
    parser.add_argument('--account-registration', type=Path)
    args = parser.parse_args()
    nightly = binding(json.loads(args.binding.read_text()))
    report = unread_provider(args.surface, 'Hosted real-provider credentials are not approved/configured; no provider was launched')
    report.update(platform=sys.platform, machine=platform.machine(), nightly=nightly, mode=args.mode)
    if args.mode == 'provider-not-run':
        args.out.mkdir(parents=True, exist_ok=False)
        save(args.out / 'results.json', report)
        print(json.dumps(report))
        return 0  # Receipt production succeeded; result remains NOT RUN, never qualification PASS.
    if args.package is None or args.package_sha256 is None or args.account_registration is None:
        parser.error('account-free requires --package, --package-sha256 and --account-registration')
    try:
        require(sys.platform == 'darwin', 'account-free requires a native macOS disposable runner; provider-not-run is portable')
        from smoke import Smoke
        smoke = Smoke(args.package, args.package_sha256, args.out, args.account_registration)
        if smoke.record['source'] != nightly:
            raise RuntimeError('Transferred package is bound to another nightly')
        observed = smoke.run()
        report.update(result='NOT RUN', account_free_result=observed['result'],
                      partial_checks=observed['probes'], cleanup=observed['cleanup'])
        # This native Install proof is a distinct account-free scope. It must not
        # turn either provider's unexecuted five-journey matrix green.
        save(args.out / 'results.json', report)
        return 0 if observed['result'] == 'PASS' else 1
    except Exception as error:
        args.out.mkdir(parents=True, exist_ok=True)
        report.update(account_free_result='FAIL', reason=str(error))
        save(args.out / 'results.json', report)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
