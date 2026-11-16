#!/usr/bin/env python3
"""Prepare the exact-nightly macOS dispatch body after the Linux archive is built.

Does not send requests or read credentials. The existing nightly operator may pipe
this finite body to its approved workflow dispatcher after publication.
"""
import argparse
import json
from pathlib import Path
from common import binding, save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True, help='The current Linux nightly run.json, after native packaging')
    parser.add_argument('--workflow-ref', required=True, help='Published workflow branch/ref, normally main')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    run = json.loads(args.run.read_text())
    value = binding(dict(schema='se.nightly-binding/v1', started_at=run['started_at'],
                         product_commit=run['product']['commit'], judge_commit=run['judge']['commit'],
                         linux_archive_sha256=run['product']['archive_sha256']))
    save(args.out, dict(ref=args.workflow_ref, inputs=dict(nightly_binding=json.dumps(value, separators=(',', ':')))))
    print(str(args.out))


if __name__ == '__main__':
    main()
